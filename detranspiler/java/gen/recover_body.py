from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.deobfuscation.anti_analysis import is_low_trust_symbol
from detranspiler.jar.guided import get_jar_fallback_body
from detranspiler.jar.similarity import similarity_between_bodies
from detranspiler.java.body.recovery import body_should_prefer_jar
from detranspiler.java.body.selection import compose_method_body, format_recovery_comment, normalize_body_lines, pick_best_return_expr, select_java_body
from detranspiler.java.gen.state import GenerationState
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.pseudoc import infer_java_lines_from_pseudoc, infer_java_return_from_pseudoc
from detranspiler.java.pseudoc_blocks import _extract_label_block
from detranspiler.java.pseudoc_locals import enrich_java_param_names_from_block, enrich_param_map_from_block
from detranspiler.java.recovery_hints import _jni_side_effect_lines
from detranspiler.java.return_from_pseudoc import _infer_simple_java_return
from detranspiler.java.type_mapping import _default_return_expr
from detranspiler.java.void_from_bytecode import _infer_java_void_body_from_bytecode
from detranspiler.java.void_from_pseudoc import _infer_simple_java_void_body
from detranspiler.jni.synthesis import infer_java_body_from_jni_calls, infer_java_return_from_jni_calls
from detranspiler.java.void_from_dispatch import infer_void_from_register_print_sequence
from detranspiler.native.flatten_recover import recover_java_from_flattening
from detranspiler.native.interproc import collect_related_blocks
from detranspiler.recovery.strategy import should_try_jar_fallback

def _semantic_recovery_advisory(state: GenerationState, *, symbol_low_trust: bool) -> bool:
    if symbol_low_trust:
        return True
    strat = state.recovery_strategy
    if not isinstance(strat, dict) or not strat.get('skip_semantic_on_anti'):
        return False
    aa = state.anti_analysis
    if not isinstance(aa, dict):
        return False
    return aa.get('risk_level') in ('HIGH', 'MEDIUM')

@dataclass
class MethodBodyRequest:
    class_internal: str
    method_name: str
    descriptor: Optional[str]
    ret_java: str
    param_types: List[str]
    param_names: List[str]
    block_primary: Optional[str]
    block_secondary: Optional[str] = None
    use_helper_blocks: bool = False
    use_interproc: bool = False
    side_effect_symbol: Optional[str] = None
    void_symbol: Optional[str] = None
    check_low_trust: bool = False
    hint_main: Optional[bool] = None
    non_void_jni_body_fallback: bool = True
    native_param_base: int = 3

@dataclass
class MethodBodyResult:
    body_emitted: bool
    recovery_entry: Optional[Dict[str, Any]]
    param_names: List[str]
    low_trust: bool

def resolve_pseudoc_block(state: GenerationState, *, primary: Optional[str], secondary: Optional[str]=None, use_helpers: bool=False, use_interproc: bool=False) -> Optional[str]:
    block: Optional[str] = None
    if isinstance(primary, str) and primary:
        block = state.by_name.get(_sanitize_java_identifier(primary)) or state.by_name.get(primary)
    if (block is None or not str(block).strip()) and use_helpers and isinstance(primary, str):
        helper = state.helper_blocks.get(primary)
        if isinstance(helper, str) and helper.strip():
            block = helper
    if (block is None or not str(block).strip()) and isinstance(secondary, str) and secondary:
        block = state.by_name.get(_sanitize_java_identifier(secondary)) or state.by_name.get(secondary)
    if (block is None or not str(block).strip()) and use_interproc and isinstance(primary, str) and primary:
        if primary.startswith('LAB_') and isinstance(state.pseudo_c_text, str):
            block = _extract_label_block(state.pseudo_c_text, label=primary)
        else:
            merged = collect_related_blocks(root_symbol=primary, callgraph=state.callgraph, blocks_by_name=state.by_name)
            if isinstance(merged, str) and merged.strip():
                block = merged
    if isinstance(block, str) and block.strip():
        return block
    return None

def _bytecode_body_candidate(state: GenerationState, *, class_internal: str, method_name: str, descriptor: Optional[str]) -> Optional[List[str]]:
    if not isinstance(state.jar_meta, dict) or not isinstance(descriptor, str):
        return None
    cm = state.jar_meta.get(class_internal)
    if not isinstance(cm, dict):
        return None
    methods_code = cm.get('methods_code')
    if not isinstance(methods_code, dict):
        return None
    bcode = methods_code.get((method_name, descriptor))
    if not isinstance(bcode, (bytes, bytearray)):
        return None
    cp = cm.get('cp')
    methods_locals = cm.get('methods_locals')
    local_names = None
    if isinstance(methods_locals, dict):
        local_names = methods_locals.get((method_name, descriptor))
    body = _infer_java_void_body_from_bytecode(bytes(bcode), cp=cp if isinstance(cp, list) else None, local_names=local_names if isinstance(local_names, dict) else None, local_var_table=cm.get('methods_lvt', {}).get((method_name, descriptor)) if isinstance(cm.get('methods_lvt'), dict) else None, bootstrap_methods=cm.get('bootstrap_methods') if isinstance(cm.get('bootstrap_methods'), list) else None)
    if isinstance(body, list) and body:
        return body
    return None

def _param_map_from_names(param_names: List[str], param_types: List[str], *, native_param_base: int=3) -> Dict[str, str]:
    return {f'param_{i + native_param_base}': param_names[i] for i in range(len(param_types))}

def _prelude_lines_without_return(lines: Optional[List[str]]) -> List[str]:
    if not isinstance(lines, list):
        return []
    return [ln for ln in lines if isinstance(ln, str) and ln.strip() and (not ln.strip().startswith('return '))]

def _collect_non_void_return_body(*, best_expr: str, ret_sources: List[str], block: Optional[str], param_map: Dict[str, str], ret_java: str, side_effect_symbol: Optional[str], jni_calls: Any, param_names: List[str], strings_by_addr: Any=None, dat_ptr_values: Any=None, read_string_at_va: Any=None) -> Optional[Tuple[List[str], str]]:
    prelude: List[str] = []
    for stmt in _jni_side_effect_lines(fn_symbol=side_effect_symbol, jni_calls=jni_calls, param_map=param_map, ret_java=ret_java, java_param_names=param_names):
        prelude.append(stmt if stmt.startswith('    ') else f'    {stmt}')
    if isinstance(block, str) and block.strip():
        pseudo_lines = infer_java_lines_from_pseudoc(block, param_map=param_map, ret_java=ret_java, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, read_string_at_va=read_string_at_va)
        prelude.extend(_prelude_lines_without_return(pseudo_lines))
    body = compose_method_body(prelude_lines=prelude, return_expr=best_expr)
    if body:
        source = 'composed' if len(ret_sources) > 1 else ret_sources[0] if ret_sources else 'return'
        return body, source
    return None

def emit_recovered_method_body(state: GenerationState, out_lines: List[str], request: MethodBodyRequest, *, jar_ref: Optional[List[str]], jar_ret: Optional[str]) -> MethodBodyResult:
    param_names = list(request.param_names)
    param_map = _param_map_from_names(param_names, request.param_types, native_param_base=request.native_param_base)
    body_emitted = False
    recovery_entry: Optional[Dict[str, Any]] = None
    void_candidates: List[Tuple[str, Optional[List[str]]]] = []
    non_void_candidates: List[Tuple[str, Optional[List[str]]]] = []
    trust_symbol = request.block_primary if request.check_low_trust else None
    symbol_low_trust = is_low_trust_symbol(trust_symbol, state.anti_analysis) if request.check_low_trust else False
    semantic_advisory = _semantic_recovery_advisory(state, symbol_low_trust=symbol_low_trust)
    bytecode = _bytecode_body_candidate(state, class_internal=request.class_internal, method_name=request.method_name, descriptor=request.descriptor)
    if bytecode:
        if request.ret_java == 'void':
            void_candidates.append(('bytecode', bytecode))
        else:
            non_void_candidates.append(('bytecode', bytecode))
    if jar_ref and request.ret_java != 'void':
        non_void_candidates.append(('jar', jar_ref))
    block: Optional[str] = None
    block = resolve_pseudoc_block(state, primary=request.block_primary, secondary=request.block_secondary, use_helpers=request.use_helper_blocks, use_interproc=request.use_interproc)
    if isinstance(block, str) and block.strip():
        param_names = enrich_java_param_names_from_block(block, param_names)
        param_map = _param_map_from_names(param_names, request.param_types, native_param_base=request.native_param_base)
        param_map = enrich_param_map_from_block(block, param_map)
    if isinstance(block, str) and block:
        return_candidates: List[Tuple[str, Optional[str]]] = []
        expr = _infer_simple_java_return(block, param_map=param_map, ret_java=request.ret_java, java_param_names=param_names, strings_by_addr=state.strings_by_addr, dat_ptr_values=state.dat_ptr_values, read_string_at_va=state.read_string_at_va, read_u64_at_va=state.read_u64_at_va)
        if expr is not None:
            return_candidates.append(('simple', expr))
        jni_sym = request.block_primary if isinstance(request.block_primary, str) else request.block_secondary
        if request.ret_java != 'void':
            expr_jni = infer_java_return_from_jni_calls(fn_symbol=jni_sym, jni_calls=state.jni_calls, param_map=param_map, ret_java=request.ret_java, java_param_names=param_names)
            if expr_jni is not None:
                return_candidates.append(('jni', expr_jni))
        expr_pc = infer_java_return_from_pseudoc(block, param_map=param_map, ret_java=request.ret_java)
        if expr_pc is not None:
            return_candidates.append(('pseudoc', expr_pc))
        if jar_ret is not None:
            return_candidates.append(('jar', jar_ret))
        best_expr, ret_sources = pick_best_return_expr(return_candidates, jar_reference_expr=jar_ret)
        if best_expr is not None and request.ret_java != 'void':
            side_sym = request.side_effect_symbol or jni_sym
            composed = _collect_non_void_return_body(best_expr=best_expr, ret_sources=ret_sources, block=block, param_map=param_map, ret_java=request.ret_java, side_effect_symbol=side_sym if isinstance(side_sym, str) else None, jni_calls=state.jni_calls, param_names=param_names, strings_by_addr=state.strings_by_addr, dat_ptr_values=state.dat_ptr_values, read_string_at_va=state.read_string_at_va)
            if composed is not None:
                body_lines, source = composed
                non_void_candidates.append((source, body_lines))
        if not body_emitted and request.ret_java == 'void':
            if request.hint_main is None:
                hint_main = bool(request.method_name == 'main' and request.descriptor == '([Ljava/lang/String;)V' and (request.param_types == ['String[]']))
            else:
                hint_main = request.hint_main
            void_body = _infer_simple_java_void_body(block, param_map=param_map, strings_by_addr=state.strings_by_addr, dat_ptr_values=state.dat_ptr_values, read_string_at_va=state.read_string_at_va, extra_seed_strings=state.jar_seed_strings + state.bin_seed_strings, hint_main=hint_main)
            if isinstance(void_body, list) and void_body:
                void_candidates.append(('simple', void_body))
    if request.ret_java == 'void' and (not body_emitted):
        void_sym = request.void_symbol or request.block_primary or request.block_secondary
        pseudo_lines = infer_java_lines_from_pseudoc(block if isinstance(block, str) else '', param_map=param_map, ret_java=request.ret_java, strings_by_addr=state.strings_by_addr, dat_ptr_values=state.dat_ptr_values, read_string_at_va=state.read_string_at_va)
        if isinstance(pseudo_lines, list) and pseudo_lines:
            void_candidates.append(('pseudoc', pseudo_lines))
        flat_body = recover_java_from_flattening(fn_symbol=void_sym if isinstance(void_sym, str) else None, flattening=state.flattening, param_map=param_map, ret_java=request.ret_java)
        if isinstance(flat_body, list) and flat_body:
            void_candidates.append(('flatten', flat_body))
        jni_body = infer_java_body_from_jni_calls(fn_symbol=void_sym if isinstance(void_sym, str) else None, jni_calls=state.jni_calls, param_map=param_map, ret_java=request.ret_java, java_param_names=param_names)
        if isinstance(jni_body, list) and jni_body:
            void_candidates.append(('jni', jni_body))
    if request.ret_java == 'void' and isinstance(jar_ref, list) and jar_ref:
        void_candidates.append(('jar', jar_ref))
    if request.ret_java == 'void' and isinstance(block, str) and block.strip():
        dispatch_body = infer_void_from_register_print_sequence(block, class_internal=request.class_internal, jni_register=state.jni_register, jni_calls=state.jni_calls, read_u64_at_va=state.read_u64_at_va)
        if isinstance(dispatch_body, list) and dispatch_body:
            void_candidates.append(('dispatch', dispatch_body))
    if request.ret_java == 'void' and (not body_emitted) and should_try_jar_fallback(strategy=state.recovery_strategy, body_emitted=body_emitted, low_trust=symbol_low_trust):
        jar_body = get_jar_fallback_body(jar_index=state.jar_index, class_internal=request.class_internal, method=request.method_name, descriptor=request.descriptor)
        if isinstance(jar_body, list) and jar_body:
            void_candidates.append(('jar', jar_body))
    if request.ret_java == 'void' and void_candidates and (not body_emitted):
        src, best_body, score, body_sources = select_java_body(void_candidates, strategy=state.recovery_strategy, jar_reference=jar_ref)
        if isinstance(best_body, list) and best_body:
            if isinstance(jar_ref, list) and jar_ref and body_should_prefer_jar(best_body, jar_ref):
                best_body = normalize_body_lines([ln for ln in jar_ref if isinstance(ln, str)])
                src = 'jar'
                body_sources = ['jar']
            elif src == 'dispatch' or 'dispatch' in body_sources:
                dispatch_only = next((body for cand_src, body in void_candidates if cand_src == 'dispatch'), None)
                if isinstance(dispatch_only, list) and dispatch_only:
                    best_body = normalize_body_lines(dispatch_only)
                else:
                    best_body = [ln for ln in normalize_body_lines(best_body) if not re.search('\\b(cVar\\d*|local_[0-9A-Za-z_]+)\\b', ln.strip()) or 'System.out.' in ln]
                body_sources = ['dispatch']
                src = 'dispatch'
            comment = format_recovery_comment()
            if comment:
                out_lines.append(comment)
            for stmt in normalize_body_lines(best_body):
                out_lines.append(stmt)
            body_emitted = True
            recovery_entry = {'kind': 'void', 'sources': body_sources, 'score': score, 'primary_source': src}
            if jar_ref:
                recovery_entry['jar_similarity'] = round(similarity_between_bodies(best_body, jar_ref), 3)
    fallback_sym = request.void_symbol or request.block_primary or request.block_secondary
    if request.ret_java != 'void' and (not body_emitted):
        jni_body = infer_java_body_from_jni_calls(fn_symbol=fallback_sym if isinstance(fallback_sym, str) else None, jni_calls=state.jni_calls, param_map=param_map, ret_java=request.ret_java, java_param_names=param_names)
        if isinstance(jni_body, list) and jni_body:
            non_void_candidates.append(('jni', jni_body))
    if not body_emitted and request.ret_java != 'void' and isinstance(block, str) and block.strip():
        pseudo_lines = infer_java_lines_from_pseudoc(block, param_map=param_map, ret_java=request.ret_java, strings_by_addr=state.strings_by_addr, dat_ptr_values=state.dat_ptr_values, read_string_at_va=state.read_string_at_va)
        if isinstance(pseudo_lines, list) and pseudo_lines:
            non_void_candidates.append(('pseudoc', pseudo_lines))
        flat_body = recover_java_from_flattening(fn_symbol=request.block_primary if isinstance(request.block_primary, str) else None, flattening=state.flattening, param_map=param_map, ret_java=request.ret_java)
        if isinstance(flat_body, list) and flat_body:
            non_void_candidates.append(('flatten', flat_body))
    if not body_emitted and should_try_jar_fallback(strategy=state.recovery_strategy, body_emitted=body_emitted, low_trust=symbol_low_trust) and (request.ret_java != 'void'):
        jar_body = get_jar_fallback_body(jar_index=state.jar_index, class_internal=request.class_internal, method=request.method_name, descriptor=request.descriptor)
        if isinstance(jar_body, list) and jar_body:
            non_void_candidates.append(('jar', jar_body))
    if request.ret_java != 'void' and non_void_candidates and (not body_emitted):
        src, best_body, score, body_sources = select_java_body(non_void_candidates, strategy=state.recovery_strategy, jar_reference=jar_ref)
        if isinstance(best_body, list) and best_body:
            comment = format_recovery_comment()
            if comment:
                out_lines.append(comment)
            for stmt in normalize_body_lines(best_body):
                out_lines.append(stmt)
            body_emitted = True
            recovery_entry = {'kind': 'body', 'sources': body_sources, 'score': score, 'primary_source': src}
            if jar_ref:
                recovery_entry['jar_similarity'] = round(similarity_between_bodies(best_body, jar_ref), 3)
    if not body_emitted:
        default_ret = _default_return_expr(request.ret_java)
        if default_ret is not None:
            out_lines.append(f'    return {default_ret};')
    return MethodBodyResult(body_emitted=body_emitted, recovery_entry=recovery_entry, param_names=param_names, low_trust=symbol_low_trust)
