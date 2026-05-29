from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.jar.guided import get_jar_fallback_body, get_jar_reference_body, get_jar_return_expr
from detranspiler.java.body.recovery import is_stub_body_lines
from detranspiler.java.body.selection import normalize_body_lines
from detranspiler.java.gen.build_state import build_generation_state
from detranspiler.java.gen.recover_body import MethodBodyRequest, emit_recovered_method_body
from detranspiler.java.gen.state import GenerationState
from detranspiler.java.jni_descriptors import _jni_method_sig_to_java
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.jar.locals import resolve_java_param_names

def _export_descriptor_suffix(descriptor: Optional[str]) -> Optional[str]:
    if not isinstance(descriptor, str) or not descriptor.strip():
        return None
    s = descriptor.strip()
    if s.startswith('('):
        close = s.find(')')
        if close == -1:
            return None
        return s[1:close] + s[close + 1:]
    return s

def _jni_export_symbol(*, class_internal: str, method_name: str, descriptor: Optional[str]) -> Optional[str]:
    if not class_internal or not method_name:
        return None
    suffix = _export_descriptor_suffix(descriptor)
    if not suffix:
        return None
    cls_seg = class_internal.replace('/', '_')
    return f'Java_{cls_seg}_{method_name}__{suffix}'

def _resolve_pseudoc_symbols(state: GenerationState, *, fn_symbol: Optional[str], class_internal: str, method_name: str, descriptor: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    candidates: List[str] = []

    def add(sym: Optional[str]) -> None:
        if isinstance(sym, str) and sym and (sym not in candidates):
            candidates.append(sym)
    add(fn_symbol)
    add(_jni_export_symbol(class_internal=class_internal, method_name=method_name, descriptor=descriptor))
    base = f"Java_{class_internal.replace('/', '_')}_{method_name}"
    for key in state.by_name:
        if isinstance(key, str) and (key == fn_symbol or key.startswith(base)):
            add(key)
    for raw_name, _method_ident in state.method_items:
        add(raw_name if isinstance(raw_name, str) else None)
    existing = [c for c in candidates if _block_exists(state, c)]
    missing = [c for c in candidates if c not in existing]
    ordered = existing + missing
    primary = ordered[0] if ordered else fn_symbol
    secondary = ordered[1] if len(ordered) > 1 else None
    return primary, secondary

def _block_exists(state: GenerationState, symbol: Optional[str]) -> bool:
    if not isinstance(symbol, str) or not symbol:
        return False
    block = state.by_name.get(_sanitize_java_identifier(symbol)) or state.by_name.get(symbol)
    return isinstance(block, str) and bool(block.strip())

def build_repair_state_from_job(job: Dict[str, Any], *, pseudocode_dir: Path, pseudo_c_path: Optional[Path]=None) -> Optional[GenerationState]:
    if not isinstance(job, dict):
        return None
    analysis = job.get('analysis')
    if not isinstance(analysis, dict):
        return None
    artifacts = job.get('artifacts')
    if not isinstance(artifacts, dict):
        artifacts = {}
    if pseudo_c_path is None:
        raw = artifacts.get('pseudo_c_file')
        if isinstance(raw, str):
            pseudo_c_path = Path(raw)
    if pseudo_c_path is None or not pseudo_c_path.is_file():
        candidate = pseudocode_dir.parent / 'pseudo_c' / 'decompiled.c'
        if candidate.is_file():
            pseudo_c_path = candidate
    if pseudo_c_path is None or not pseudo_c_path.is_file():
        return None
    functions_json_path = None
    raw_fn = artifacts.get('ghidra_functions_json')
    if isinstance(raw_fn, str):
        functions_json_path = Path(raw_fn)
    exports: List[str] = []
    meta = job.get('metadata')
    if isinstance(meta, dict):
        raw_exports = meta.get('exports')
        if isinstance(raw_exports, list):
            exports = [str(e) for e in raw_exports if isinstance(e, str)]
    input_info = job.get('input')
    binary_path = None
    if isinstance(input_info, dict) and isinstance(input_info.get('path'), str):
        binary_path = Path(input_info['path'])
    jar_path = None
    jar_decompile = analysis.get('jar_decompile')
    if isinstance(jar_decompile, dict) and isinstance(jar_decompile.get('jar_path'), str):
        jar_path = Path(jar_decompile['jar_path'])
    jar_sources = pseudocode_dir / 'jar_sources'
    string_map = None
    sym_path = artifacts.get('string_symbol_map_json')
    if isinstance(sym_path, str):
        try:
            import json
            doc = json.loads(Path(sym_path).read_text(encoding='utf-8'))
            if isinstance(doc, dict) and isinstance(doc.get('symbols'), dict):
                string_map = doc['symbols']
        except Exception:
            string_map = None
    seeds: List[str] = []
    sd = analysis.get('string_decrypt')
    if isinstance(sd, dict):
        for item in sd.get('strings') or []:
            if isinstance(item, dict) and isinstance(item.get('value'), str):
                if item['value'] not in seeds:
                    seeds.append(item['value'])
    try:
        return build_generation_state(exports=exports, pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, jni_register=analysis.get('jni_register') if isinstance(analysis.get('jni_register'), dict) else None, jni_calls=analysis.get('jni_calls') if isinstance(analysis.get('jni_calls'), dict) else None, jar_path=jar_path if jar_path and jar_path.is_file() else None, binary_path=binary_path if binary_path and binary_path.is_file() else None, callgraph=analysis.get('callgraph') if isinstance(analysis.get('callgraph'), dict) else None, extra_seed_strings=seeds or None, flattening=analysis.get('flattening') if isinstance(analysis.get('flattening'), dict) else None, anti_analysis=analysis.get('anti_analysis') if isinstance(analysis.get('anti_analysis'), dict) else None, jar_sources_dir=jar_sources if jar_sources.is_dir() else None, deobfuscation=analysis.get('deobfuscation') if isinstance(analysis.get('deobfuscation'), dict) else None, string_decrypt=sd if isinstance(sd, dict) else None, string_symbol_map=string_map)
    except Exception:
        return None

def _lookup_native_method(native_index: Optional[Dict[str, Any]], *, class_internal: str, method: str, descriptor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not isinstance(native_index, dict):
        return None
    best = None
    for item in native_index.get('methods') or []:
        if not isinstance(item, dict):
            continue
        if item.get('class') != class_internal or item.get('method') != method:
            continue
        if descriptor and item.get('descriptor') and (item.get('descriptor') != descriptor):
            continue
        best = item
        if item.get('descriptor') == descriptor:
            return item
    return best

def recover_method_body_lines(state: GenerationState, *, class_internal: str, method_name: str, descriptor: Optional[str], fn_symbol: Optional[str]) -> Optional[List[str]]:
    ret_java = 'void'
    param_types: List[str] = []
    if isinstance(descriptor, str) and descriptor:
        sig = _jni_method_sig_to_java(descriptor)
        if sig is not None:
            ret_java, param_types = sig
    param_names = resolve_java_param_names(param_types=param_types, class_internal=class_internal, method=method_name, descriptor=descriptor, is_static=True, jar_meta=state.jar_meta, jar_index=state.jar_index)
    jar_ref = get_jar_reference_body(jar_index=state.jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
    jar_ret = get_jar_return_expr(jar_index=state.jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
    block_primary, block_secondary = _resolve_pseudoc_symbols(state, fn_symbol=fn_symbol, class_internal=class_internal, method_name=method_name, descriptor=descriptor)
    side_symbol = block_primary if _block_exists(state, block_primary) else fn_symbol
    out_lines: List[str] = []
    result = emit_recovered_method_body(state, out_lines, MethodBodyRequest(class_internal=class_internal, method_name=method_name, descriptor=descriptor, ret_java=ret_java, param_types=param_types, param_names=param_names, block_primary=block_primary, block_secondary=block_secondary, use_helper_blocks=True, use_interproc=True, void_symbol=side_symbol, side_effect_symbol=side_symbol), jar_ref=jar_ref, jar_ret=jar_ret)
    if not result.body_emitted:
        fallback = get_jar_fallback_body(jar_index=state.jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
        if isinstance(fallback, list) and fallback:
            return normalize_body_lines(fallback)
        return None
    normalized = normalize_body_lines([ln for ln in out_lines if isinstance(ln, str)])
    if is_stub_body_lines(normalized):
        return None
    return normalized

def recover_stub_via_pipeline(state: GenerationState, native_index: Optional[Dict[str, Any]], *, class_internal: str, method_name: str, descriptor: Optional[str]) -> Optional[List[str]]:
    item = _lookup_native_method(native_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
    fn_symbol = item.get('fn_symbol') if isinstance(item, dict) else None
    desc = descriptor
    if isinstance(item, dict) and isinstance(item.get('descriptor'), str):
        desc = item.get('descriptor')
    return recover_method_body_lines(state, class_internal=class_internal, method_name=method_name, descriptor=desc if isinstance(desc, str) else descriptor, fn_symbol=fn_symbol if isinstance(fn_symbol, str) else None)
