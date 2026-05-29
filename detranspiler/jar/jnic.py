from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.deobfuscation.jnic_body import JnicRecoveryConfig, recover_jnic_body
from detranspiler.java.body.recovery import is_invalid_java_body_lines, is_stub_body_lines
from detranspiler.java.gen.build_state import build_generation_state
from detranspiler.java.gen.method_meta import resolve_register_method, unique_method_ident
from detranspiler.java.gen.recover_body import MethodBodyRequest, emit_recovered_method_body
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.imports import inject_java_imports
from detranspiler.java.jni_descriptors import _internal_class_to_package_and_class, _jni_method_sig_to_java
from detranspiler.java.jni_export_parse import _parse_jni_export_name
from detranspiler.jar.locals import resolve_java_param_names
_JNIC_LOADER_METHOD = '$jnicLoader'
_JNIC_DEFAULT_DESCRIPTOR = '(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;'
_JNIC_DEFAULT_VOID_DESCRIPTOR = '(Ljava/lang/Object;[Ljava/lang/Object;)V'
_JNIC_PLACEHOLDER_SIGNATURES = frozenset({'()V', '()Ljava/lang/Object;'})
_NATIVE_JUNK_RE = re.compile('\\b(cVar\\d*|local_[0-9A-Za-z_]+|uVar\\d*|DAT_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+)\\b')
_GARBAGE_STRING_RE = re.compile('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]')

def _is_jnic_transpiler(jnic_patterns: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(jnic_patterns, dict):
        return False
    guess = str(jnic_patterns.get('transpiler_guess') or '').upper()
    if guess == 'JNIC':
        return True
    hits = jnic_patterns.get('hits') or []
    markers = {str(h.get('value') or '') for h in hits if isinstance(h, dict)}
    return bool({'jnic', 'JNIC'} & markers)

def _infer_native_return(fn_symbol: Optional[str], by_name: Dict[str, str]) -> str:
    if not isinstance(fn_symbol, str) or not fn_symbol:
        return 'Object'
    block = by_name.get(fn_symbol) or by_name.get(_sanitize_java_identifier(fn_symbol))
    if not isinstance(block, str):
        return 'Object'
    head = block.strip().split('{', 1)[0]
    if re.search('\\bvoid\\b', head):
        return 'void'
    if re.search('\\bulonglong\\b|\\nuint64\\b|\\blonglong\\b', head):
        return 'long'
    if re.search('\\bint\\b|\\buint\\b|\\bundefined4\\b', head):
        return 'int'
    if re.search('\\bbool\\b|\\bboolean\\b', head):
        return 'boolean'
    if re.search('\\bfloat\\b', head):
        return 'float'
    if re.search('\\bdouble\\b', head):
        return 'double'
    return 'Object'

def _method_signature_parts(descriptor: Optional[str], *, fn_symbol: Optional[str], by_name: Dict[str, str]) -> Tuple[str, List[str], str]:
    sig = descriptor if isinstance(descriptor, str) and descriptor.startswith('(') else None
    if sig is None:
        ret = _infer_native_return(fn_symbol, by_name)
        sig = _JNIC_DEFAULT_VOID_DESCRIPTOR if ret == 'void' else _JNIC_DEFAULT_DESCRIPTOR
    parsed = _jni_method_sig_to_java(sig)
    if parsed is None:
        ret = _infer_native_return(fn_symbol, by_name)
        if ret == 'void':
            return 'void', ['Object', 'Object[]'], _JNIC_DEFAULT_VOID_DESCRIPTOR
        return 'Object', ['Object', 'Object[]'], _JNIC_DEFAULT_DESCRIPTOR
    return parsed[0], list(parsed[1]), sig

def _body_is_usable(body: List[str]) -> bool:
    if is_stub_body_lines(body) or is_invalid_java_body_lines(body):
        return False
    meaningful = [ln.strip() for ln in body if ln.strip() and not ln.strip().startswith('//')]
    if not meaningful:
        return False
    if len(meaningful) == 1 and meaningful[0] in {'return 0;', 'return null;', 'return false;'}:
        return False
    if any(_NATIVE_JUNK_RE.search(ln) for ln in meaningful):
        return False
    for ln in meaningful:
        if ln.startswith('System.out.println('):
            m = re.search('System\\.out\\.println\\("([^"]*)"\\)', ln)
            if m and _GARBAGE_STRING_RE.search(m.group(1)):
                return False
        if re.match('^(long|int)\\s+v\\d+\\s*=\\s*0x[0-9a-fA-F]+;$', ln):
            return False
        if ln.startswith('final String _s') and (_GARBAGE_STRING_RE.search(ln) or (re.search('=\\s*"[^"\\n]{0,8}";\\s*$', ln) and (not re.search('=\\s*"[A-Za-z][A-Za-z0-9_ ./:-]{2,}";\\s*$', ln)))):
            return False
    return True

def _meaningful_body_count(body: List[str]) -> int:
    return sum((1 for ln in body if isinstance(ln, str) and ln.strip() and (not ln.strip().startswith('//'))))

def _try_jnic_native_body(*, fn_symbol: Optional[str], block_by_name: Dict[str, str], jni_calls: Optional[Dict[str, Any]], decoded_strings: Optional[Dict[str, str]], param_types: List[str], param_names: List[str], ret_java: str) -> Optional[List[str]]:
    if not isinstance(fn_symbol, str) or not fn_symbol:
        return None
    block = block_by_name.get(fn_symbol) or block_by_name.get(_sanitize_java_identifier(fn_symbol))
    if not isinstance(block, str) or not block.strip():
        return None
    return recover_jnic_body(fn_symbol=fn_symbol, block=block, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, native_param_base=2, config=JnicRecoveryConfig(decoded_strings=decoded_strings or {}))

def _explicit_register_signature(method: Dict[str, Any]) -> Optional[str]:
    sig = method.get('signature')
    if not isinstance(sig, str) or not sig.startswith('('):
        return None
    if sig in _JNIC_PLACEHOLDER_SIGNATURES:
        return None
    return sig

def _jnic_param_names(param_types: List[str]) -> List[str]:
    if param_types == ['Object', 'Object[]']:
        return ['ctx', 'args']
    return [f'var{i}' for i in range(len(param_types))]

def _resolve_jnic_method_name(class_internal: str, idx: int, method: Dict[str, Any], jar_meta: Any) -> str:
    name = method.get('name') if isinstance(method.get('name'), str) else None
    if name and name != _JNIC_LOADER_METHOD:
        safe = _sanitize_java_identifier(name)
        if safe and (not safe.startswith('native_')):
            return safe
    fn_symbol = method.get('fn_symbol') if isinstance(method.get('fn_symbol'), str) else None
    inferred, _sig, _fn = resolve_register_method(class_internal, idx, method, jar_meta)
    if isinstance(inferred, str) and inferred and (not inferred.startswith('native_FUN')):
        safe = _sanitize_java_identifier(inferred)
        if safe and safe != _JNIC_LOADER_METHOD:
            return safe
    return _safe_method_name(name, fn_symbol, idx)

def _safe_method_name(name: Optional[str], fn_symbol: Optional[str], index: int) -> str:
    if isinstance(name, str) and name and (name != _JNIC_LOADER_METHOD):
        safe = _sanitize_java_identifier(name)
        if safe and (not safe.startswith('native_')):
            return safe
    if isinstance(fn_symbol, str) and fn_symbol.startswith('FUN_'):
        return f'native_{fn_symbol[4:].lower()}'
    return f'native_{index}'

def _loader_export_classes(exports: Optional[List[str]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for sym in exports or []:
        if not isinstance(sym, str) or not sym.startswith('Java_'):
            continue
        parsed = _parse_jni_export_name(sym)
        if not isinstance(parsed, dict) or not parsed.get('is_jnic_loader'):
            continue
        cls = parsed.get('class')
        if isinstance(cls, str) and cls:
            out[cls] = parsed
    return out

def _registered_methods_for_class(jni_register: Optional[Dict[str, Any]], *, target_class: Optional[str]) -> List[Dict[str, Any]]:
    if not isinstance(jni_register, dict) or not target_class:
        return []
    out: List[Dict[str, Any]] = []
    for call in jni_register.get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        fn = call.get('function')
        if not isinstance(fn, str) or not fn.startswith('Java_'):
            continue
        parsed = _parse_jni_export_name(fn)
        if not isinstance(parsed, dict) or not parsed.get('is_jnic_loader'):
            continue
        if parsed.get('class') != target_class:
            continue
        for method in call.get('methods') or []:
            if isinstance(method, dict):
                item = dict(method)
                item.setdefault('class', target_class)
                out.append(item)
    return out

def _compose_class_source(class_internal: str, *, loader: bool, methods: List[Dict[str, Any]], state) -> Tuple[str, int]:
    pkg, cls_name = _internal_class_to_package_and_class(class_internal)
    lines: List[str] = []
    if pkg:
        lines.extend([f'package {pkg};', ''])
    lines.append(f'public class {cls_name} {{')
    lines.append('')
    if loader:
        lines.append(f'  public static native void {_JNIC_LOADER_METHOD}();')
        lines.append('')
    used_names: set[str] = set()
    recovered = 0
    for idx, method in enumerate(methods):
        fn_symbol = method.get('fn_symbol') if isinstance(method.get('fn_symbol'), str) else None
        display_name = _resolve_jnic_method_name(class_internal, idx, method, state.jar_meta)
        base = display_name
        suffix = 2
        while display_name in used_names:
            display_name = f'{base}_{suffix}'
            suffix += 1
        used_names.add(display_name)
        sig = _explicit_register_signature(method)
        ret_java, param_types, effective_sig = _method_signature_parts(sig, fn_symbol=fn_symbol, by_name=state.by_name)
        param_names = _jnic_param_names(param_types)
        if param_names == [f'var{i}' for i in range(len(param_types))]:
            param_names = resolve_java_param_names(param_types=param_types, class_internal=class_internal, method=display_name, descriptor=effective_sig, is_static=True, jar_meta=state.jar_meta, jar_index=state.jar_index)
        params = ', '.join((f'{t} {param_names[i]}' for i, t in enumerate(param_types)))
        body_lines: List[str] = []
        jnic_body = _try_jnic_native_body(fn_symbol=fn_symbol, block_by_name=state.by_name, jni_calls=getattr(state, 'jni_calls', None), decoded_strings=getattr(state, 'jnic_decoded_strings', None), param_types=list(param_types), param_names=list(param_names), ret_java=ret_java)
        if isinstance(jnic_body, list) and jnic_body and _body_is_usable(jnic_body):
            body_lines = jnic_body
        if not body_lines and isinstance(fn_symbol, str) and (fn_symbol in state.by_name):
            candidate_lines: List[str] = []
            result = emit_recovered_method_body(state, candidate_lines, MethodBodyRequest(class_internal=class_internal, method_name=display_name, descriptor=effective_sig, ret_java=ret_java, param_types=param_types, param_names=param_names, block_primary=fn_symbol, use_helper_blocks=True, use_interproc=True, side_effect_symbol=fn_symbol, void_symbol=fn_symbol, check_low_trust=True, non_void_jni_body_fallback=True, native_param_base=2), jar_ref=None, jar_ret=None)
            if result.body_emitted and _body_is_usable(candidate_lines):
                body_lines = candidate_lines
        if body_lines:
            lines.append(f'  public static {ret_java} {display_name}({params}) {{')
            for ln in body_lines:
                stripped = ln.strip()
                if stripped and not stripped.startswith('//'):
                    lines.append(f'    {stripped}')
            lines.append('  }')
            recovered += 1
            lines.append('')
            continue
        lines.append(f'  public static native {ret_java} {display_name}({params});')
        lines.append('')
    lines.append('}')
    return '\n'.join(lines) + '\n', recovered

def build_jnic_overlay_sources(*, pseudocode_dir: Path, exports: Optional[List[str]]=None, jni_register: Optional[Dict[str, Any]]=None, jnic_patterns: Optional[Dict[str, Any]]=None, native_index: Optional[Dict[str, Any]]=None, pseudo_c_path: Optional[Path]=None, functions_json_path: Optional[Path]=None, jni_calls: Optional[Dict[str, Any]]=None, binary_path: Optional[Path]=None, callgraph: Optional[Dict[str, Any]]=None, flattening: Optional[Dict[str, Any]]=None, anti_analysis: Optional[Dict[str, Any]]=None, string_decrypt: Optional[Dict[str, Any]]=None, string_symbol_map: Optional[Dict[str, str]]=None) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    if not _is_jnic_transpiler(jnic_patterns):
        return {'status': 'SKIPPED_NOT_JNIC', 'pattern': 'jnic'}
    loader_classes = _loader_export_classes(exports)
    if not loader_classes:
        return {'status': 'SKIPPED_NO_JNIC_LOADER', 'pattern': 'jnic'}
    if pseudo_c_path is None:
        candidate = pseudocode_dir / 'pseudo_c' / 'decompiled.c'
        pseudo_c_path = candidate if candidate.is_file() else None
    if functions_json_path is None:
        candidate = pseudocode_dir.parent / 'ghidra' / 'functions.json'
        functions_json_path = candidate if candidate.is_file() else None
    state = build_generation_state(exports=list(exports or []), pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, jni_register=jni_register, jni_calls=jni_calls, binary_path=binary_path, callgraph=callgraph, flattening=flattening, anti_analysis=anti_analysis, string_decrypt=string_decrypt, string_symbol_map=string_symbol_map)
    jnic_dir = pseudocode_dir / 'jnic'
    export_dir = pseudocode_dir / 'jni_exports'
    jnic_dir.mkdir(parents=True, exist_ok=True)
    classes_written = 0
    methods_written = 0
    bodies_recovered = 0
    manifest: List[Dict[str, Any]] = []
    for class_internal, loader_info in loader_classes.items():
        methods = _registered_methods_for_class(jni_register, target_class=class_internal)
        if not methods and isinstance(native_index, dict):
            for item in native_index.get('methods') or []:
                if not isinstance(item, dict):
                    continue
                if item.get('class') != class_internal:
                    continue
                if item.get('method') == _JNIC_LOADER_METHOD:
                    continue
                methods.append(item)
        rel_parts = [p for p in class_internal.split('/') if p]
        if not rel_parts:
            continue
        source, recovered = _compose_class_source(class_internal, loader=True, methods=methods, state=state)
        out_path = jnic_dir.joinpath(*rel_parts).with_suffix('.java')
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('\n'.join(inject_java_imports(source.splitlines())) + '\n', encoding='utf-8')
        classes_written += 1
        methods_written += len(methods)
        bodies_recovered += recovered
        export_path = export_dir.joinpath(*rel_parts).with_suffix('.java')
        if export_path.is_file():
            export_path.write_text(out_path.read_text(encoding='utf-8'), encoding='utf-8')
        manifest.append({'class': class_internal, 'loader_export': loader_info.get('symbol'), 'methods_total': len(methods), 'bodies_recovered': recovered, 'output': str(out_path.resolve())})
    manifest_path = pseudocode_dir / 'jnic_manifest.json'
    manifest_path.write_text(json.dumps({'status': 'OK', 'pattern': 'jnic', 'classes_total': classes_written, 'methods_total': methods_written, 'bodies_recovered': bodies_recovered, 'classes': manifest}, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'status': 'OK', 'pattern': 'jnic', 'classes_total': classes_written, 'methods_total': methods_written, 'bodies_recovered': bodies_recovered, 'output_dir': str(jnic_dir.resolve()), 'manifest_path': str(manifest_path.resolve())}
