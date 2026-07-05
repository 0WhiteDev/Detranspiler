from __future__ import annotations
import json
import re
import shutil
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
from detranspiler.jar.radioegor.context import _descriptor_from_decl
from detranspiler.jar.radioegor.util import _format_body, _param_names
_JNIC_LOADER_METHOD = '$jnicLoader'
_JNIC_DEFAULT_DESCRIPTOR = '(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;'
_JNIC_DEFAULT_VOID_DESCRIPTOR = '(Ljava/lang/Object;[Ljava/lang/Object;)V'
_JNIC_PLACEHOLDER_SIGNATURES = frozenset({'()V', '()Ljava/lang/Object;'})
_NATIVE_JUNK_RE = re.compile('\\b(cVar\\d*|local_[0-9A-Za-z_]+|uVar\\d*|DAT_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+)\\b')
_GARBAGE_STRING_RE = re.compile('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]')
_PLACEHOLDER_MEMBER_RE = re.compile(r'(?:<enc:|\.m\d+\s*\(|\.f\d+\b|Class\.forName\("<enc:)')
_JNIC_NATIVE_DECL_RE = re.compile(r'(?P<indent>^[ \t]*)(?P<mods>(?:(?:public|private|protected|static|final|synchronized|strictfp)\s+)*)native\s+(?:(?:/\*.*?\*/)\s*)?(?P<ret>[\w$\[\]<>., ?]+?)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*;', re.MULTILINE)

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


def _simple_java_type(value: str) -> str:
    text = re.sub(r'\b(?:final|volatile|transient)\s+', '', str(value or '').strip()).replace('...', '[]')
    dimensions = ''
    while text.endswith('[]'):
        dimensions += '[]'
        text = text[:-2].strip()
    text = re.sub(r'<.*>', '', text).strip().replace('$', '.')
    return (text.rsplit('.', 1)[-1] if text else text) + dimensions


def _decl_param_types(params: str) -> List[str]:
    if not params.strip():
        return []
    out: List[str] = []
    for raw in params.split(','):
        cleaned = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', raw).strip()
        pieces = cleaned.rsplit(None, 1)
        out.append(_simple_java_type(pieces[0] if len(pieces) == 2 else cleaned))
    return out


def _descriptor_matches_decl(descriptor: Optional[str], params: str) -> bool:
    parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
    if parsed is None:
        return False
    return [_simple_java_type(item) for item in parsed[1]] == _decl_param_types(params)

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
    if any(_PLACEHOLDER_MEMBER_RE.search(ln) for ln in meaningful):
        return False
    if any(re.search(r'(?<![A-Za-z_$])(?:0|[1-9]\d*)\.[A-Za-z_$][\w$]*\s*\(', ln) for ln in meaningful):
        return False
    declared_temps = {
        match.group(1)
        for line in meaningful
        for match in re.finditer(r'\b(?:boolean|byte|char|short|int|long|float|double|Object|String|Class<\?>|[A-Za-z_$][\w$<>.?]*)(?:\[\])?\s+(v\d+)\b', line)
    }
    used_temps = {token for line in meaningful for token in re.findall(r'\bv\d+\b', line)}
    if used_temps - declared_temps:
        return False
    declared_types: Dict[str, str] = {}
    for line in meaningful:
        match = re.search(r'\b(?P<type>(?:[A-Za-z_$][\w$<>.?]*|boolean|byte|char|short|int|long|float|double)(?:\[\])?)\s+(?P<name>v\d+)\b', line)
        if match:
            declared_types[match.group('name')] = match.group('type')
    for line in meaningful:
        match = re.match(r'return\s+\((?P<target>[^)]+)\)\s*(?P<name>v\d+)\s*;', line)
        if match and declared_types.get(match.group('name'), '').endswith('[]') and not match.group('target').strip().endswith('[]'):
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

def _try_jnic_native_body(*, fn_symbol: Optional[str], block_by_name: Dict[str, str], jni_calls: Optional[Dict[str, Any]], decoded_strings: Optional[Dict[str, str]], param_types: List[str], param_names: List[str], ret_java: str, is_static: bool=False, class_internal: Optional[str]=None, native_index: Optional[Dict[str, Any]]=None) -> Optional[List[str]]:
    if not isinstance(fn_symbol, str) or not fn_symbol:
        return None
    block = block_by_name.get(fn_symbol) or block_by_name.get(_sanitize_java_identifier(fn_symbol))
    if not isinstance(block, str) or not block.strip():
        return None
    return recover_jnic_body(fn_symbol=fn_symbol, block=block, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, native_param_base=3, receiver_name=None if is_static else 'this', config=JnicRecoveryConfig(decoded_strings=decoded_strings or {}, class_internal=class_internal, native_index=native_index))

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

def _resolve_jnic_signature(class_internal: str, idx: int, method: Dict[str, Any], jar_meta: Any) -> Optional[str]:
    explicit = _explicit_register_signature(method)
    if explicit is not None:
        return explicit
    _name, inferred, _fn = resolve_register_method(class_internal, idx, method, jar_meta)
    return inferred if isinstance(inferred, str) and inferred.startswith('(') else None


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

def _jar_method_flags(jar_meta: Any, class_internal: str, method_name: str, descriptor: Optional[str]) -> Optional[int]:
    if not isinstance(jar_meta, dict):
        return None
    class_info = jar_meta.get(class_internal)
    methods = class_info.get('methods') if isinstance(class_info, dict) else None
    if not isinstance(methods, dict):
        return None
    if isinstance(descriptor, str):
        flags = methods.get((method_name, descriptor))
        if isinstance(flags, int):
            return flags
    matches = [flags for (name, _desc), flags in methods.items() if name == method_name and isinstance(flags, int)]
    return matches[0] if len(matches) == 1 else None


def _overlay_class_source(class_internal: str, text: str, methods: List[Dict[str, Any]], state) -> Tuple[str, int]:
    resolved: List[Tuple[str, Optional[str], Dict[str, Any]]] = []
    for idx, method in enumerate(methods):
        name = _resolve_jnic_method_name(class_internal, idx, method, state.jar_meta)
        descriptor = _resolve_jnic_signature(class_internal, idx, method, state.jar_meta)
        resolved.append((name, descriptor, method))
    recovered = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal recovered
        method_name = match.group('name')
        descriptor = _descriptor_from_decl(match.group('ret'), match.group('params').strip())
        candidates = [item for item in resolved if item[0] == method_name]
        exact = [item for item in candidates if item[1] == descriptor]
        if len(exact) == 1:
            _name, effective_sig, method = exact[0]
        else:
            shaped = [item for item in candidates if _descriptor_matches_decl(item[1], match.group('params'))]
            if len(shaped) == 1:
                _name, effective_sig, method = shaped[0]
            elif len(candidates) == 1:
                _name, effective_sig, method = candidates[0]
            else:
                return match.group(0)
        if not isinstance(effective_sig, str):
            effective_sig = descriptor
        fn_symbol = method.get('fn_symbol') if isinstance(method.get('fn_symbol'), str) else None
        ret_java, param_types, _ = _method_signature_parts(effective_sig, fn_symbol=fn_symbol, by_name=state.by_name)
        target_names = _param_names(match.group('params'))
        if len(target_names) != len(param_types):
            return match.group(0)
        flags = _jar_method_flags(state.jar_meta, class_internal, method_name, effective_sig)
        is_static = bool(flags is not None and (flags & 0x0008))
        body = _try_jnic_native_body(
            fn_symbol=fn_symbol,
            block_by_name=state.by_name,
            jni_calls=getattr(state, 'jni_calls', None),
            decoded_strings=getattr(state, 'jnic_decoded_strings', None),
            param_types=list(param_types),
            param_names=target_names,
            ret_java=ret_java,
            is_static=is_static,
            class_internal=class_internal,
            native_index=getattr(state, 'native_index', None),
        )
        if not isinstance(body, list) or not _body_is_usable(body):
            return match.group(0)
        indent = match.group('indent')
        mods = re.sub(r'\s+', ' ', match.group('mods')).strip()
        prefix = f"{indent}{(mods + ' ' if mods else '')}{match.group('ret').strip()} {method_name}({match.group('params').strip()})"
        recovered += 1
        return prefix + ' {\n' + _format_body(body, method_indent=indent) + '\n' + indent + '}'

    return _JNIC_NATIVE_DECL_RE.sub(repl, text), recovered


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
        sig = _resolve_jnic_signature(class_internal, idx, method, state.jar_meta)
        ret_java, param_types, effective_sig = _method_signature_parts(sig, fn_symbol=fn_symbol, by_name=state.by_name)
        param_names = _jnic_param_names(param_types)
        if param_names == [f'var{i}' for i in range(len(param_types))]:
            param_names = resolve_java_param_names(param_types=param_types, class_internal=class_internal, method=display_name, descriptor=effective_sig, is_static=True, jar_meta=state.jar_meta, jar_index=state.jar_index)
        params = ', '.join((f'{t} {param_names[i]}' for i, t in enumerate(param_types)))
        body_lines: List[str] = []
        flags = _jar_method_flags(state.jar_meta, class_internal, display_name, effective_sig)
        jnic_body = _try_jnic_native_body(fn_symbol=fn_symbol, block_by_name=state.by_name, jni_calls=getattr(state, 'jni_calls', None), decoded_strings=getattr(state, 'jnic_decoded_strings', None), param_types=list(param_types), param_names=list(param_names), ret_java=ret_java, is_static=bool(flags is not None and (flags & 0x0008)), class_internal=class_internal, native_index=getattr(state, 'native_index', None))
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

def build_jnic_overlay_sources(*, pseudocode_dir: Path, jar_path: Optional[Path]=None, exports: Optional[List[str]]=None, jni_register: Optional[Dict[str, Any]]=None, jnic_patterns: Optional[Dict[str, Any]]=None, native_index: Optional[Dict[str, Any]]=None, pseudo_c_path: Optional[Path]=None, functions_json_path: Optional[Path]=None, jni_calls: Optional[Dict[str, Any]]=None, binary_path: Optional[Path]=None, callgraph: Optional[Dict[str, Any]]=None, flattening: Optional[Dict[str, Any]]=None, anti_analysis: Optional[Dict[str, Any]]=None, string_decrypt: Optional[Dict[str, Any]]=None, string_symbol_map: Optional[Dict[str, str]]=None) -> Dict[str, Any]:
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
    pseudo_c_char_limit = max(2_000_000, pseudo_c_path.stat().st_size) if pseudo_c_path is not None and pseudo_c_path.is_file() else 2_000_000
    state = build_generation_state(exports=list(exports or []), pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, max_pseudo_c_chars=pseudo_c_char_limit, jni_register=jni_register, jni_calls=jni_calls, jar_path=jar_path, binary_path=binary_path, callgraph=callgraph, flattening=flattening, anti_analysis=anti_analysis, string_decrypt=string_decrypt, string_symbol_map=string_symbol_map)
    state.native_index = native_index
    jnic_dir = pseudocode_dir / 'jnic'
    export_dir = pseudocode_dir / 'jni_exports'
    if jnic_dir.exists():
        shutil.rmtree(jnic_dir)
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
        jar_source_path = pseudocode_dir / 'jar_sources' / Path(*rel_parts).with_suffix('.java')
        if jar_source_path.is_file():
            original_source = jar_source_path.read_text(encoding='utf-8', errors='replace')
            source, recovered = _overlay_class_source(class_internal, original_source, methods, state)
        else:
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
