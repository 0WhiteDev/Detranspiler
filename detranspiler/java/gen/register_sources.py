from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Tuple
from detranspiler.jar.guided import get_jar_reference_body, get_jar_return_expr
from detranspiler.jar.locals import resolve_java_param_names
from detranspiler.java.gen.method_meta import resolve_register_method, unique_method_ident
from detranspiler.java.gen.recover_body import MethodBodyRequest, emit_recovered_method_body
from detranspiler.java.gen.state import GenerationState
from detranspiler.java.imports import inject_java_imports
from detranspiler.jar.method_lookup import _jar_find_unique_class_for_method_descriptor
from detranspiler.java.jni_descriptors import _internal_class_to_package_and_class, _jni_method_sig_to_java
from detranspiler.java.modifiers import _access_flags_to_modifiers
from detranspiler.java.recovery_hints import _emit_flattening_hints, _emit_jni_hints

def write_register_sources(state: GenerationState, *, out_path: Path, jni_register: Optional[Dict[str, Any]], method_recovery: List[Dict[str, Any]]) -> Tuple[int, Optional[Path]]:
    jni_sources_written = 0
    jni_out_dir: Optional[Path] = None
    if not isinstance(jni_register, dict):
        return jni_sources_written, jni_out_dir
    calls = jni_register.get('register_calls')
    if not isinstance(calls, list):
        return jni_sources_written, jni_out_dir
    by_class: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in calls:
        if not isinstance(c, dict):
            continue
        cls = c.get('class')
        methods = c.get('methods')
        if not isinstance(cls, str) or not cls or (not isinstance(methods, list)):
            continue
        for m in methods:
            if isinstance(m, dict):
                by_class[cls].append(m)
    static_tables = jni_register.get('static_method_tables')
    if isinstance(static_tables, list):
        for t in static_tables:
            if not isinstance(t, dict):
                continue
            table_cls = t.get('class')
            methods = t.get('methods')
            if not isinstance(methods, list):
                continue
            for m in methods:
                if not isinstance(m, dict):
                    continue
                cls = table_cls if isinstance(table_cls, str) and table_cls else None
                name = m.get('name')
                sig = m.get('signature')
                if cls is None and isinstance(name, str) and isinstance(sig, str):
                    cls = _jar_find_unique_class_for_method_descriptor(state.jar_meta, method_name=name, method_desc=sig)
                if not isinstance(cls, str) or not cls:
                    continue
                m2 = dict(m)
                raw = m2.get('raw')
                if isinstance(raw, dict):
                    m2['raw'] = {**raw, 'source': 'static_jni_method_table'}
                else:
                    m2['raw'] = {'source': 'static_jni_method_table'}
                by_class[cls].append(m2)
    if not by_class:
        return jni_sources_written, jni_out_dir
    jni_out_dir = out_path.parent / 'jni'
    for cls, methods in by_class.items():
        pkg, cls_name = _internal_class_to_package_and_class(cls)
        rel_parts = [p for p in cls.split('/') if p]
        if not rel_parts:
            continue
        file_path = jni_out_dir.joinpath(*rel_parts).with_suffix('.java')
        file_path.parent.mkdir(parents=True, exist_ok=True)
        any_instance = False
        class_access = None
        if isinstance(state.jar_meta, dict):
            cm = state.jar_meta.get(cls)
            if isinstance(cm, dict):
                class_access = cm.get('access_flags')
        out_lines: List[str] = []
        if pkg:
            out_lines.append(f'package {pkg};')
            out_lines.append('')
        used_method_idents: set = set()
        class_vis, _ = _access_flags_to_modifiers(class_access, default_public=True)
        if class_vis:
            out_lines.append(f'{class_vis} class {cls_name} {{')
        else:
            out_lines.append(f'class {cls_name} {{')
        out_lines.append('')
        for mi, m in enumerate(methods):
            name, sig, fn_symbol = resolve_register_method(cls, mi, m, state.jar_meta)
            java_sig = _jni_method_sig_to_java(sig)
            if java_sig is None:
                ret_java, param_types = ('void', [])
            else:
                ret_java, param_types = java_sig
            method_flags = None
            if isinstance(state.jar_meta, dict):
                cm = state.jar_meta.get(cls)
                if isinstance(cm, dict):
                    mm = cm.get('methods')
                    if isinstance(mm, dict):
                        method_flags = mm.get((name, sig))
            vis, is_static = _access_flags_to_modifiers(method_flags, default_public=True)
            if method_flags is None:
                is_static = True
            if not is_static:
                any_instance = True
            param_names = resolve_java_param_names(param_types=param_types, class_internal=cls, method=name, descriptor=sig, is_static=is_static, jar_meta=state.jar_meta, jar_index=state.jar_index)
            params_str = ', '.join((f'{t} {param_names[idx]}' for idx, t in enumerate(param_types)))
            method_ident = unique_method_ident(name, used_method_idents)
            decl_parts: List[str] = []
            if vis:
                decl_parts.append(vis)
            if is_static:
                decl_parts.append('static')
            decl = ' '.join(decl_parts).strip()
            if decl:
                out_lines.append(f'  {decl} {ret_java} {method_ident}({params_str}) {{')
            else:
                out_lines.append(f'  {ret_java} {method_ident}({params_str}) {{')
            jar_ref = get_jar_reference_body(jar_index=state.jar_index, class_internal=cls, method=name, descriptor=sig)
            jar_ret = get_jar_return_expr(jar_index=state.jar_index, class_internal=cls, method=name, descriptor=sig)
            _emit_jni_hints(out_lines, state.jni_hints, fn_symbol)
            _emit_flattening_hints(out_lines, state.flat_hints, fn_symbol)
            result = emit_recovered_method_body(state, out_lines, MethodBodyRequest(class_internal=cls, method_name=name, descriptor=sig, ret_java=ret_java, param_types=param_types, param_names=param_names, block_primary=fn_symbol if fn_symbol else None, use_interproc=bool(fn_symbol), side_effect_symbol=fn_symbol, void_symbol=fn_symbol, check_low_trust=True, hint_main=bool(name == 'main' and sig == '([Ljava/lang/String;)V'), non_void_jni_body_fallback=True), jar_ref=jar_ref, jar_ret=jar_ret)
            if result.body_emitted:
                entry: Dict[str, Any] = {'class': cls, 'method': name, 'descriptor': sig, 'fn_symbol': fn_symbol}
                if isinstance(result.recovery_entry, dict):
                    entry.update(result.recovery_entry)
                else:
                    entry['sources'] = ['heuristic']
                method_recovery.append(entry)
            out_lines.append('  }')
            out_lines.append('')
        out_lines.append('}')
        file_path.write_text('\n'.join(inject_java_imports(out_lines)) + '\n', encoding='utf-8')
        jni_sources_written += 1
    return jni_sources_written, jni_out_dir
