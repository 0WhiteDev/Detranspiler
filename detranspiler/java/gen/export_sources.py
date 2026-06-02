import json
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Tuple
from detranspiler.jar.guided import get_jar_reference_body, get_jar_return_expr
from detranspiler.jar.locals import resolve_java_param_names
from detranspiler.java.gen.method_meta import unique_method_ident
from detranspiler.java.gen.recover_body import MethodBodyRequest, MethodBodyResult, emit_recovered_method_body
from detranspiler.java.gen.state import GenerationState
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.imports import inject_java_imports
from detranspiler.jar.method_lookup import _jar_infer_unique_method_descriptor
from detranspiler.java.jni_descriptors import _internal_class_to_package_and_class, _jni_method_sig_to_java
from detranspiler.java.jni_export_parse import _parse_jni_export_name
from detranspiler.java.jni_signature_infer import refine_jni_export_java_signature
from detranspiler.java.modifiers import _access_flags_to_modifiers
from detranspiler.java.recovery_hints import _emit_jni_hints

def write_export_sources(state: GenerationState, *, out_path: Path, exports: List[str], max_functions: int, method_recovery: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
    jni_export_sources_written = 0
    export_methods: List[Dict[str, Any]] = []
    for e in exports[:max_functions]:
        parsed = _parse_jni_export_name(e, jar_meta=state.jar_meta)
        if isinstance(parsed, dict):
            export_methods.append(parsed)
    if not export_methods:
        return jni_export_sources_written, export_methods
    export_out_dir = out_path.parent / 'jni_exports'
    export_manifest_path = out_path.parent / 'jni_exports_manifest.json'
    by_class_exports: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in export_methods:
        cls = item.get('class')
        if isinstance(cls, str) and cls:
            by_class_exports[cls].append(item)
    manifest_items: List[Dict[str, Any]] = []
    for cls, methods in by_class_exports.items():
        pkg, cls_name = _internal_class_to_package_and_class(cls)
        rel_parts = [p for p in cls.split('/') if p]
        if not rel_parts:
            continue
        file_path = export_out_dir.joinpath(*rel_parts).with_suffix('.java')
        file_path.parent.mkdir(parents=True, exist_ok=True)
        class_access = None
        if isinstance(state.jar_meta, dict):
            cm = state.jar_meta.get(cls)
            if isinstance(cm, dict):
                class_access = cm.get('access_flags')
        out_lines: List[str] = []
        if pkg:
            out_lines.append(f'package {pkg};')
            out_lines.append('')
        class_vis, _ = _access_flags_to_modifiers(class_access, default_public=True)
        out_lines.append(f"{(class_vis + ' ' if class_vis else '')}class {cls_name} {{")
        out_lines.append('')
        used_method_idents: set = set()
        for mi, m in enumerate(methods):
            name = m.get('method')
            sig = m.get('descriptor')
            raw_symbol = m.get('raw_symbol')
            fn_symbol = m.get('symbol')
            if not isinstance(name, str) or not name:
                name = f'native_{mi}'
            if not isinstance(sig, str) or not sig:
                sig = _jar_infer_unique_method_descriptor(state.jar_meta, internal_class=cls, method_name=name)
            java_sig = _jni_method_sig_to_java(sig) if isinstance(sig, str) and sig else None
            if java_sig is None:
                gh_sig = None
                if isinstance(raw_symbol, str):
                    gh_sig = state.sig_by_raw.get(raw_symbol) or state.sig_by_sanitized.get(_sanitize_java_identifier(raw_symbol))
                if gh_sig is not None:
                    block = None
                    if isinstance(raw_symbol, str):
                        block = state.by_name.get(_sanitize_java_identifier(raw_symbol)) or state.by_name.get(raw_symbol)
                    ret_java, param_types, inferred_names = refine_jni_export_java_signature(
                        block=block,
                        ghidra_ret=gh_sig[0],
                        ghidra_params=gh_sig[1],
                        strings_by_addr=state.strings_by_addr,
                        dat_ptr_values=state.dat_ptr_values,
                        read_string_at_va=state.read_string_at_va,
                    )
                else:
                    ret_java, param_types, inferred_names = ('void', [], [])
            else:
                ret_java, param_types = java_sig
                inferred_names = []
            manifest_items.append({'class': cls, 'method': name, 'descriptor': sig if isinstance(sig, str) else None, 'return_type': ret_java, 'parameter_types': param_types, 'native_symbol': raw_symbol if isinstance(raw_symbol, str) else None, 'source': 'exported_jni_symbol'})
            method_flags = None
            if isinstance(state.jar_meta, dict):
                cm = state.jar_meta.get(cls)
                if isinstance(cm, dict):
                    mm = cm.get('methods')
                    if isinstance(mm, dict) and isinstance(sig, str):
                        method_flags = mm.get((name, sig))
            vis, is_static = _access_flags_to_modifiers(method_flags, default_public=True)
            if method_flags is None:
                is_static = True
            param_names = resolve_java_param_names(param_types=param_types, class_internal=cls, method=name if isinstance(name, str) else '', descriptor=sig if isinstance(sig, str) else None, is_static=is_static, jar_meta=state.jar_meta, jar_index=state.jar_index)
            if inferred_names and len(inferred_names) == len(param_names):
                param_names = [
                    inferred_names[idx]
                    if not inferred_names[idx].startswith('param_')
                    else param_names[idx]
                    for idx in range(len(param_names))
                ]
            method_ident = unique_method_ident(name, used_method_idents)
            params_str = ', '.join((f'{t} {param_names[idx]}' for idx, t in enumerate(param_types)))
            decl_parts: List[str] = []
            if vis:
                decl_parts.append(vis)
            if is_static:
                decl_parts.append('static')
            decl = ' '.join(decl_parts).strip()
            out_lines.append(f"  {(decl + ' ' if decl else '')}{ret_java} {method_ident}({params_str}) {{")
            jar_ref = get_jar_reference_body(jar_index=state.jar_index, class_internal=cls, method=name, descriptor=sig if isinstance(sig, str) else None)
            jar_ret = get_jar_return_expr(jar_index=state.jar_index, class_internal=cls, method=name, descriptor=sig if isinstance(sig, str) else None)
            _emit_jni_hints(out_lines, state.jni_hints, raw_symbol if isinstance(raw_symbol, str) else None)
            if isinstance(fn_symbol, str) and fn_symbol != raw_symbol:
                _emit_jni_hints(out_lines, state.jni_hints, fn_symbol)
            side_sym = raw_symbol if isinstance(raw_symbol, str) else fn_symbol
            skip_body = bool(m.get('is_jnic_loader'))
            if not skip_body:
                result = emit_recovered_method_body(state, out_lines, MethodBodyRequest(class_internal=cls, method_name=name, descriptor=sig if isinstance(sig, str) else None, ret_java=ret_java, param_types=param_types, param_names=param_names, block_primary=raw_symbol if isinstance(raw_symbol, str) else None, block_secondary=fn_symbol if isinstance(fn_symbol, str) else None, use_helper_blocks=True, use_interproc=bool(raw_symbol or fn_symbol), side_effect_symbol=side_sym if isinstance(side_sym, str) else None, void_symbol=side_sym if isinstance(side_sym, str) else None, hint_main=bool(name == 'main' and sig == '([Ljava/lang/String;)V'), non_void_jni_body_fallback=True), jar_ref=jar_ref, jar_ret=jar_ret)
            else:
                result = MethodBodyResult(body_emitted=True, recovery_entry={'sources': ['jnic-loader'], 'primary_source': 'jnic-loader'}, param_names=param_names, low_trust=False)
            if result.body_emitted:
                entry = {'class': cls, 'method': name, 'descriptor': sig if isinstance(sig, str) else None, 'fn_symbol': raw_symbol if isinstance(raw_symbol, str) else fn_symbol, 'source': 'exported_jni_symbol'}
                if isinstance(result.recovery_entry, dict):
                    entry.update(result.recovery_entry)
                else:
                    entry['sources'] = ['heuristic']
                method_recovery.append(entry)
            out_lines.append('  }')
            out_lines.append('')
        out_lines.append('}')
        file_path.write_text('\n'.join(inject_java_imports(out_lines)) + '\n', encoding='utf-8')
        jni_export_sources_written += 1
    export_manifest_path.write_text(json.dumps({'status': 'OK', 'classes_total': len(by_class_exports), 'methods_total': len(manifest_items), 'methods': manifest_items}, ensure_ascii=False, indent=2), encoding='utf-8')
    return jni_export_sources_written, export_methods
