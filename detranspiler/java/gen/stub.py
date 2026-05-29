from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.jar.guided import get_jar_reference_body, get_jar_return_expr
from detranspiler.java.gen.recover_body import MethodBodyRequest, emit_recovered_method_body
from detranspiler.java.gen.state import GenerationState
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.jni_export_parse import _parse_jni_export_name
from detranspiler.java.recovery_hints import _emit_flattening_hints, _emit_jni_hints
from detranspiler.java.type_mapping import _default_return_expr

def _resolve_stub_method_meta(state: GenerationState, raw_name: str, method_ident: str, sig: Optional[tuple]) -> tuple[str, str, Optional[str], str, List[str], List[str]]:
    ret_java = sig[0] if sig else 'void'
    param_types = [t for t, _n in sig[1]] if sig else []
    param_names = [n for _t, n in sig[1]] if sig else []
    class_internal = f'native/{state.class_ident}'
    method_name = method_ident
    descriptor: Optional[str] = None
    parsed = _parse_jni_export_name(raw_name, jar_meta=state.jar_meta)
    if isinstance(parsed, dict):
        cls = parsed.get('class')
        mname = parsed.get('method')
        desc = parsed.get('descriptor')
        if isinstance(cls, str) and cls:
            class_internal = cls
        if isinstance(mname, str) and mname:
            method_name = mname
        if isinstance(desc, str) and desc:
            descriptor = desc
    return class_internal, method_name, descriptor, ret_java, param_types, param_names

def write_stub_class(state: GenerationState, out_path: Path, *, method_recovery: Optional[List[Dict[str, Any]]]=None) -> int:
    lines: List[str] = [f'public final class {state.class_ident} {{', f'  private {state.class_ident}() {{}}', '']
    recovered = 0
    for raw_name, method_ident in state.method_items:
        sig = state.sig_by_raw.get(raw_name) or state.sig_by_sanitized.get(_sanitize_java_identifier(raw_name))
        if sig:
            ret_java, params = sig
            params_str = ', '.join((f'{t} {n}' for t, n in params))
            lines.append(f'  public static {ret_java} {method_ident}({params_str}) {{')
        else:
            ret_java = 'void'
            params = []
            lines.append(f'  public static void {method_ident}() {{')
        class_internal, method_name, descriptor, ret_java, param_types, param_names = _resolve_stub_method_meta(state, raw_name, method_ident, sig)
        jar_ref = get_jar_reference_body(jar_index=state.jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
        jar_ret = get_jar_return_expr(jar_index=state.jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
        _emit_jni_hints(lines, state.jni_hints, raw_name)
        _emit_flattening_hints(lines, state.flat_hints, raw_name)
        result = emit_recovered_method_body(state, lines, MethodBodyRequest(class_internal=class_internal, method_name=method_name, descriptor=descriptor, ret_java=ret_java, param_types=param_types, param_names=param_names, block_primary=raw_name, use_helper_blocks=True, use_interproc=True, side_effect_symbol=raw_name, void_symbol=raw_name, hint_main=bool(method_name == 'main' and descriptor == '([Ljava/lang/String;)V')), jar_ref=jar_ref, jar_ret=jar_ret)
        if not result.body_emitted:
            default_ret = _default_return_expr(ret_java)
            if default_ret is not None:
                lines.append(f'    return {default_ret};')
        else:
            recovered += 1
            if isinstance(method_recovery, list):
                entry: Dict[str, Any] = {'class': class_internal, 'method': method_name, 'descriptor': descriptor, 'fn_symbol': raw_name, 'source': 'native_stub'}
                if isinstance(result.recovery_entry, dict):
                    entry.update(result.recovery_entry)
                else:
                    entry['sources'] = ['heuristic']
                method_recovery.append(entry)
        lines.append('  }')
        lines.append('')
    lines.append('}')
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return recovered
