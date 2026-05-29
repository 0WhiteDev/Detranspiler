from typing import Any, Dict, List, Optional
from detranspiler.java.comment_escape import _java_comment_escape
from detranspiler.jni.synthesis import infer_java_body_from_jni_calls

def _jni_call_hints_by_function(jni_calls: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    if not isinstance(jni_calls, dict):
        return {}
    calls = jni_calls.get('calls')
    if not isinstance(calls, list):
        return {}
    out: Dict[str, List[str]] = {}
    for call in calls:
        if not isinstance(call, dict):
            continue
        fn = call.get('function')
        if not isinstance(fn, str) or not fn:
            continue
        resolved = call.get('resolved')
        if not isinstance(resolved, dict):
            continue
        hints: List[str] = []
        target = resolved.get('target_method')
        if isinstance(target, dict):
            cls = target.get('class')
            method = target.get('method')
            sig = target.get('signature')
            call_name = call.get('jni_name')
            if method:
                prefix = f'{cls}.' if isinstance(cls, str) and cls else ''
                suffix = f' {sig}' if isinstance(sig, str) and sig else ''
                via = f' via {call_name}' if isinstance(call_name, str) and call_name else ''
                hints.append(f'JNI calls {prefix}{method}{suffix}{via}')
        cls2 = resolved.get('class')
        if isinstance(cls2, str) and cls2 and (call.get('jni_name') == 'FindClass'):
            hints.append(f'JNI finds class {cls2}')
        if not hints:
            continue
        bucket = out.setdefault(fn, [])
        for hint in hints:
            if hint not in bucket:
                bucket.append(hint)
                if len(bucket) >= 20:
                    break
    return out

def _jni_side_effect_lines(*, fn_symbol: Optional[str], jni_calls: Optional[Dict[str, Any]], param_map: Dict[str, str], ret_java: str, java_param_names: List[str]) -> List[str]:
    body = infer_java_body_from_jni_calls(fn_symbol=fn_symbol, jni_calls=jni_calls, param_map=param_map, ret_java=ret_java, java_param_names=java_param_names, max_statements=64)
    if not isinstance(body, list):
        return []
    return [ln for ln in body if not ln.strip().startswith('return ')]

def _emit_jni_hints(lines: List[str], hints_by_function: Dict[str, List[str]], fn_symbol: Optional[str]) -> None:
    return

def _emit_flattening_hints(lines: List[str], hints: Dict[str, List[str]], fn_symbol: Optional[str]) -> None:
    return

def _flattening_hints_by_function(flattening: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    if not isinstance(flattening, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for fn in flattening.get('functions') or []:
        if not isinstance(fn, dict):
            continue
        name = fn.get('function')
        hint = fn.get('recovery_hint')
        if isinstance(name, str) and isinstance(hint, str) and hint:
            out.setdefault(name, []).append(hint)
        for island in fn.get('semantic_islands') or []:
            if not isinstance(island, dict):
                continue
            if island.get('kind') == 'puts' and isinstance(island.get('value'), str):
                out.setdefault(name, []).append(f"flattened puts: {island['value']}")
    return out

def _emit_flattening_hints(lines: List[str], hints: Dict[str, List[str]], fn_symbol: Optional[str]) -> None:
    return
