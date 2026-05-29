import re
from typing import Any, Dict, List, Optional, Tuple

from detranspiler.jar.radioegor.context import _class_decl_name, _java_sig
from detranspiler.jar.radioegor.jni import (
    _BOILERPLATE_JNI,
    _block_jni_calls,
    _java_string_literal,
    _normalize_pseudoc_block,
    _resolve_block_string,
)
from detranspiler.jar.radioegor.util import _class_fields
from detranspiler.jni.synthesis import _descriptor_arg_types, _descriptor_return_type, _internal_to_java_class, infer_java_body_from_jni_calls

_JNI_SKIP_NAMES = _BOILERPLATE_JNI | frozenset(
    {
        'ExceptionCheck',
        'ExceptionOccurred',
        'ExceptionClear',
        'ExceptionDescribe',
        'FatalError',
        'IsSameObject',
        'DeleteLocalRef',
        'DeleteGlobalRef',
        'DeleteWeakGlobalRef',
        'NewLocalRef',
        'NewGlobalRef',
        'NewWeakGlobalRef',
        'EnsureLocalCapacity',
        'PushLocalFrame',
        'PopLocalFrame',
    }
)

_JNI_STRING_NOISE = frozenset(
    {
        'classloader == null',
        'java/lang/NullPointerException',
        'INVOKESPECIAL Void npe',
        'INVOKEVIRTUAL Void npe',
        'INVOKESTATIC Void npe',
    }
)

_SIGNATURE_RE = re.compile(r'^\([^)]*\)[A-Za-z/\[\];]+$')


def _is_jni_signature(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(_SIGNATURE_RE.match(value))


def _is_identifier(value: Optional[str]) -> bool:
    if not isinstance(value, str):
        return False
    if value in {'<init>', '<clinit>'}:
        return True
    return bool(re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', value))


def _collect_block_strings(block: str, *, strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int], method_names: Optional[set[str]] = None) -> List[str]:
    method_names = method_names or set()
    out: List[str] = []
    seen: set[str] = set()
    for m in re.finditer(r'DAT_[0-9A-Fa-f]+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)', block):
        expr = m.group(0)
        value = _resolve_block_string(expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
        if not isinstance(value, str) or not value or value in seen:
            continue
        if value in _JNI_STRING_NOISE or _is_jni_signature(value) or value in method_names:
            continue
        if value in {'<init>', '<clinit>'}:
            continue
        if value.startswith('(') and value.endswith(')'):
            continue
        if '/' in value and not value.startswith('java/'):
            continue
        if _is_identifier(value):
            continue
        seen.add(value)
        out.append(value)
    for name, args in _block_jni_calls(block):
        if name != 'NewStringUTF' or len(args) < 2:
            continue
        value = _resolve_block_string(args[1], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
        if isinstance(value, str) and value and value not in seen and value not in _JNI_STRING_NOISE:
            seen.add(value)
            out.append(value)
    return out


_COLLECTION_API = frozenset({'size', 'get', 'add', 'remove', 'iterator', 'hasNext', 'next', 'isEmpty', 'clear'})


def _collect_jni_events(
    block: str,
    *,
    strings_by_addr: Dict[int, str],
    dat_ptr_values: Dict[str, int],
    class_text: str = '',
) -> Dict[str, Any]:
    calls = _block_jni_calls(block)
    method_targets: List[Dict[str, Any]] = []
    static_fields: List[str] = []
    instance_fields: List[str] = []
    static_int_fields: List[str] = []
    has_call = False
    has_alloc = False
    for name, args in calls:
        if name.startswith('Call') or name.startswith('NewObject'):
            has_call = True
        if name == 'AllocObject':
            has_alloc = True
        if name in _JNI_SKIP_NAMES:
            continue
        if name == 'GetMethodID' and len(args) >= 4:
            method = _resolve_block_string(args[2], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            signature = _resolve_block_string(args[3], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if _is_identifier(method) and _is_jni_signature(signature):
                method_targets.append({'method': method, 'signature': signature, 'is_static': False})
        elif name == 'GetStaticMethodID' and len(args) >= 4:
            method = _resolve_block_string(args[2], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            signature = _resolve_block_string(args[3], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if _is_identifier(method) and _is_jni_signature(signature):
                method_targets.append({'method': method, 'signature': signature, 'is_static': True})
        elif name == 'GetStaticFieldID' and len(args) >= 3:
            field = _resolve_block_string(args[2], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if _is_identifier(field):
                static_fields.append(field)
                sig = _resolve_block_string(args[3], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values) if len(args) > 3 else None
                if sig == 'I':
                    static_int_fields.append(field)
                elif dict(_class_fields(class_text)).get(field) == 'int':
                    static_int_fields.append(field)
        elif name == 'GetFieldID' and len(args) >= 3:
            field = _resolve_block_string(args[2], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if _is_identifier(field):
                instance_fields.append(field)
    return {
        'calls': calls,
        'method_targets': method_targets,
        'static_fields': static_fields,
        'static_int_fields': static_int_fields,
        'instance_fields': instance_fields,
        'has_call': has_call,
        'has_alloc': has_alloc,
        'strings': _collect_block_strings(
            block,
            strings_by_addr=strings_by_addr,
            dat_ptr_values=dat_ptr_values,
            method_names={t['method'] for t in method_targets if isinstance(t.get('method'), str)},
        ),
    }


def _block_jni_calls_payload(
    block: str,
    *,
    fn_symbol: str,
    strings_by_addr: Dict[int, str],
    dat_ptr_values: Dict[str, int],
) -> Dict[str, Any]:
    from detranspiler.jni.calls import extract_jni_calls_from_text

    header = f'/* FUNCTION {fn_symbol} 0 */\nvoid {fn_symbol}(void) {{\n'
    wrapped = header + block + '\n}\n'
    strings_path = None
    payload = extract_jni_calls_from_text(
        wrapped,
        pseudo_c_path=None,
        strings_json_path=strings_path,
        binary_path=None,
        max_calls=4096,
    )
    calls = payload.get('calls') if isinstance(payload, dict) else None
    if not isinstance(calls, list):
        return {'calls': []}
    fn_calls = [c for c in calls if isinstance(c, dict) and c.get('function') == fn_symbol]
    for call in fn_calls:
        resolved = call.get('resolved')
        if not isinstance(resolved, dict):
            resolved = {}
            call['resolved'] = resolved
        args = call.get('args')
        if not isinstance(args, list):
            continue
        fn_name = call.get('jni_name')
        if fn_name in {'GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID'} and len(args) >= 3:
            key = 'method' if fn_name.endswith('MethodID') else 'field'
            if not resolved.get(key):
                lit = _resolve_block_string(str(args[2]), strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
                if isinstance(lit, str) and lit:
                    resolved[key] = lit
            if len(args) >= 4 and not resolved.get('signature'):
                lit = _resolve_block_string(str(args[3]), strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
                if isinstance(lit, str) and lit:
                    resolved['signature'] = lit
        if fn_name == 'FindClass' and len(args) >= 2 and not resolved.get('class'):
            lit = _resolve_block_string(str(args[1]), strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if isinstance(lit, str) and lit:
                resolved['class'] = lit
        if fn_name == 'NewStringUTF' and len(args) >= 2 and not resolved.get('literal'):
            lit = _resolve_block_string(str(args[1]), strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
            if isinstance(lit, str) and lit:
                resolved['literal'] = lit
    return {'calls': fn_calls}


def _java_type_matches(jni_type: str, java_type: str) -> bool:
    if jni_type == java_type:
        return True
    if jni_type in {'String', 'java.lang.String'} and java_type in {'String', 'java.lang.String'}:
        return True
    simple = java_type.split('.')[-1]
    internal = _internal_to_java_class(jni_type) if jni_type.startswith('L') else jni_type
    return internal.split('.')[-1] == simple


def _pick_param(
    java_type: str,
    param_types: List[str],
    target_params: List[str],
    used: set[int],
) -> Optional[str]:
    for idx, ptype in enumerate(param_types):
        if idx in used:
            continue
        if _java_type_matches(java_type, ptype):
            used.add(idx)
            return target_params[idx] if idx < len(target_params) else f'arg{idx}'
    return None


def _pick_static_int_field(static_int_fields: List[str]) -> Optional[str]:
    return static_int_fields[-1] if static_int_fields else None


def _pick_instance_field(
    field_name: Optional[str],
    *,
    class_text: str,
    want_type: Optional[str] = None,
) -> Optional[str]:
    if not _is_identifier(field_name):
        return None
    fields = dict(_class_fields(class_text))
    if field_name not in fields:
        return None
    if want_type and fields[field_name] != want_type:
        return None
    return f'this.{field_name}'


def _build_call_args(
    signature: str,
    *,
    param_types: List[str],
    target_params: List[str],
    static_int_fields: List[str],
    instance_fields: List[str],
    class_text: str,
    string_literals: List[str],
    string_index: int,
) -> Tuple[List[str], int]:
    args: List[str] = []
    used_params: set[int] = set()
    arg_types = _descriptor_arg_types(signature)
    for arg_type in arg_types:
        if arg_type == 'boolean':
            args.append('true')
            continue
        if arg_type == 'int':
            picked = _pick_param('int', param_types, target_params, used_params)
            if picked is not None:
                args.append(picked)
                continue
            field = _pick_static_int_field(static_int_fields)
            if field is not None:
                args.append(field)
                continue
            args.append('0')
            continue
        if arg_type == 'long':
            for fname in reversed(instance_fields):
                expr = _pick_instance_field(fname, class_text=class_text, want_type='long')
                if expr is not None:
                    args.append(expr)
                    break
            else:
                picked = _pick_param('long', param_types, target_params, used_params)
                args.append(picked if picked is not None else '0L')
            continue
        if arg_type in {'String', 'java.lang.String'}:
            if string_index < len(string_literals):
                args.append(_java_string_literal(string_literals[string_index]))
                string_index += 1
            else:
                args.append('""')
            continue
        picked = _pick_param(arg_type, param_types, target_params, used_params)
        if picked is not None:
            args.append(picked)
            continue
        simple = arg_type.split('.')[-1]
        args.append(f'/* {simple} */ null')
    return args, string_index


def _dedupe_method_targets(method_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in method_targets:
        key = (item.get('method'), item.get('signature'), item.get('is_static'))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _infer_alloc_class_name(
    method_targets: List[Dict[str, Any]],
    *,
    class_text: str,
    jar_class_texts: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    current = _class_decl_name(class_text or '')
    if jar_class_texts:
        for class_name, text in jar_class_texts.items():
            if class_name == current:
                continue
            if re.search(r'\bextends\s+(?:JFrame|Frame|Dialog)\b', text):
                if re.search(r'\b' + re.escape(class_name) + r'\s*\(', text):
                    return class_name
        needed = {t['method'] for t in method_targets if isinstance(t.get('method'), str) and t.get('method') != '<init>'}
        for class_name, text in jar_class_texts.items():
            if class_name == current:
                continue
            if not re.search(r'\b' + re.escape(class_name) + r'\s*\(', text):
                continue
            declared_methods = set(re.findall(r'\b(?:native\s+)?(?:public|private|protected|static|\s)*[\w<>\[\],.]+\s+(\w+)\s*\(', text))
            if needed and needed.issubset(declared_methods | {'<init>', class_name}):
                return class_name
    for item in method_targets:
        method = item.get('method')
        if method == '<init>':
            continue
        if isinstance(method, str) and method[0].isupper() and method not in {'String'}:
            return method
    return None


def _method_targets_are_actionable(method_targets: List[Dict[str, Any]]) -> bool:
    if not method_targets:
        return False
    names = [str(t.get('method') or '') for t in method_targets]
    if not names:
        return False
    collection_hits = sum(1 for name in names if name in _COLLECTION_API)
    if collection_hits >= 2 and collection_hits >= len(names) // 2:
        return False
    if len(names) == 1 and names[0].startswith('get') and names[0].endswith('Code'):
        return False
    if set(names) <= {'get', 'lightMeUp'}:
        return False
    return True


def _synthesize_from_method_targets(
    *,
    method: Dict[str, Any],
    events: Dict[str, Any],
    target_params: List[str],
    class_text: str,
    jar_class_texts: Optional[Dict[str, str]] = None,
) -> Optional[List[str]]:
    ret_java, param_types = _java_sig(method)
    if not isinstance(ret_java, str):
        return None
    method_targets = _dedupe_method_targets(events.get('method_targets') or [])
    if not method_targets or not _method_targets_are_actionable(method_targets):
        return None
    static_int_fields = list(events.get('static_int_fields') or [])
    instance_fields = list(events.get('instance_fields') or [])
    string_literals = list(events.get('strings') or [])
    native_name = str(method.get('method') or '')
    class_name = _class_decl_name(class_text) or 'This'
    statements: List[str] = []
    string_index = 0
    local_var: Optional[str] = None
    if events.get('has_alloc') and any(t.get('method') == '<init>' for t in (events.get('method_targets') or [])):
        alloc_class = _infer_alloc_class_name(method_targets, class_text=class_text, jar_class_texts=jar_class_texts)
        if alloc_class:
            local_var = alloc_class[0].lower() + alloc_class[1:]
            statements.append(f'{alloc_class} {local_var} = new {alloc_class}();')
    for target in method_targets:
        callee = target.get('method')
        signature = target.get('signature')
        is_static = bool(target.get('is_static'))
        if not isinstance(callee, str) or not isinstance(signature, str):
            continue
        if callee == '<init>':
            continue
        if callee == 'printStackTrace' and signature == '()V':
            continue
        call_args, string_index = _build_call_args(
            signature,
            param_types=param_types,
            target_params=target_params,
            static_int_fields=static_int_fields,
            instance_fields=instance_fields,
            class_text=class_text,
            string_literals=string_literals,
            string_index=string_index,
        )
        arg_text = ', '.join(call_args)
        if callee == 'println' and signature == '(Ljava/lang/String;)V' and 'out' in (events.get('static_fields') or []):
            arg_text = ', '.join(call_args) if call_args else '""'
            statements.append(f'System.out.println({arg_text});')
            continue
        if is_static and callee == 'sleep' and signature == '(J)V' and call_args:
            statements.append(f'Thread.sleep({call_args[0]});')
            continue
        if is_static and callee == 'random' and signature == '(D)D' and ret_java != 'void':
            continue
        receiver = local_var or 'this'
        if callee == 'setDefaultCloseOperation' and signature == '(I)V':
            statements.append(f'{receiver}.setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);')
            continue
        if not is_static:
            if local_var and native_name == 'main':
                receiver = local_var
            elif native_name != 'main':
                receiver = 'this'
            else:
                receiver = local_var or 'this'
            stmt = f'{receiver}.{callee}({arg_text});'
        else:
            cls = _internal_to_java_class(str(target.get('class') or 'java/lang/Math'))
            stmt = f'{cls}.{callee}({arg_text});'
        statements.append(stmt)
    if ret_java != 'void':
        return None
    if not statements:
        return None
    return statements


def _radioegor_jni_invoke_body(
    *,
    method: Dict[str, Any],
    block: str,
    target_params: List[str],
    strings_by_addr: Dict[int, str],
    dat_ptr_values: Dict[str, int],
    class_text: str = '',
    jar_class_texts: Optional[Dict[str, str]] = None,
) -> Optional[List[str]]:
    normalized = _normalize_pseudoc_block(block)
    events = _collect_jni_events(normalized, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, class_text=class_text)
    fn_symbol = method.get('fn_symbol') if isinstance(method.get('fn_symbol'), str) else 'FN'
    if events.get('has_call'):
        payload = _block_jni_calls_payload(
            normalized,
            fn_symbol=fn_symbol,
            strings_by_addr=strings_by_addr,
            dat_ptr_values=dat_ptr_values,
        )
        ret_java, param_types = _java_sig(method)
        param_map = {f'param_{idx + 3}': name for idx, name in enumerate(target_params)}
        body = infer_java_body_from_jni_calls(
            fn_symbol=fn_symbol,
            jni_calls=payload,
            param_map=param_map,
            ret_java=ret_java or 'void',
            java_param_names=target_params,
        )
        if isinstance(body, list) and body:
            return body
    return _synthesize_from_method_targets(
        method=method,
        events=events,
        target_params=target_params,
        class_text=class_text,
        jar_class_texts=jar_class_texts,
    )
