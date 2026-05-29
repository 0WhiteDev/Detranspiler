import re
from typing import Any, Dict, List, Optional

from detranspiler.jni.vtable import JNI_INDEX_NAMES
from detranspiler.jar.radioegor.context import _class_decl_name, _int_literal, _java_sig
from detranspiler.jar.radioegor.util import _class_fields
from detranspiler.jar.radioegor.validate import _radioegor_body_is_usable
from detranspiler.jni.register import _resolve_string_expr

_VTABLE_CALL_RE = re.compile('\\(\\*\\*\\(code \\*\\*\\)\\(\\*\\s*\\w+\\s*\\+\\s*(0x[0-9a-fA-F]+)\\)\\)\\s*\\(([^;]*)\\)', re.DOTALL)
_VTABLE_MULTILINE_RE = re.compile(
    '\\(\\*\\*\\(code\\s+\\*\\*\\)\\(\\*\\s*\\w+\\s*\\+\\s*(0x[0-9a-fA-F]+)\\)\\)\\s*\\n\\s*\\(',
    re.IGNORECASE,
)

def _normalize_pseudoc_block(block: str) -> str:
    if not isinstance(block, str) or not block:
        return block
    return _VTABLE_MULTILINE_RE.sub(lambda m: f'(**(code **)(*param_1 + {m.group(1)}))(', block)

def _vtable_call_name(offset_hex: str) -> Optional[str]:
    off = _int_literal(offset_hex)
    if off is None or off < 0 or off % 8 != 0:
        return None
    return JNI_INDEX_NAMES.get(off // 8)

def _split_top_level_args(arg_str: str) -> List[str]:
    args: List[str] = []
    depth = 0
    current = ''
    for ch in arg_str:
        if ch in '([{':
            depth += 1
            current += ch
        elif ch in ')]}':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            args.append(current.strip())
            current = ''
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args

def _block_jni_calls(block: str) -> List[tuple[str, List[str]]]:
    block = _normalize_pseudoc_block(block)
    out: List[tuple[str, List[str]]] = []
    for m in _VTABLE_CALL_RE.finditer(block):
        name = _vtable_call_name(m.group(1))
        if name:
            out.append((name, _split_top_level_args(m.group(2))))
    return out

def _resolve_block_string(expr: str, *, strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int]) -> Optional[str]:
    value, _meta = _resolve_string_expr(str(expr).strip(), strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources={}, read_string_at_va=None, var_assigns={})
    return value if isinstance(value, str) and value else None

_FIELD_GET_RE = re.compile('^Get(?:Static)?(\\w+)Field$')

_FIELD_SET_RE = re.compile('^Set(?:Static)?(\\w+)Field$')

def _accessor_field_candidates(method_name: str) -> set[str]:
    cands = {method_name}
    for prefix in ('get', 'is', 'set'):
        if method_name.startswith(prefix) and len(method_name) > len(prefix):
            rest = method_name[len(prefix):]
            cands.add(rest[0].lower() + rest[1:])
            cands.add(rest)
    return cands

def _infer_field_from_accessor(method_name: str, declared: set[str]) -> Optional[str]:
    if not isinstance(method_name, str) or not method_name:
        return None
    for cand in _accessor_field_candidates(method_name):
        if cand in declared:
            return cand
    if method_name.startswith('get') and len(method_name) > 3:
        tail = method_name[3:]
        for variant in (tail[0].lower() + tail[1:], tail):
            if variant in declared:
                return variant
    return None

def _radioegor_simple_getter_body(*, method: Dict[str, Any], class_text: str, target_params: List[str]) -> Optional[List[str]]:
    ret_java, param_types = _java_sig(method)
    if ret_java in {None, 'void'} or param_types:
        return None
    method_name = method.get('method')
    if not isinstance(method_name, str):
        return None
    declared = {name for name, _typ in _class_fields(class_text)}
    field_name = _infer_field_from_accessor(method_name, declared)
    if not field_name:
        return None
    receiver = _class_decl_name(class_text) or 'this'
    if ret_java == 'boolean' and method_name.startswith('is'):
        return [f'return {receiver}.{field_name};']
    if ret_java in {'int', 'long', 'float', 'double', 'byte', 'short', 'char', 'boolean', 'String', 'java.lang.String'}:
        return [f'return {receiver}.{field_name};']
    return None

def _radioegor_void_int_setter_body(*, method: Dict[str, Any], class_text: str, target_params: List[str]) -> Optional[List[str]]:
    ret_java, param_types = _java_sig(method)
    if ret_java != 'void' or param_types != ['int'] or len(target_params) != 1:
        return None
    int_fields = [name for name, typ in _class_fields(class_text) if typ == 'int']
    if not int_fields:
        return None
    field_name = _infer_field_from_accessor(str(method.get('method') or ''), {name for name, _ in _class_fields(class_text)})
    if field_name not in int_fields:
        field_name = int_fields[0] if len(int_fields) == 1 else None
    if not field_name:
        return None
    return [f'this.{field_name} = {target_params[0]};']

def _radioegor_field_accessor_body(*, method: Dict[str, Any], block: str, target_params: List[str], strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int], class_text: str) -> Optional[List[str]]:
    ret_java, param_types = _java_sig(method)
    if not isinstance(ret_java, str):
        return None
    calls = _block_jni_calls(block)
    if not calls:
        return None
    names = [name for name, _args in calls]
    if any((n.startswith('Call') or n in {'AllocObject', 'NewObject', 'NewObjectV', 'NewObjectA'} or (n.startswith('New') and n.endswith('Array')) for n in names)):
        return None
    field_id_calls = [c for c in calls if c[0] in {'GetFieldID', 'GetStaticFieldID'}]
    if len(field_id_calls) != 1:
        return _radioegor_simple_getter_body(method=method, class_text=class_text, target_params=target_params) or _radioegor_void_int_setter_body(method=method, class_text=class_text, target_params=target_params)
    getters = [c for c in calls if _FIELD_GET_RE.match(c[0]) and c[0] not in {'GetFieldID'}]
    setters = [c for c in calls if _FIELD_SET_RE.match(c[0]) and c[0] not in {'SetFieldID'}]
    is_static = field_id_calls[0][0] == 'GetStaticFieldID'
    id_args = field_id_calls[0][1]
    if len(id_args) < 3:
        return None
    declared = {name for name, _typ in _class_fields(class_text)}
    method_name = method.get('method')
    field_name = _resolve_block_string(id_args[2], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
    if not field_name or not re.fullmatch('[A-Za-z_$][A-Za-z0-9_$]*', field_name):
        field_name = _infer_field_from_accessor(str(method_name or ''), declared)
    if not field_name or field_name not in declared:
        return _radioegor_simple_getter_body(method=method, class_text=class_text, target_params=target_params) or _radioegor_void_int_setter_body(method=method, class_text=class_text, target_params=target_params)
    if not isinstance(method_name, str) or field_name not in _accessor_field_candidates(method_name):
        return None
    receiver = (_class_decl_name(class_text) if is_static else 'this') or 'this'
    if ret_java != 'void' and (not param_types) and getters and (not setters):
        return [f'return {receiver}.{field_name};']
    if ret_java == 'void' and len(param_types) == 1 and (len(target_params) == 1) and setters and (not getters):
        return [f'{receiver}.{field_name} = {target_params[0]};']
    return None

_BOILERPLATE_JNI = frozenset({'ExceptionCheck', 'ExceptionOccurred', 'ExceptionClear', 'ExceptionDescribe', 'DeleteLocalRef', 'DeleteGlobalRef', 'DeleteWeakGlobalRef', 'NewLocalRef', 'NewGlobalRef', 'NewWeakGlobalRef', 'PushLocalFrame', 'PopLocalFrame', 'EnsureLocalCapacity', 'GetObjectRefType', 'IsSameObject', 'MonitorEnter', 'MonitorExit', 'GetStringUTFChars', 'ReleaseStringUTFChars', 'GetStringLength', 'GetStringUTFLength'})

def _java_string_literal(value: str) -> str:
    out = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'

def _radioegor_void_two_int_setter_body(*, method: Dict[str, Any], class_text: str, target_params: List[str]) -> Optional[List[str]]:
    ret_java, param_types = _java_sig(method)
    if ret_java != 'void' or param_types != ['int', 'int'] or len(target_params) != 2:
        return None
    int_fields = [name for name, typ in _class_fields(class_text) if typ == 'int']
    if len(int_fields) >= 2:
        return [f'this.{int_fields[0]} = {target_params[0]};', f'this.{int_fields[1]} = {target_params[1]};']
    return None

def _radioegor_pipeline_body(*, method: Dict[str, Any], class_internal: str, target_params: List[str], repair_state: Any) -> Optional[List[str]]:
    if repair_state is None or not class_internal:
        return None
    method_name = method.get('method')
    if not isinstance(method_name, str) or not method_name:
        return None
    from detranspiler.jar.locals import resolve_java_param_names
    from detranspiler.jar.native_repair import recover_method_body_lines
    from detranspiler.jar.radioegor.util import _translate_params
    descriptor = method.get('descriptor') if isinstance(method.get('descriptor'), str) else None
    fn_symbol = method.get('fn_symbol') if isinstance(method.get('fn_symbol'), str) else None
    body = recover_method_body_lines(repair_state, class_internal=class_internal, method_name=method_name, descriptor=descriptor, fn_symbol=fn_symbol)
    if not isinstance(body, list) or not body or not _radioegor_body_is_usable(body):
        return None
    _ret_java, param_types = _java_sig(method)
    pipeline_params = resolve_java_param_names(param_types=param_types, class_internal=class_internal, method=method_name, descriptor=descriptor, is_static=False, jar_meta=getattr(repair_state, 'jar_meta', None), jar_index=getattr(repair_state, 'jar_index', None))
    if pipeline_params and target_params and pipeline_params != target_params:
        body = _translate_params([str(ln) for ln in body], [str(p) for p in pipeline_params], target_params)
    return body if _radioegor_body_is_usable(body) else None

def _radioegor_constant_string_body(*, method: Dict[str, Any], block: str, strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int]) -> Optional[List[str]]:
    ret_java, _param_types = _java_sig(method)
    if ret_java not in {'String', 'java.lang.String'}:
        return None
    calls = _block_jni_calls(block)
    if not calls:
        return None
    new_strings = [c for c in calls if c[0] in {'NewStringUTF', 'NewString'}]
    if len(new_strings) != 1:
        return None
    for name, _args in calls:
        if name in {'NewStringUTF', 'NewString'} or name in _BOILERPLATE_JNI:
            continue
        return None
    args = new_strings[0][1]
    if len(args) < 2:
        return None
    literal = _resolve_block_string(args[1], strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values)
    if literal is None:
        return None
    return [f'return {_java_string_literal(literal)};']

def _radioegor_native_body(*, method: Dict[str, Any], block: Optional[str], target_params: List[str], strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int], class_text: str='', class_internal: str='', repair_state: Any=None, jar_class_texts: Optional[Dict[str, str]]=None) -> Optional[List[str]]:
    if not isinstance(block, str) or not block.strip():
        return _radioegor_simple_getter_body(method=method, class_text=class_text, target_params=target_params) or _radioegor_void_int_setter_body(method=method, class_text=class_text, target_params=target_params) or _radioegor_void_two_int_setter_body(method=method, class_text=class_text, target_params=target_params)
    from detranspiler.jar.radioegor.block_synthesis import _radioegor_jni_invoke_body
    for producer in (
        lambda: _radioegor_field_accessor_body(method=method, block=block, target_params=target_params, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, class_text=class_text),
        lambda: _radioegor_constant_string_body(method=method, block=block, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values),
        lambda: _radioegor_jni_invoke_body(method=method, block=block, target_params=target_params, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, class_text=class_text, jar_class_texts=jar_class_texts),
        lambda: _radioegor_simple_getter_body(method=method, class_text=class_text, target_params=target_params),
        lambda: _radioegor_void_int_setter_body(method=method, class_text=class_text, target_params=target_params),
        lambda: _radioegor_void_two_int_setter_body(method=method, class_text=class_text, target_params=target_params),
        lambda: _radioegor_pipeline_body(method=method, class_internal=class_internal, target_params=target_params, repair_state=repair_state),
    ):
        body = producer()
        if isinstance(body, list) and body and _radioegor_body_is_usable(body):
            return body
    return None
