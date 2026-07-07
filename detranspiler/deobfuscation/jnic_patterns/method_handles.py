from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from detranspiler.deobfuscation.jnic_patterns.render import JavaBodyBuilder


def _call_resolved_id(call: Any, index: int) -> Optional[Dict[str, Any]]:
    if index >= len(call.args):
        return None
    value = call.resolved_ids.get(call.args[index])
    return value if isinstance(value, dict) else None


def recover_method_handle_resolver(*, fn_symbol: str, calls: Sequence[Any], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    simple_types = [item.replace('$', '.').rsplit('.', 1)[-1] for item in param_types]
    if simple_types != ['Lookup', 'MutableCallSite', 'String', 'MethodType', 'long', 'long'] or len(param_names) != 6 or not ret_java.endswith('MethodHandle') or not class_internal:
        return None
    methods = [item for item in (native_index or {}).get('methods', []) if isinstance(item, dict) and item.get('class') == class_internal]
    field_resolvers = [item for item in methods if item.get('descriptor') == '(JJ)Ljava/lang/reflect/Field;' and isinstance(item.get('method'), str)]
    method_resolvers = [item for item in methods if item.get('descriptor') == '(JJ)Ljava/lang/reflect/Method;' and isinstance(item.get('method'), str)]
    if len(field_resolvers) != 1 or len(method_resolvers) != 1:
        return None
    all_calls = [item for item in (jni_calls or {}).get('calls', []) if isinstance(item, dict)]
    id_names = {
        str(info.get('name'))
        for call in all_calls for info in (call.get('resolved_ids') or {}).values()
        if isinstance(info, dict) and info.get('name')
    }
    id_names.update(
        value
        for call in all_calls for value in (call.get('resolved_strings') or {}).values()
        if isinstance(value, str)
    )
    required = {'charAt', 'getDeclaringClass', 'getName', 'getType', 'getReturnType', 'getParameterTypes', 'methodType', 'parameterCount', 'dropArguments', 'findGetter', 'findSetter', 'findStaticGetter', 'findStaticSetter', 'findVirtual', 'findStatic'}
    if not required <= id_names or not any(call.jni_name == 'CallCharMethod' for call in calls):
        return None
    comparison_map = (jni_calls or {}).get('jnic_instruction_comparisons')
    raw_comparisons = comparison_map.get(fn_symbol) if isinstance(comparison_map, dict) else None
    if not isinstance(raw_comparisons, list):
        return None
    by_register: Dict[str, List[Tuple[int, int]]] = {}
    for item in raw_comparisons:
        if not isinstance(item, dict) or not isinstance(item.get('register'), str) or not isinstance(item.get('value'), int):
            continue
        try:
            address = int(str(item.get('address') or '0'), 16)
        except ValueError:
            address = 0
        if 0 <= item['value'] <= 0xffff:
            by_register.setdefault(item['register'], []).append((address, item['value']))
    candidates: List[List[int]] = []
    for entries in by_register.values():
        values: List[int] = []
        for _address, value in sorted(entries):
            if value not in values:
                values.append(value)
        if len(values) in {5, 6}:
            candidates.append(values)
    if len(candidates) != 1:
        return None
    markers = candidates[0]
    if len(markers) == 6 and 'findSpecial' not in id_names:
        return None

    def char_expr(value: int) -> str:
        char = chr(value)
        if char == "'":
            return "'\\''"
        if char == '\\':
            return "'\\\\'"
        if 0x20 <= value <= 0x7e:
            return repr(char)
        return f'(char) 0x{value:04x}'

    getter, setter, static_getter, static_setter = [char_expr(value) for value in markers[:4]]
    virtual = char_expr(markers[4])
    static = char_expr(markers[5]) if len(markers) == 6 else None
    lookup, _call_site, name, method_type, key1, key2 = param_names
    owner = class_internal.replace('/', '.').replace('$', '.')
    field_resolver = field_resolvers[0]['method']
    method_resolver = method_resolvers[0]['method']
    body = JavaBodyBuilder()
    body.line(f'char kind = {name}.charAt(0);')
    body.line('java.lang.invoke.MethodHandle handle;')
    body.line('java.lang.reflect.Field field = null;')
    body.line('java.lang.reflect.Method method = null;')
    body.open('try')
    body.open(f'if (kind == {getter} || kind == {setter} || kind == {static_getter} || kind == {static_setter})')
    body.line(f'field = {owner}.{field_resolver}({key1}, {key2});')
    body.line('Class<?> declaring = field.getDeclaringClass();')
    body.line('String memberName = field.getName();')
    body.line('Class<?> fieldType = field.getType();')
    body.open(f'if (kind == {getter})')
    body.line(f'handle = {lookup}.findGetter(declaring, memberName, fieldType);')
    body.transition(f'else if (kind == {setter})')
    body.line(f'handle = {lookup}.findSetter(declaring, memberName, fieldType);')
    body.transition(f'else if (kind == {static_getter})')
    body.line(f'handle = {lookup}.findStaticGetter(declaring, memberName, fieldType);')
    body.transition('else')
    body.line(f'handle = {lookup}.findStaticSetter(declaring, memberName, fieldType);')
    body.close()
    body.transition('else')
    body.line(f'method = {owner}.{method_resolver}({key1}, {key2});')
    body.line('Class<?> declaring = method.getDeclaringClass();')
    body.line('String memberName = method.getName();')
    body.line('java.lang.invoke.MethodType targetType = java.lang.invoke.MethodType.methodType(method.getReturnType(), method.getParameterTypes());')
    body.open(f'if (kind == {virtual})')
    body.line(f'handle = {lookup}.findVirtual(declaring, memberName, targetType);')
    if static is not None:
        body.transition(f'else if (kind == {static})')
        body.line(f'handle = {lookup}.findStatic(declaring, memberName, targetType);')
        body.transition('else')
        body.line(f'handle = {lookup}.findSpecial(declaring, memberName, targetType, declaring);')
    else:
        body.transition('else')
        body.line(f'handle = {lookup}.findStatic(declaring, memberName, targetType);')
    body.close()
    body.close()
    body.line(f'return java.lang.invoke.MethodHandles.dropArguments(handle, {method_type}.parameterCount() - 2, new Class<?>[] {{ long.class, long.class }});')
    body.transition('catch (Exception e)')
    body.line('String member = field != null ? field.toString() : method != null ? method.toString() : " null ";')
    body.line('throw new RuntimeException(e.getClass().getName() + " : " + member + " : " + e);')
    body.close()
    return body.build()

