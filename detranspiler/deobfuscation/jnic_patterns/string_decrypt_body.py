from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Tuple

from detranspiler.deobfuscation.jnic_patterns.render import JavaBodyBuilder


def _local_names(param_names: Sequence[str]) -> Dict[str, str]:
    used = set(param_names)
    out: Dict[str, str] = {}
    for base in ('index', 'characters', 'keyTable', 'key', 'seed', 'evenKey', 'oddKey', 'position'):
        name = base
        suffix = 2
        while name in used:
            name = f'{base}{suffix}'
            suffix += 1
        used.add(name)
        out[base] = name
    return out


def _string_fields(calls: Sequence[Any], class_internal: str) -> Optional[Tuple[str, str]]:
    fields = Counter(
        str(info.get('name'))
        for call in calls
        for info in call.resolved_ids.values()
        if isinstance(info, dict)
        and info.get('kind') == 'field'
        and info.get('class') == class_internal
        and info.get('static')
        and info.get('signature') == '[Ljava/lang/String;'
        and info.get('name')
    )
    if len(fields) != 2:
        return None
    ordered = fields.most_common()
    if ordered[0][1] == ordered[1][1]:
        return None
    return ordered[0][0], ordered[1][0]


def recover_string_decryptor(*, fn_symbol: str, calls: Sequence[Any], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str]) -> Optional[List[str]]:
    simple_return = ret_java.replace('$', '.').rsplit('.', 1)[-1]
    if simple_return != 'String' or len(param_names) not in {2, 3} or list(param_types) != ['int'] * len(param_names) or not class_internal:
        return None
    models = (jni_calls or {}).get('jnic_string_decryptors')
    model = models.get(fn_symbol) if isinstance(models, dict) else None
    if not isinstance(model, dict) or model.get('parameter_count') != len(param_names):
        return None
    keys = model.get('key_table')
    index_xor = model.get('index_xor')
    if not isinstance(keys, list) or len(keys) != 256 or set(keys) != set(range(256)) or not isinstance(index_xor, int):
        return None
    names = {call.jni_name for call in calls}
    if not {'GetStaticObjectField', 'GetObjectArrayElement', 'CallObjectMethod', 'GetCharArrayRegion', 'GetArrayLength'} <= names:
        return None
    fields = _string_fields(calls, class_internal)
    if fields is None:
        return None
    cache_field, encrypted_field = fields
    owner = class_internal.replace('/', '.').replace('$', '.')
    cache = f'{owner}.{cache_field}'
    encrypted = f'{owner}.{encrypted_field}'
    local = _local_names(param_names)
    index_expression = f'{param_names[0]} ^ {param_names[2]} ^ 0x{index_xor:04x}' if len(param_names) == 3 else f'{param_names[0]} ^ 0x{index_xor:04x}'
    seed_expression = f'{param_names[1]} ^ {param_names[2]}' if len(param_names) == 3 else param_names[1]
    body = JavaBodyBuilder()
    body.line(f'int {local["index"]} = ({index_expression}) & 0xffff;')
    body.open(f'if ({cache}[{local["index"]}] == null)')
    body.line(f'char[] {local["characters"]} = {encrypted}[{local["index"]}].toCharArray();')
    body.open(f'int[] {local["keyTable"]} = new int[]')
    for start in range(0, 256, 16):
        values = ', '.join(str(value) for value in keys[start:start + 16])
        body.line(values + (',' if start < 240 else ''))
    body.close(';')
    body.line(f'int {local["key"]} = {local["keyTable"]}[{local["characters"]}[0] & 0xff];')
    body.line(f'int {local["seed"]} = {seed_expression};')
    body.line(f'int {local["evenKey"]} = ({local["seed"]} & 0xff) - {local["key"]};')
    body.open(f'if ({local["evenKey"]} < 0)')
    body.line(f'{local["evenKey"]} += 256;')
    body.close()
    body.line(f'int {local["oddKey"]} = (({local["seed"]} & 0xffff) >>> 8) - {local["key"]};')
    body.open(f'if ({local["oddKey"]} < 0)')
    body.line(f'{local["oddKey"]} += 256;')
    body.close()
    body.open(f'for (int {local["position"]} = 0; {local["position"]} < {local["characters"]}.length; {local["position"]}++)')
    body.open(f'if (({local["position"]} & 1) == 0)')
    body.line(f'{local["characters"]}[{local["position"]}] = (char) ({local["characters"]}[{local["position"]}] ^ {local["evenKey"]});')
    body.line(f'{local["evenKey"]} = (({local["evenKey"]} >>> 3 | {local["evenKey"]} << 5) ^ {local["characters"]}[{local["position"]}]) & 0xff;')
    body.transition('else')
    body.line(f'{local["characters"]}[{local["position"]}] = (char) ({local["characters"]}[{local["position"]}] ^ {local["oddKey"]});')
    body.line(f'{local["oddKey"]} = (({local["oddKey"]} >>> 3 | {local["oddKey"]} << 5) ^ {local["characters"]}[{local["position"]}]) & 0xff;')
    body.close()
    body.close()
    body.line(f'{cache}[{local["index"]}] = new String({local["characters"]}).intern();')
    body.close()
    body.line(f'return {cache}[{local["index"]}];')
    return body.build()


__all__ = ['recover_string_decryptor']
