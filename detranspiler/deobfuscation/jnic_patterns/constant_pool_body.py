from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from detranspiler.deobfuscation.jnic_patterns.render import JavaBodyBuilder

_FIELD_ID_RE = re.compile(r'\b(?:DAT|_DAT)_[0-9A-Fa-f]+\b')
_ADDRESS_RE = re.compile(r'(?:_?DAT_|0x)?(?P<address>[0-9A-Fa-f]{8,16})', re.IGNORECASE)


def _local_names(param_names: Sequence[str]) -> Dict[str, str]:
    used = set(param_names)
    out: Dict[str, str] = {}
    for base in ('packed', 'index', 'value', 'keyTable', 'key', 'characterKeys', 'position', 'shift', 'characterKey', 'characters'):
        name = base
        suffix = 2
        while name in used:
            name = f'{base}{suffix}'
            suffix += 1
        used.add(name)
        out[base] = name
    return out


def _address(value: Any) -> Optional[str]:
    match = _ADDRESS_RE.fullmatch(str(value or ''))
    return match.group('address').lower() if match is not None else None


def _pool_fields(jni_calls: Optional[Dict[str, Any]], block: str, class_internal: str, absolute_addresses: Sequence[Any]) -> Optional[Tuple[str, str]]:
    identifiers = {address for value in [*absolute_addresses, *_FIELD_ID_RE.findall(block)] if (address := _address(value)) is not None}
    by_signature: Dict[str, set[str]] = {}
    for call in (jni_calls or {}).get('calls') or []:
        if not isinstance(call, dict):
            continue
        if call.get('jni_name') == 'GetStaticFieldID' and _address(call.get('result_var')) in identifiers and class_internal in (call.get('resolved_classes') or {}).values():
            strings = {str(value) for value in (call.get('resolved_strings') or {}).values() if isinstance(value, str)}
            signatures = strings & {'[Ljava/lang/Object;', '[Ljava/lang/String;'}
            names = strings - signatures
            if len(signatures) == 1 and len(names) == 1:
                by_signature.setdefault(next(iter(signatures)), set()).add(next(iter(names)))
        for identifier, info in (call.get('resolved_ids') or {}).items():
            if _address(identifier) not in identifiers or not isinstance(info, dict):
                continue
            if info.get('kind') != 'field' or info.get('class') != class_internal or not info.get('static') or not info.get('name'):
                continue
            signature = info.get('signature')
            if signature in {'[Ljava/lang/Object;', '[Ljava/lang/String;'}:
                by_signature.setdefault(str(signature), set()).add(str(info['name']))
    object_fields = by_signature.get('[Ljava/lang/Object;', set())
    string_fields = by_signature.get('[Ljava/lang/String;', set())
    if len(object_fields) != 1 or len(string_fields) != 1:
        return None
    return next(iter(object_fields)), next(iter(string_fields))


def recover_constant_pool_decoder(*, fn_symbol: str, block: Optional[str], calls: Sequence[Any], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str]) -> Optional[List[str]]:
    if ret_java != 'int' or list(param_types) != ['long', 'long'] or len(param_names) != 2 or not class_internal or not isinstance(block, str):
        return None
    models = (jni_calls or {}).get('jnic_constant_pool_decoders')
    model = models.get(fn_symbol) if isinstance(models, dict) else None
    keys = model.get('key_table') if isinstance(model, dict) else None
    if not isinstance(keys, list) or len(keys) != 64 or set(keys) != set(range(64)):
        return None
    names = {call.jni_name for call in calls}
    if not {'GetStaticObjectField', 'GetObjectArrayElement', 'IsInstanceOf', 'NewIntArray'} <= names:
        return None
    absolute_addresses = model.get('absolute_addresses')
    fields = _pool_fields(jni_calls, block, class_internal, absolute_addresses if isinstance(absolute_addresses, list) else [])
    if fields is None:
        return None
    pool_field, cache_field = fields
    owner = class_internal.replace('/', '.').replace('$', '.')
    pool = f'{owner}.{pool_field}'
    cache = f'{owner}.{cache_field}'
    local = _local_names(param_names)
    body = JavaBodyBuilder()
    body.line(f'long {local["packed"]} = {param_names[0]} ^ ({param_names[1]} << 48 | {param_names[1]});')
    body.line(f'int {local["index"]} = (int) ({local["packed"]} >>> 46);')
    body.open(f'if ({cache}[{local["index"]}] != null)')
    body.line(f'return {local["index"]};')
    body.close()
    body.line(f'Object {local["value"]} = {pool}[{local["index"]}];')
    body.open(f'if (!({local["value"]} instanceof String))')
    body.line(f'return {local["index"]};')
    body.close()
    body.open(f'int[] {local["keyTable"]} = new int[]')
    for start in range(0, 64, 16):
        values = ', '.join(str(value) for value in keys[start:start + 16])
        body.line(values + (',' if start < 48 else ''))
    body.close(';')
    body.line(f'int {local["key"]} = {local["keyTable"]}[(int) ({local["packed"]} >>> 42 & 0x3f)];')
    body.line(f'int[] {local["characterKeys"]} = new int[6];')
    body.open(f'for (int {local["position"]} = 0; {local["position"]} < {local["characterKeys"]}.length; {local["position"]}++)')
    body.line(f'int {local["shift"]} = 7 * (5 - {local["position"]});')
    body.line(f'int {local["characterKey"]} = ((int) ({local["packed"]} >>> {local["shift"]}) & 0x7f) - {local["key"]};')
    body.open(f'if ({local["characterKey"]} < 0)')
    body.line(f'{local["characterKey"]} += 128;')
    body.close()
    body.line(f'{local["characterKeys"]}[{local["position"]}] = {local["characterKey"]};')
    body.close()
    body.line(f'char[] {local["characters"]} = ((String) {local["value"]}).toCharArray();')
    body.open(f'for (int {local["position"]} = 0; {local["position"]} < {local["characters"]}.length; {local["position"]}++)')
    body.line(f'int {local["characterKey"]} = {local["characterKeys"]}[{local["position"]} % {local["characterKeys"]}.length];')
    body.open(f'if ({local["characterKey"]} == 0)')
    body.line('break;')
    body.close()
    body.line(f'{local["characters"]}[{local["position"]}] = (char) ({local["characters"]}[{local["position"]}] ^ {local["characterKey"]});')
    body.close()
    body.line(f'{cache}[{local["index"]}] = new String({local["characters"]});')
    body.line(f'return {local["index"]};')
    return body.build()


__all__ = ['recover_constant_pool_decoder']
