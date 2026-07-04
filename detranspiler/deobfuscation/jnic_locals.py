from __future__ import annotations

import ast
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

ReadU64 = Callable[[int], Optional[int]]

_FUNC_RE = re.compile(r'/\* FUNCTION (?P<name>\S+)\s+[0-9A-Fa-f]+\s+\*/')
_DECL_RE = re.compile(
    r'^\s*(?P<type>undefined\d+|byte|char|uchar|short|ushort|int|uint|longlong|ulonglong|'
    r'undefined|bool)\s+(?P<name>_?(?:local|uStack|iStack|lStack)_[0-9A-Fa-f]+)\s*;'
)
_ASSIGN_RE = re.compile(
    r'^\s*(?P<name>[A-Za-z_]\w*)(?:\._(?P<part_off>\d+)_(?P<part_size>\d+)_)?\s*=\s*(?P<expr>.+);\s*$'
)
_ARRAY_DECL_RE = re.compile(r'^\s*(?P<type>wchar_t|undefined1|byte|char|uchar)\s+(?P<name>_?(?:local|[A-Za-z]+Stack)_[0-9A-Fa-f]+)\s*\[\s*(?P<count>\d+)\s*]\s*;')
_ARRAY_ASSIGN_RE = re.compile(r'^\s*(?P<name>[A-Za-z_]\w*)\[(?P<index>\d+)]\s*=\s*(?P<expr>.+);\s*$')
_WIDE_GLOBAL_INDEX_RE = re.compile(r'u_[A-Za-z0-9_]*_([0-9A-Fa-f]{6,})\[(\d+)]')
_STACK_RE = re.compile(r'^_?(?:local|[A-Za-z]+Stack)_([0-9A-Fa-f]+)$')
_GLOBAL_RE = re.compile(r'(?<![A-Za-z0-9_])_?(?:DAT|UNK)_([0-9A-Fa-f]{6,})(?![A-Za-z0-9_])')
_TOKEN_RE = re.compile(r'(?<![A-Za-z0-9_])([A-Za-z_]\w*)(?![A-Za-z0-9_])')
_CAST_RE = re.compile(
    r'\((?:(?:un)?signed\s+)?(?:undefined\d*|u?int\d*|u?long(?:long)?|u?short|u?char|'
    r'byte|char|bool|size_t|float|double|code|void)(?:\s*\*+)?\)'
)
_CONCAT_RE = re.compile(r'CONCAT(?P<hi>\d)(?P<lo>\d)\s*\(')
_KEYSTREAM_LOAD_RE = re.compile(
    r'\*\((?P<type>byte|u?char|undefined\d+|u?int\d*|u?longlong)\s*\*\)'
    r'\(\s*_?(?:DAT|UNK)_[0-9A-Fa-f]{6,}\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)[uUlL]*\s*\)'
)

_TYPE_WIDTH = {
    'undefined1': 1, 'byte': 1, 'char': 1, 'uchar': 1, 'undefined': 1, 'bool': 1,
    'undefined2': 2, 'short': 2, 'ushort': 2,
    'undefined4': 4, 'int': 4, 'uint': 4,
    'undefined8': 8, 'longlong': 8, 'ulonglong': 8,
}


def _type_width(kind: str, default: int=8) -> int:
    lowered = str(kind or '').lower()
    match = re.search(r'(?:undefined|u?int)(\d+)$', lowered)
    if match:
        return max(1, int(match.group(1)))
    if lowered in {'byte', 'char', 'uchar'}:
        return 1
    if lowered in {'short', 'ushort'}:
        return 2
    if lowered in {'int', 'uint', 'float'}:
        return 4
    if lowered in {'longlong', 'ulonglong', 'double'}:
        return 8
    return default


def _split_args(raw: str) -> Optional[Tuple[str, str]]:
    depth = 0
    for index, char in enumerate(raw):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ',' and depth == 0:
            return raw[:index], raw[index + 1:]
    return None


def _replace_concats(expr: str, values: Dict[str, int], read_u64_at_va: ReadU64, keystream: Optional[bytes]=None) -> str:
    while True:
        match = _CONCAT_RE.search(expr)
        if not match:
            return expr
        depth = 1
        index = match.end()
        while index < len(expr) and depth:
            if expr[index] == '(':
                depth += 1
            elif expr[index] == ')':
                depth -= 1
            index += 1
        if depth:
            return expr
        pair = _split_args(expr[match.end():index - 1])
        if pair is None:
            return expr
        high = _eval_expr(pair[0], values, read_u64_at_va, keystream)
        low = _eval_expr(pair[1], values, read_u64_at_va, keystream)
        if high is None or low is None:
            return expr
        high_width = int(match.group('hi'))
        low_width = int(match.group('lo'))
        value = ((high & ((1 << (high_width * 8)) - 1)) << (low_width * 8)) | (
            low & ((1 << (low_width * 8)) - 1)
        )
        expr = expr[:match.start()] + str(value) + expr[index:]


def _safe_int_eval(expr: str) -> Optional[int]:
    try:
        tree = ast.parse(expr, mode='eval')
    except SyntaxError:
        return None
    allowed = (
        ast.Expression, ast.Constant, ast.UnaryOp, ast.BinOp,
        ast.Add, ast.Sub, ast.BitXor, ast.BitOr, ast.BitAnd,
        ast.LShift, ast.RShift, ast.Invert, ast.USub, ast.UAdd,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        return None
    try:
        value = eval(compile(tree, '<jnic-expression>', 'eval'), {'__builtins__': {}}, {})
    except Exception:
        return None
    return value if isinstance(value, int) else None


def _eval_expr(expr: str, values: Dict[str, int], read_u64_at_va: ReadU64, keystream: Optional[bytes]=None) -> Optional[int]:
    value_expr = expr.strip()
    wide_global = _WIDE_GLOBAL_INDEX_RE.fullmatch(value_expr)
    if wide_global:
        raw = read_u64_at_va(int(wide_global.group(1), 16) + int(wide_global.group(2)) * 2)
        return (raw & 0xffff) if isinstance(raw, int) else None
    value_expr = re.sub(r"'\\0'", '0', value_expr)
    value_expr = re.sub(r"'(.)'", lambda m: str(ord(m.group(1))), value_expr)
    def keystream_repl(match: re.Match[str]) -> str:
        if not isinstance(keystream, (bytes, bytearray)):
            return match.group(0)
        offset = int(match.group('offset'), 16 if match.group('offset').lower().startswith('0x') else 10)
        kind = match.group('type').lower()
        width = _type_width(kind, 4)
        if offset < 0 or offset + width > len(keystream):
            return match.group(0)
        return str(int.from_bytes(keystream[offset:offset + width], 'little'))

    value_expr = _KEYSTREAM_LOAD_RE.sub(keystream_repl, value_expr)
    value_expr = _CAST_RE.sub('', value_expr)
    value_expr = re.sub(r'\b(?:uint\d*|int\d*)\b', '', value_expr)
    value_expr = _replace_concats(value_expr, values, read_u64_at_va, keystream)

    def global_repl(match: re.Match[str]) -> str:
        raw = read_u64_at_va(int(match.group(1), 16))
        return str(raw if isinstance(raw, int) else 0)

    value_expr = _GLOBAL_RE.sub(global_repl, value_expr)

    def token_repl(match: re.Match[str]) -> str:
        token = match.group(1)
        return str(values[token]) if token in values else token

    value_expr = _TOKEN_RE.sub(token_repl, value_expr)
    value_expr = re.sub(r'(?<=\d)[uUlL]+\b', '', value_expr)
    return _safe_int_eval(value_expr)


def _stack_offset(name: str) -> Optional[int]:
    match = _STACK_RE.match(name)
    return int(match.group(1), 16) if match else None


def _decode_stack_string(
    base_name: str,
    values: Dict[str, int],
    widths: Dict[str, int],
    partials: Dict[str, bytearray],
    wide: bool=False,
    tail_specs: Optional[Dict[str, List[Tuple[int, int, int]]]]=None,
    keystream: Optional[bytes]=None,
    require_terminator: bool=True,
    byte_offset: int=0,
) -> Optional[str]:
    base = _stack_offset(base_name)
    if base is not None:
        base -= max(0, byte_offset)
    if base is None:
        return None
    memory: Dict[int, int] = {}
    for name, value in values.items():
        offset = _stack_offset(name)
        width = widths.get(name)
        if offset is None or not isinstance(width, int):
            continue
        relative = base - offset
        raw = bytes(partials.get(name) or int(value & ((1 << (width * 8)) - 1)).to_bytes(width, 'little'))
        if relative > 512 or relative + len(raw) <= 0:
            continue
        for index, byte in enumerate(raw):
            position = relative + index
            if 0 <= position <= 512:
                memory[position] = byte
    normalized_base = base_name.lstrip('_')
    if isinstance(keystream, (bytes, bytearray)) and isinstance(tail_specs, dict):
        for start, key_offset, end in tail_specs.get(normalized_base, []):
            if start < 0 or end <= start:
                continue
            for relative in range(start, end):
                if relative in memory and key_offset + relative < len(keystream):
                    memory[relative] ^= keystream[key_offset + relative]
    data = bytearray()
    terminated = False
    for index in range(512):
        byte = memory.get(index)
        if byte is None:
            break
        if not wide and byte == 0:
            terminated = True
            break
        data.append(byte)
        if wide and len(data) >= 2 and len(data) % 2 == 0 and data[-2:] == b'\x00\x00':
            data = data[:-2]
            terminated = True
            break
    if not data or (require_terminator and not terminated):
        return None
    if wide:
        try:
            text = bytes(data[:len(data) - len(data) % 2]).decode('utf-16le')
        except UnicodeDecodeError:
            return None
        return text if text and all(ch.isprintable() or ch in '\r\n\t' for ch in text) else None
    for encoding in ('utf-8', 'ascii'):
        try:
            text = bytes(data).decode(encoding)
        except UnicodeDecodeError:
            continue
        if text and all(ch.isprintable() or ch in '\r\n\t' for ch in text):
            return text
    return None



def _tail_xor_specs(function_text: str) -> Dict[str, List[Tuple[int, int, int]]]:
    specs: Dict[str, List[Tuple[int, int, int]]] = {}
    for match in re.finditer(r'while\s*\(\s*(?P<iterator>[A-Za-z_]\w*)\s*!=\s*(?P<end>0x[0-9A-Fa-f]+|\d+)\s*\)', function_text):
        iterator = match.group('iterator')
        end = int(match.group('end'), 16 if match.group('end').lower().startswith('0x') else 10)
        window = function_text[max(0, match.start() - 1400):match.start()]
        bases = re.findall(rf'&(?P<base>_?(?:local|awStack|uStack|iStack|lStack)_[0-9A-Fa-f]+)\s*\+\s*{re.escape(iterator)}\b', window)
        if not bases:
            continue
        offsets = re.findall(rf'_?(?:DAT|UNK)_[0-9A-Fa-f]{{6,}}\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\+\s*{re.escape(iterator)}\b', window)
        offsets += re.findall(rf'\b{re.escape(iterator)}\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\+\s*_?(?:DAT|UNK)_[0-9A-Fa-f]{{6,}}', window)
        if not offsets:
            continue
        starts = re.findall(rf'\b{re.escape(iterator)}\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;', window)
        if not starts:
            continue
        nonzero = [value for value in starts if int(value, 16 if value.lower().startswith('0x') else 10) > 0]
        chosen_start = nonzero[-1] if nonzero else starts[-1]
        tail_start = int(chosen_start, 16 if chosen_start.lower().startswith('0x') else 10)
        offset_values = [int(value, 16 if value.lower().startswith('0x') else 10) for value in offsets]
        offset = min(offset_values)
        specs.setdefault(bases[-1].lstrip('_'), []).append((tail_start, offset, end))
    return specs

def _function_ranges(text: str) -> Dict[str, Tuple[int, int]]:
    matches = list(_FUNC_RE.finditer(text))
    return {
        match.group('name'): (
            text.count('\n', 0, match.end()) + 1,
            text.count('\n', 0, matches[index + 1].start()) + 1 if index + 1 < len(matches) else text.count('\n') + 2,
        )
        for index, match in enumerate(matches)
    }



def _attach_call_symbol_aliases(calls: List[Dict[str, Any]], pseudo_c: str) -> None:
    by_function: Dict[str, List[Dict[str, Any]]] = {}
    for call in calls:
        function = call.get('function')
        if isinstance(function, str):
            by_function.setdefault(function, []).append(call)
    ranges = _function_ranges(pseudo_c)
    lines = pseudo_c.splitlines()
    simple = re.compile(r'^\s*(?P<dst>[A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?P<src>[A-Za-z_]\w*)\s*;\s*$')
    assigned = re.compile(r'^\s*(?P<dst>[A-Za-z_]\w*)\s*=')
    for function, function_calls in by_function.items():
        line_range = ranges.get(function)
        if line_range is None:
            continue
        aliases: Dict[str, str] = {}
        pending = sorted(function_calls, key=lambda item: int(item.get('line') or 0))
        call_index = 0
        start, end = line_range
        for line_number in range(start, min(end, len(lines) + 1)):
            line = lines[line_number - 1]
            match = simple.match(line)
            if match:
                source = match.group('src')
                seen = {match.group('dst')}
                while source in aliases and source not in seen:
                    seen.add(source)
                    source = aliases[source]
                aliases[match.group('dst')] = source
            else:
                match = assigned.match(line)
                if match:
                    aliases.pop(match.group('dst'), None)
            while call_index < len(pending) and int(pending[call_index].get('line') or 0) <= line_number:
                call = pending[call_index]
                resolved: Dict[str, str] = {}
                for raw in call.get('args') or []:
                    symbol = str(raw)
                    seen: set[str] = set()
                    while symbol in aliases and symbol not in seen:
                        seen.add(symbol)
                        symbol = aliases[symbol]
                    if symbol != str(raw):
                        resolved[str(raw)] = symbol
                if resolved:
                    call['_resolved_symbols'] = resolved
                call_index += 1

def enrich_jni_calls_with_local_strings(
    jni_calls: Optional[Dict[str, Any]],
    *,
    pseudo_c: Optional[str],
    read_u64_at_va: ReadU64,
    keystream: Optional[bytes]=None,
) -> Dict[str, Any]:
    if not isinstance(jni_calls, dict) or not isinstance(pseudo_c, str) or not pseudo_c:
        return jni_calls or {'status': 'SKIPPED'}
    calls = [dict(item) for item in jni_calls.get('calls') or [] if isinstance(item, dict)]
    by_function: Dict[str, List[Dict[str, Any]]] = {}
    for call in calls:
        function = call.get('function')
        if isinstance(function, str):
            by_function.setdefault(function, []).append(call)
    ranges = _function_ranges(pseudo_c)
    lines = pseudo_c.splitlines()
    resolved_total = 0
    for function, function_calls in by_function.items():
        line_range = ranges.get(function)
        if line_range is None:
            continue
        start, end = line_range
        pending = sorted(function_calls, key=lambda item: int(item.get('line') or 0))
        function_text = '\n'.join(lines[max(0, start - 1):max(0, end - 1)])
        tail_specs = _tail_xor_specs(function_text)
        values: Dict[str, int] = {}
        widths: Dict[str, int] = {}
        partials: Dict[str, bytearray] = {}
        array_element_widths: Dict[str, int] = {}
        call_index = 0
        pending_assignment = ''
        for line_number in range(start, min(end, len(lines) + 1)):
            line = lines[line_number - 1]
            declaration = _DECL_RE.match(line)
            if declaration:
                widths[declaration.group('name')] = _type_width(declaration.group('type'))
            array_declaration = _ARRAY_DECL_RE.match(line)
            if array_declaration:
                element_width = 2 if array_declaration.group('type') == 'wchar_t' else 1
                widths[array_declaration.group('name')] = int(array_declaration.group('count')) * element_width
                array_element_widths[array_declaration.group('name')] = element_width
            array_assignment = _ARRAY_ASSIGN_RE.match(line)
            if array_assignment:
                array_name = array_assignment.group('name')
                array_index = int(array_assignment.group('index'))
                array_value = _eval_expr(array_assignment.group('expr'), values, read_u64_at_va, keystream)
                if array_value is not None and array_name in widths:
                    array_width = widths[array_name]
                    raw = partials.setdefault(array_name, bytearray(int(values.get(array_name, 0)).to_bytes(array_width, 'little')))
                    element_width = array_element_widths.get(array_name, 1)
                    offset = array_index * element_width
                    if offset + element_width <= array_width:
                        mask = (1 << (element_width * 8)) - 1
                        raw[offset:offset + element_width] = int(array_value & mask).to_bytes(element_width, 'little')
                        values[array_name] = int.from_bytes(raw, 'little')
            assignment_line = line
            stripped = line.strip()
            if pending_assignment:
                pending_assignment += ' ' + stripped
                if ';' in stripped:
                    assignment_line = pending_assignment
                    pending_assignment = ''
                else:
                    assignment_line = ''
            elif re.match(r'^[A-Za-z_]\w*(?:\._\d+_\d+_)?\s*=.*$', stripped) and ';' not in stripped:
                pending_assignment = stripped
                assignment_line = ''
            assignment = _ASSIGN_RE.match(assignment_line)
            if assignment:
                name = assignment.group('name')
                value = _eval_expr(assignment.group('expr'), values, read_u64_at_va, keystream)
                if value is not None:
                    width = widths.get(name, 8)
                    widths.setdefault(name, width)
                    part_off = assignment.group('part_off')
                    part_size = assignment.group('part_size')
                    if part_off is not None and part_size is not None:
                        raw = partials.setdefault(name, bytearray(int(values.get(name, 0)).to_bytes(width, 'little')))
                        offset = int(part_off)
                        size = int(part_size)
                        raw[offset:offset + size] = int(value & ((1 << (size * 8)) - 1)).to_bytes(max(size, 1), 'little')[:size]
                        values[name] = int.from_bytes(raw, 'little')
                    else:
                        values[name] = value & ((1 << (width * 8)) - 1)
                        partials[name] = bytearray(values[name].to_bytes(width, 'little'))
            while call_index < len(pending) and int(pending[call_index].get('line') or 0) <= line_number:
                call = pending[call_index]
                resolved: Dict[str, str] = {}
                for arg_index, arg in enumerate(call.get('args') or []):
                    arg_text = str(arg)
                    allow_bare = ((call.get('jni_name') in {'NewString', 'NewStringUTF', 'FindClass'} and arg_index == 1) or (call.get('jni_name') in {'GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID'} and arg_index in {2, 3}))
                    prefix = r'&?_?' if allow_bare else r'&_?'
                    pattern = prefix + r'((?:local|[A-Za-z]+Stack)_[0-9A-Fa-f]+)(?:\s*\+\s*(0x[0-9A-Fa-f]+|\d+))?'
                    match = re.fullmatch(pattern, arg_text)
                    if not match:
                        continue
                    local_name = match.group(1)
                    if arg_text.startswith('&_'):
                        local_name = '_' + local_name
                    byte_offset = int(match.group(2), 16 if match.group(2) and match.group(2).lower().startswith('0x') else 10) if match.group(2) else 0
                    decoded = _decode_stack_string(
                        local_name,
                        values,
                        widths,
                        partials,
                        wide=call.get('jni_name') == 'NewString' and arg_index == 1,
                        tail_specs=tail_specs,
                        keystream=keystream,
                        require_terminator=call.get('jni_name') not in {'NewString', 'NewStringUTF'},
                        byte_offset=byte_offset,
                    )
                    if decoded is not None:
                        resolved[arg_text] = decoded
                if resolved:
                    call['resolved_strings'] = resolved
                    resolved_total += len(resolved)
                call_index += 1
    _attach_call_symbol_aliases(calls, pseudo_c)
    scoped_classes: Dict[Tuple[str, str], str] = {}
    global_classes: Dict[str, str] = {}
    id_results: Dict[str, Dict[str, Any]] = {}

    def remember_class(call: Dict[str, Any], symbol: str, class_name: str) -> None:
        function = str(call.get('function') or '')
        scoped_classes[(function, symbol)] = class_name
        if re.match(r'^_?(?:DAT|UNK)_[0-9A-Fa-f]+$', symbol):
            global_classes[symbol] = class_name

    def resolve_class(call: Dict[str, Any], symbol: str) -> Optional[str]:
        function = str(call.get('function') or '')
        return scoped_classes.get((function, symbol)) or global_classes.get(symbol)

    for call in calls:
        name = call.get('jni_name')
        args = [str(arg) for arg in call.get('args') or []]
        result = call.get('result_var')
        resolved = call.get('resolved_strings') if isinstance(call.get('resolved_strings'), dict) else {}
        existing = call.get('resolved') if isinstance(call.get('resolved'), dict) else {}
        if name == 'FindClass' and isinstance(result, str) and len(args) > 1:
            class_name = resolved.get(args[1])
            if isinstance(class_name, str):
                remember_class(call, result, class_name)
        elif name == 'NewGlobalRef' and isinstance(result, str) and len(args) > 1:
            class_name = resolve_class(call, args[1])
            if isinstance(class_name, str):
                remember_class(call, result, class_name)
        elif name in {'GetMethodID', 'GetStaticMethodID'} and isinstance(result, str) and len(args) > 3:
            method_name = resolved.get(args[2]) or existing.get('method')
            signature = resolved.get(args[3]) or existing.get('signature')
            if isinstance(method_name, str):
                id_results[result] = {
                    'kind': 'method',
                    'name': method_name,
                    'signature': signature,
                    'class': resolve_class(call, args[1]),
                    'static': name == 'GetStaticMethodID',
                }
        elif name in {'GetFieldID', 'GetStaticFieldID'} and isinstance(result, str) and len(args) > 3:
            field_name = resolved.get(args[2]) or existing.get('field')
            signature = resolved.get(args[3]) or existing.get('signature')
            if isinstance(field_name, str):
                id_results[result] = {
                    'kind': 'field',
                    'name': field_name,
                    'signature': signature,
                    'class': resolve_class(call, args[1]),
                    'static': name == 'GetStaticFieldID',
                }
    for call in calls:
        symbol_aliases = call.get('_resolved_symbols') if isinstance(call.get('_resolved_symbols'), dict) else {}
        linked = {
            str(arg): id_results[symbol_aliases.get(str(arg), str(arg))]
            for arg in call.get('args') or []
            if symbol_aliases.get(str(arg), str(arg)) in id_results
        }
        if linked:
            call['resolved_ids'] = linked
        class_consumers = {'NewGlobalRef', 'NewLocalRef', 'NewWeakGlobalRef', 'GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID', 'IsInstanceOf', 'NewObject', 'NewObjectA', 'NewObjectV', 'AllocObject', 'NewObjectArray'}
        linked_classes: Dict[str, str] = {}
        for arg in call.get('args') or []:
            raw = str(arg)
            symbol = symbol_aliases.get(raw, raw)
            class_name = global_classes.get(symbol)
            if class_name is None and call.get('jni_name') in class_consumers:
                class_name = resolve_class(call, symbol)
            if isinstance(class_name, str):
                linked_classes[raw] = class_name
        if linked_classes:
            call['resolved_classes'] = linked_classes
    for call in calls:
        call.pop('_resolved_symbols', None)
    updated = dict(jni_calls)
    updated['calls'] = calls
    updated['jnic_local_strings_resolved'] = resolved_total
    updated['jnic_ids_resolved'] = len(id_results)
    updated['jnic_classes_resolved'] = len(scoped_classes)
    return updated



def enrich_jni_calls_from_jar(jni_calls: Optional[Dict[str, Any]], *, jar_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(jni_calls, dict) or not isinstance(jar_meta, dict):
        return jni_calls or {'status': 'SKIPPED'}
    from detranspiler.java.jni_descriptors import _jni_descriptor_to_java_type, _jni_method_sig_to_java
    calls = [dict(item) for item in jni_calls.get('calls') or [] if isinstance(item, dict)]
    enriched = 0
    ids_inferred = 0
    field_ids_inferred = 0
    return_kinds = {'Object': 'reference', 'Boolean': 'boolean', 'Byte': 'byte', 'Char': 'char', 'Short': 'short', 'Int': 'int', 'Long': 'long', 'Float': 'float', 'Double': 'double', 'Void': 'void'}

    def java_return_kind(java_type: str) -> str:
        primitives = {'void', 'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'}
        return java_type if java_type in primitives else 'reference'

    for call in calls:
        call_name = str(call.get('jni_name') or '')
        kind_match = re.match(r'^CallStatic(Object|Boolean|Byte|Char|Short|Int|Long|Float|Double|Void)Method', call_name)
        if kind_match is None or isinstance(call.get('resolved_ids'), dict):
            continue
        args = [str(arg) for arg in call.get('args') or []]
        if len(args) < 3 or int(call.get('args_total') or len(args)) != len(args):
            continue
        id_symbol = args[2]
        if not re.fullmatch(r'_?(?:DAT|UNK)_[0-9A-Fa-f]+', id_symbol):
            continue
        classes = call.get('resolved_classes') if isinstance(call.get('resolved_classes'), dict) else {}
        owner = classes.get(args[1])
        class_meta = jar_meta.get(owner) if isinstance(owner, str) else None
        methods = class_meta.get('methods') if isinstance(class_meta, dict) else None
        if not isinstance(methods, dict):
            continue
        expected_kind = return_kinds[kind_match.group(1)]
        candidates: List[Tuple[str, str]] = []
        for key, flags in methods.items():
            if not (isinstance(key, tuple) and len(key) == 2 and isinstance(flags, int) and flags & 0x0008):
                continue
            method_name, descriptor = key
            parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
            if parsed is None or len(parsed[1]) != len(args) - 3 or java_return_kind(parsed[0]) != expected_kind:
                continue
            candidates.append((method_name, descriptor))
        if len(candidates) == 1:
            method_name, descriptor = candidates[0]
            call['resolved_ids'] = {id_symbol: {'kind': 'method', 'name': method_name, 'signature': descriptor, 'class': owner, 'static': True, 'source': 'jar_shape'}}
            ids_inferred += 1

    scoped_types: Dict[Tuple[str, str], str] = {}
    for _pass in range(3):
        changed = False
        for call in calls:
            function = str(call.get('function') or '')
            call_name = str(call.get('jni_name') or '')
            args = [str(arg) for arg in call.get('args') or []]
            classes = dict(call.get('resolved_classes') or {}) if isinstance(call.get('resolved_classes'), dict) else {}
            if len(args) > 1 and (function, args[1]) in scoped_types:
                classes.setdefault(args[1], scoped_types[(function, args[1])])
                call['resolved_classes'] = classes
            linked = call.get('resolved_ids') if isinstance(call.get('resolved_ids'), dict) else {}
            kind_match = re.match(r'^Call(Object|Boolean|Byte|Char|Short|Int|Long|Float|Double|Void)Method', call_name)
            nonvirtual_match = re.match(r'^CallNonvirtual(Object|Boolean|Byte|Char|Short|Int|Long|Float|Double|Void)Method', call_name)
            if not linked and (kind_match or nonvirtual_match) and int(call.get('args_total') or len(args)) == len(args):
                nonvirtual = nonvirtual_match is not None
                method_index = 3 if nonvirtual else 2
                argument_index = method_index + 1
                if len(args) > method_index:
                    owner = classes.get(args[2]) if nonvirtual and len(args) > 2 else classes.get(args[1]) if len(args) > 1 else None
                    id_symbol = args[method_index]
                    class_meta = jar_meta.get(owner) if isinstance(owner, str) else None
                    methods = class_meta.get('methods') if isinstance(class_meta, dict) else None
                    expected_kind = return_kinds[(nonvirtual_match or kind_match).group(1)]
                    candidates: List[Tuple[str, str]] = []
                    if isinstance(methods, dict) and re.fullmatch(r'_?(?:DAT|UNK)_[0-9A-Fa-f]+', id_symbol):
                        for key, flags in methods.items():
                            if not (isinstance(key, tuple) and len(key) == 2 and isinstance(flags, int) and not (flags & 0x0008)):
                                continue
                            method_name, descriptor = key
                            parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
                            if parsed is None or len(parsed[1]) != len(args) - argument_index or java_return_kind(parsed[0]) != expected_kind:
                                continue
                            if nonvirtual and method_name != '<init>':
                                continue
                            candidates.append((method_name, descriptor))
                    if len(candidates) == 1:
                        method_name, descriptor = candidates[0]
                        linked = {id_symbol: {'kind': 'method', 'name': method_name, 'signature': descriptor, 'class': owner, 'static': False, 'source': 'jar_shape'}}
                        call['resolved_ids'] = linked
                        ids_inferred += 1
                        changed = True
            field_match = re.match(r'^(Get|Set)(Static)?(Object|Boolean|Byte|Char|Short|Int|Long|Float|Double)Field$', call_name)
            if not linked and field_match and len(args) > 2:
                is_static_field = field_match.group(2) == 'Static'
                owner = classes.get(args[1])
                id_symbol = args[2]
                class_meta = jar_meta.get(owner) if isinstance(owner, str) else None
                fields = class_meta.get('fields') if isinstance(class_meta, dict) else None
                expected_kind = return_kinds[field_match.group(3)]
                candidates: List[Tuple[str, str]] = []
                if isinstance(fields, dict) and re.fullmatch(r'_?(?:DAT|UNK)_[0-9A-Fa-f]+', id_symbol):
                    for key, flags in fields.items():
                        if not (isinstance(key, tuple) and len(key) == 2 and isinstance(flags, int) and bool(flags & 0x0008) == is_static_field):
                            continue
                        field_name, descriptor = key
                        parsed_field = _jni_descriptor_to_java_type(descriptor) if isinstance(descriptor, str) else None
                        if parsed_field is None:
                            continue
                        field_type, array_dim = parsed_field
                        field_kind = 'reference' if array_dim > 0 or field_type not in {'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'} else field_type
                        if field_kind == expected_kind:
                            candidates.append((field_name, descriptor))
                if len(candidates) == 1:
                    field_name, descriptor = candidates[0]
                    linked = {id_symbol: {'kind': 'field', 'name': field_name, 'signature': descriptor, 'class': owner, 'static': is_static_field, 'source': 'jar_shape'}}
                    call['resolved_ids'] = linked
                    field_ids_inferred += 1
                    changed = True

            result = call.get('result_var')
            if isinstance(result, str):
                result_type = None
                if call_name in {'NewObject', 'NewObjectA', 'NewObjectV', 'AllocObject'} and len(args) > 1:
                    result_type = classes.get(args[1])
                elif 'ObjectMethod' in call_name and linked:
                    info = next((item for item in linked.values() if isinstance(item, dict) and isinstance(item.get('signature'), str)), None)
                    return_desc = info['signature'].split(')', 1)[1] if isinstance(info, dict) and ')' in info['signature'] else ''
                    if return_desc.startswith('L') and return_desc.endswith(';'):
                        result_type = return_desc[1:-1]
                elif call_name in {'GetObjectField', 'GetStaticObjectField'} and linked:
                    info = next((item for item in linked.values() if isinstance(item, dict) and isinstance(item.get('signature'), str)), None)
                    field_desc = info.get('signature') if isinstance(info, dict) else ''
                    if isinstance(field_desc, str) and field_desc.startswith('L') and field_desc.endswith(';'):
                        result_type = field_desc[1:-1]
                if isinstance(result_type, str) and scoped_types.get((function, result)) != result_type:
                    scoped_types[(function, result)] = result_type
                    changed = True
        if not changed:
            break

    for call in calls:
        linked = call.get('resolved_ids')
        if not isinstance(linked, dict) or 'Method' not in str(call.get('jni_name') or ''):
            continue
        nonvirtual = str(call.get('jni_name') or '').startswith('CallNonvirtual')
        method_index = 3 if nonvirtual else 2
        argument_index = method_index + 1
        actual_count = max(0, len(call.get('args') or []) - argument_index)
        updated_ids: Dict[str, Dict[str, Any]] = {}
        for symbol, original in linked.items():
            info = dict(original) if isinstance(original, dict) else {}
            if info.get('signature'):
                updated_ids[symbol] = info
                continue
            owner = info.get('class')
            name = info.get('name')
            class_meta = jar_meta.get(owner) if isinstance(owner, str) else None
            methods = class_meta.get('methods') if isinstance(class_meta, dict) else None
            candidates: List[str] = []
            if isinstance(methods, dict) and isinstance(name, str):
                for key, flags in methods.items():
                    if not (isinstance(key, tuple) and len(key) == 2 and key[0] == name and isinstance(flags, int)):
                        continue
                    descriptor = key[1]
                    parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
                    if parsed is None or len(parsed[1]) != actual_count:
                        continue
                    if bool(flags & 0x0008) != bool(info.get('static')):
                        continue
                    candidates.append(descriptor)
            if len(candidates) == 1:
                info['signature'] = candidates[0]
                enriched += 1
            updated_ids[symbol] = info
        call['resolved_ids'] = updated_ids
    updated = dict(jni_calls)
    updated['calls'] = calls
    updated['jnic_jar_descriptors_resolved'] = enriched
    updated['jnic_jar_method_ids_resolved'] = ids_inferred
    updated['jnic_jar_field_ids_resolved'] = field_ids_inferred
    return updated

__all__ = ['enrich_jni_calls_with_local_strings', 'enrich_jni_calls_from_jar']
