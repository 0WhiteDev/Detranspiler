from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional, Tuple

from detranspiler.binary.reader import BinaryReader

_FUNCTION_RE = re.compile(r'^\s*/\* FUNCTION (?P<name>\S+)\s+[0-9A-Fa-f]+\s+\*/', re.MULTILINE)
_SWITCH_RE = re.compile(r'\bswitch\s*\(')
_CASE_RE = re.compile(r'(?m)^\s*(?:case\s+(?P<case>0x[0-9A-Fa-f]+|\d+)|(?P<default>default))\s*:')
_SELECTOR_RE = re.compile(
    r'\*\(uint\s*\*\)\(\s*(?:DAT_[0-9A-Fa-f]+|[A-Za-z_]\w*)\s*\+\s*'
    r'(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\)\s*\^\s*(?P<key>0x[0-9A-Fa-f]+)\s*\)'
    r'\s*\+\s*(?P<shift>0x[0-9A-Fa-f]+|\d+)'
)
_TABLE_RE = re.compile(r'&DAT_(?P<base>[0-9A-Fa-f]+)\s*\+\s*\*\(int\s*\*\)\(\s*&DAT_(?P=base)\s*\+')
_RELATIVE_RE = re.compile(
    r'\*\(int\s*\*\)\(\s*(?P<base>[A-Za-z_]\w*)\s*\+'
    r'\s*\(ulonglong\)\s*\(\(\*\(uint\s*\*\)\((?:DAT_[0-9A-Fa-f]+|[A-Za-z_]\w*)\s*\+'
    r'\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\)\s*\^\s*(?P<key>0x[0-9A-Fa-f]+)\)'
    r'\s*\+\s*(?P<shift>0x[0-9A-Fa-f]+|\d+)\)\s*\*\s*4\)\s*\+\s*(?P=base)',
    re.DOTALL,
)
_PREFIX_RELATIVE_RE = re.compile(
    r'(?P<base>[A-Za-z_]\w*)\s*\+\s*\*\(int\s*\*\)\(\s*(?P=base)\s*\+'
    r'\s*\(ulonglong\)\s*\(\(\*\(uint\s*\*\)\((?:DAT_[0-9A-Fa-f]+|[A-Za-z_]\w*)\s*\+'
    r'\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\)\s*\^\s*(?P<key>0x[0-9A-Fa-f]+)\)'
    r'\s*\+\s*(?P<shift>0x[0-9A-Fa-f]+|\d+)\)\s*\*\s*4\)',
    re.DOTALL,
)


def function_blocks(text: str) -> Dict[str, str]:
    matches = list(_FUNCTION_RE.finditer(text))
    return {
        match.group('name'): text[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        for index, match in enumerate(matches)
    }


def _brace_end(text: str, start: int) -> Optional[int]:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return index
    return None


def switch_cases(block: str, size: int) -> Optional[Dict[int, str]]:
    candidates: List[Tuple[int, Dict[int, str]]] = []
    for switch in _SWITCH_RE.finditer(block):
        start = block.find('{', switch.start())
        end = _brace_end(block, start)
        if end is None:
            continue
        region = block[start + 1:end]
        labels = list(_CASE_RE.finditer(region))
        cases: Dict[int, str] = {}
        for index, label in enumerate(labels):
            value = size - 1 if label.group('default') else int(label.group('case'), 0)
            body_end = labels[index + 1].start() if index + 1 < len(labels) else len(region)
            cases[value] = region[label.end():body_end]
        candidates.append((len(cases), cases))
    if not candidates:
        return None
    count, cases = max(candidates, key=lambda item: item[0])
    return cases if count == size and set(cases) == set(range(size)) else None


def dispatch_table(block: str) -> Optional[int]:
    values = {int(match.group('base'), 16) for match in _TABLE_RE.finditer(block)}
    return next(iter(values)) if len(values) == 1 else None


def target_for_case(body: str, keystream: bytes, data: bytes, reader: BinaryReader, table: Optional[int]) -> Optional[int]:
    selectors = {
        (match.group('offset'), match.group('key'), match.group('shift'))
        for match in _SELECTOR_RE.finditer(body)
    }
    tables = {int(match.group('base'), 16) for match in _TABLE_RE.finditer(body)}
    if not tables and table is not None and any(pattern.search(body) for pattern in (_RELATIVE_RE, _PREFIX_RELATIVE_RE)):
        tables.add(table)
    if len(selectors) != 1 or len(tables) != 1:
        return None
    offset_text, key_text, shift_text = next(iter(selectors))
    table_address = next(iter(tables))
    offset = int(offset_text, 0)
    if offset < 0 or offset + 4 > len(keystream):
        return None
    selector = ((int.from_bytes(keystream[offset:offset + 4], 'little') ^ int(key_text, 16)) + int(shift_text, 0)) & 0xffffffff
    entry_offset = reader.va_to_offset(table_address + selector * 4)
    if entry_offset is None or entry_offset + 4 > len(data):
        return None
    target = table_address + struct.unpack_from('<i', data, entry_offset)[0]
    return target if reader.va_to_offset(target) is not None else None

__all__ = ['dispatch_table', 'function_blocks', 'switch_cases', 'target_for_case']
