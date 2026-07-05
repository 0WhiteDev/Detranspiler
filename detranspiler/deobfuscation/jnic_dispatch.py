from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from detranspiler.binary.reader import BinaryReader

_DISPATCH_RE = re.compile(
    r'&DAT_(?P<base>[0-9A-Fa-f]+)\s*\+\s*\*\(int\s*\*\)\(&DAT_(?P=base)\s*\+'
    r'\s*\(ulonglong\)\s*\(\(\*\(uint\s*\*\)\(DAT_[0-9A-Fa-f]+\s*\+\s*'
    r'(?P<offset>0x[0-9A-Fa-f]+|\d+)\)\s*\^\s*(?P<key>0x[0-9A-Fa-f]+)\)'
    r'\s*\+\s*(?P<shift>0x[0-9A-Fa-f]+|\d+)\)\s*\*\s*4\)',
    re.DOTALL,
)
_RELATIVE_DISPATCH_RE = re.compile(
    r'\*\(int\s*\*\)\(\s*(?P<base>[A-Za-z_]\w*)\s*\+'
    r'\s*\(ulonglong\)\s*\(\(\*\(uint\s*\*\)\((?:DAT_[0-9A-Fa-f]+|[A-Za-z_]\w*)\s*\+'
    r'\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\)\s*\^\s*(?P<key>0x[0-9A-Fa-f]+)\)'
    r'\s*\+\s*(?P<shift>0x[0-9A-Fa-f]+|\d+)\)\s*\*\s*4\)\s*\+\s*(?P=base)',
    re.DOTALL,
)
_MARKER_RE = re.compile(r'^\s*/\* FUNCTION (?P<name>\S+)\s+[0-9A-Fa-f]+\s+\*/', re.MULTILINE)


def _blocks(text: str) -> Dict[str, str]:
    matches = list(_MARKER_RE.finditer(text))
    return {
        match.group('name'): text[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        for index, match in enumerate(matches)
    }


def resolve_jnic_dispatch_targets(*, pseudo_c: str, binary_path: Path, keystream: bytes, jni_register: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not pseudo_c or not binary_path.is_file() or not keystream or not isinstance(jni_register, dict):
        return []
    data = binary_path.read_bytes()
    reader = BinaryReader(data)
    by_name = _blocks(pseudo_c)
    symbols = {
        method.get('fn_symbol')
        for call in jni_register.get('register_calls') or [] if isinstance(call, dict)
        for method in call.get('methods') or [] if isinstance(method, dict) and isinstance(method.get('fn_symbol'), str)
    }
    out: List[Dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for symbol in sorted(symbols):
        block = by_name.get(symbol, '')
        direct_matches = list(_DISPATCH_RE.finditer(block))
        candidates = [(match, int(match.group('base'), 16), 'absolute') for match in direct_matches]
        tables = {table for _match, table, _kind in candidates}
        if len(tables) == 1:
            table = next(iter(tables))
            candidates.extend((match, table, 'relative') for match in _RELATIVE_DISPATCH_RE.finditer(block))
        for match, table, dispatch_kind in candidates:
            offset = int(match.group('offset'), 0)
            if offset < 0 or offset + 4 > len(keystream):
                continue
            selector = ((int.from_bytes(keystream[offset:offset + 4], 'little') ^ int(match.group('key'), 16)) + int(match.group('shift'), 0)) & 0xffffffff
            entry_offset = reader.va_to_offset(table + selector * 4)
            if entry_offset is None or entry_offset + 4 > len(data):
                continue
            target = table + struct.unpack_from('<i', data, entry_offset)[0]
            key = (symbol, target)
            if reader.va_to_offset(target) is None or key in seen:
                continue
            seen.add(key)
            out.append({'function': symbol, 'target': f'{target:x}', 'selector': selector, 'keystream_offset': offset, 'table': f'{table:x}', 'dispatch_kind': dispatch_kind})
    return out


def write_dispatch_targets(path: Path, targets: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{item['function']} {item['target']}" for item in targets]
    path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='ascii')


def merge_dispatch_pseudoc(original: str, recovered: str) -> str:
    additions: Dict[str, List[str]] = {}
    for name, block in _blocks(recovered).items():
        base = name.split('__cff_', 1)[0]
        marker = _MARKER_RE.search(block)
        payload = block[marker.end():] if marker is not None else block
        additions.setdefault(base, []).append(payload.strip())
    if not additions:
        return original
    matches = list(_MARKER_RE.finditer(original))
    parts: List[str] = []
    cursor = 0
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(original)
        block = original[match.start():end].rstrip()
        extra = additions.get(match.group('name'))
        parts.append(original[cursor:match.start()])
        if extra:
            block += '\n\n' + '\n\n'.join(extra)
        parts.append(block + '\n\n')
        cursor = end
    parts.append(original[cursor:])
    return ''.join(parts)


__all__ = ['resolve_jnic_dispatch_targets', 'write_dispatch_targets', 'merge_dispatch_pseudoc']
