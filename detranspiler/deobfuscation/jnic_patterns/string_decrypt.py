from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional

from detranspiler.binary.reader import BinaryReader
from detranspiler.deobfuscation.jnic_patterns.switch_dispatch import dispatch_table, function_blocks, switch_cases, target_for_case

_MASK = b'\x00\x00\x00\x00\xff\xff\xff\xff'


def _registered_decryptors(jni_register: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for call in jni_register.get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        for method in call.get('methods') or []:
            if not isinstance(method, dict):
                continue
            descriptor = method.get('signature') or method.get('descriptor')
            symbol = method.get('fn_symbol')
            parameter_count = 3 if descriptor == '(III)Ljava/lang/String;' else 2 if descriptor == '(II)Ljava/lang/String;' else None
            if isinstance(symbol, str) and isinstance(parameter_count, int):
                out[symbol] = parameter_count
    return out


def _register(rex: int, value: int, extension_bit: int) -> int:
    return value + (((rex >> extension_bit) & 1) << 3)


def _case_key(target: int, data: bytes, reader: BinaryReader) -> Optional[int]:
    offset = reader.va_to_offset(target)
    if offset is None:
        return None
    raw = data[offset:offset + 128]
    mask_at = raw.find(_MASK)
    if mask_at < 2:
        return None
    mov_rex = raw[mask_at - 2]
    mov_opcode = raw[mask_at - 1]
    if mov_rex & 0xf8 != 0x48 or not 0xb8 <= mov_opcode <= 0xbf:
        return None
    mask_register = _register(mov_rex, mov_opcode - 0xb8, 0)
    value_register: Optional[int] = None
    cursor = mask_at + len(_MASK)
    for index in range(cursor, min(cursor + 12, len(raw) - 2)):
        rex, opcode, modrm = raw[index:index + 3]
        if rex & 0xf8 != 0x48 or opcode not in {0x21, 0x23} or modrm >> 6 != 3:
            continue
        reg = _register(rex, (modrm >> 3) & 7, 2)
        rm = _register(rex, modrm & 7, 0)
        if opcode == 0x21 and reg == mask_register:
            value_register = rm
        elif opcode == 0x23 and rm == mask_register:
            value_register = reg
        if value_register is not None:
            cursor = index + 3
            break
    if value_register is None:
        return None
    for index in range(cursor, min(cursor + 16, len(raw) - 7)):
        rex, opcode, modrm = raw[index:index + 3]
        if rex & 0xf8 != 0x48 or opcode not in {0x81, 0x83} or modrm >> 6 != 3 or (modrm >> 3) & 7 != 1:
            continue
        if _register(rex, modrm & 7, 0) != value_register:
            continue
        value = raw[index + 3] if opcode == 0x83 else int.from_bytes(raw[index + 3:index + 7], 'little')
        return value if 0 < value <= 255 else None
    return 0


def _index_xor(symbol: str, data: bytes, reader: BinaryReader) -> Optional[int]:
    try:
        address = int(symbol.removeprefix('FUN_'), 16)
    except ValueError:
        return None
    offset = reader.va_to_offset(address)
    if offset is None:
        return None
    raw = data[offset:offset + 160]
    marker = b'\x41\x0f\xb7\xc0'
    start = raw.find(marker)
    if start < 0:
        return None
    for index in range(start + len(marker), min(start + len(marker) + 16, len(raw) - 6)):
        if raw[index] == 0x35:
            value = int.from_bytes(raw[index + 1:index + 5], 'little')
        elif raw[index:index + 2] == b'\x81\xf0':
            value = int.from_bytes(raw[index + 2:index + 6], 'little')
        elif raw[index:index + 2] == b'\x83\xf0':
            value = raw[index + 2]
        else:
            continue
        return value if 0 <= value <= 0xffff else None
    return None


def _algorithm_shape(block: str) -> bool:
    return all(re.search(pattern, block) for pattern in (r'<<\s*5', r'>>\s*3', r'&\s*0xff', r'\+\s*0x100'))


def extract_string_decrypt_models(*, pseudo_c: str, binary_path: Path, keystream: bytes, jni_register: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    if not pseudo_c or not binary_path.is_file() or not keystream or not isinstance(jni_register, dict):
        return {}
    data = binary_path.read_bytes()
    reader = BinaryReader(data)
    blocks = function_blocks(pseudo_c)
    models: Dict[str, Dict[str, Any]] = {}
    for symbol, parameter_count in _registered_decryptors(jni_register).items():
        block = blocks.get(symbol)
        if not isinstance(block, str) or not _algorithm_shape(block):
            continue
        cases = switch_cases(block, 256)
        table = dispatch_table(block)
        index_xor = _index_xor(symbol, data, reader)
        if cases is None or table is None or index_xor is None:
            continue
        keys: Dict[int, int] = {}
        valid = True
        for case, body in cases.items():
            target = target_for_case(body, keystream, data, reader, table)
            key = _case_key(target, data, reader) if target is not None else None
            if key is None:
                valid = False
                break
            keys[case] = key
        if not valid or set(keys) != set(range(256)) or set(keys.values()) != set(range(256)):
            continue
        models[symbol] = {
            'index_xor': index_xor,
            'key_table': [keys[index] for index in range(256)],
            'parameter_count': parameter_count,
        }
    return models


__all__ = ['extract_string_decrypt_models']