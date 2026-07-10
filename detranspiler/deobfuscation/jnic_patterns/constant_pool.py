from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from detranspiler.binary.reader import BinaryReader
from detranspiler.deobfuscation.jnic_patterns.switch_dispatch import dispatch_table, function_blocks, switch_cases, target_for_case

_REGISTER = r'(?:E(?:AX|BX|CX|DX|BP|SP|SI|DI)|R(?:8|9|1[0-5])D)'
_MOV_RE = re.compile(rf'^MOV\s+(?P<register>{_REGISTER}),(?P<value>-?0x[0-9a-f]+|-?\d+)$', re.IGNORECASE)
_XOR_RE = re.compile(rf'^XOR\s+(?P<left>{_REGISTER}),(?P<right>{_REGISTER})$', re.IGNORECASE)
_ABSOLUTE_MEMORY_RE = re.compile(r'\[(?:0x)?(?P<address>[0-9a-f]{8,16})\]', re.IGNORECASE)


def _registered_decoders(jni_register: Dict[str, Any]) -> List[str]:
    return [
        str(method['fn_symbol'])
        for call in jni_register.get('register_calls') or []
        if isinstance(call, dict)
        for method in call.get('methods') or []
        if isinstance(method, dict)
        and (method.get('signature') or method.get('descriptor')) == '(JJ)I'
        and isinstance(method.get('fn_symbol'), str)
    ]


def _instruction_index(path: Optional[Path]) -> Dict[int, List[Dict[str, Any]]]:
    if path is None or not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}
    functions = document.get('functions') if isinstance(document, dict) else document
    out: Dict[int, List[Dict[str, Any]]] = {}
    for function in functions or []:
        if not isinstance(function, dict):
            continue
        try:
            entry = int(str(function.get('entry')), 16)
        except (TypeError, ValueError):
            continue
        instructions = function.get('instructions')
        if isinstance(instructions, list):
            out[entry] = [item for item in instructions if isinstance(item, dict)]
    return out


def _small_values(instructions: List[Dict[str, Any]]) -> Dict[str, Set[int]]:
    values: Dict[str, Set[int]] = {}
    for instruction in instructions:
        if instruction.get('mnemonic') == 'CALL':
            break
        text = str(instruction.get('text') or '')
        move = _MOV_RE.fullmatch(text)
        if move is not None:
            value = int(move.group('value'), 0)
            if 0 <= value < 64:
                values.setdefault(move.group('register').upper(), set()).add(value)
            continue
        xor = _XOR_RE.fullmatch(text)
        if xor is not None and xor.group('left').upper() == xor.group('right').upper():
            values.setdefault(xor.group('left').upper(), set()).add(0)
    return values


def _key_table(cases: Dict[int, str], table: int, keystream: bytes, data: bytes, reader: BinaryReader, instructions: Dict[int, List[Dict[str, Any]]]) -> Optional[List[int]]:
    candidates: Dict[int, Dict[str, Set[int]]] = {}
    for case, body in cases.items():
        target = target_for_case(body, keystream, data, reader, table)
        if target is None or target not in instructions:
            return None
        candidates[case] = _small_values(instructions[target])
    registers = set.intersection(*(set(item) for item in candidates.values())) if candidates else set()
    tables: List[List[int]] = []
    for register in registers:
        if any(len(candidates[index][register]) != 1 for index in range(64)):
            continue
        values = [next(iter(candidates[index][register])) for index in range(64)]
        if set(values) == set(range(64)):
            tables.append(values)
    return tables[0] if len(tables) == 1 else None


def _algorithm_shape(symbol: str, table: int, instructions: Dict[int, List[Dict[str, Any]]]) -> bool:
    try:
        start = int(symbol.removeprefix('FUN_'), 16)
    except ValueError:
        return False
    texts = [
        str(instruction.get('text') or '')
        for entry, items in instructions.items()
        if start <= entry < table
        for instruction in items
    ]
    patterns = (r'^SHL\s+\w+,0x30$', r'^SHR\s+\w+,0x2a$', r'^SHR\s+\w+,0x2e$', r'^AND\s+\w+,0x3f$')
    return all(any(re.fullmatch(pattern, text, re.IGNORECASE) for text in texts) for pattern in patterns)


def _absolute_addresses(symbol: str, table: int, instructions: Dict[int, List[Dict[str, Any]]]) -> List[str]:
    try:
        start = int(symbol.removeprefix('FUN_'), 16)
    except ValueError:
        return []
    return sorted({
        match.group('address').lower()
        for entry, items in instructions.items()
        if start <= entry < table
        for instruction in items
        for match in _ABSOLUTE_MEMORY_RE.finditer(str(instruction.get('text') or ''))
    })
def extract_constant_pool_models(*, pseudo_c: str, binary_path: Path, keystream: bytes, jni_register: Dict[str, Any], functions_json_path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if not pseudo_c or not binary_path.is_file() or not keystream or not isinstance(jni_register, dict):
        return {}
    data = binary_path.read_bytes()
    reader = BinaryReader(data)
    blocks = function_blocks(pseudo_c)
    instructions = _instruction_index(functions_json_path)
    models: Dict[str, Dict[str, Any]] = {}
    for symbol in _registered_decoders(jni_register):
        block = blocks.get(symbol)
        if not isinstance(block, str):
            continue
        cases = switch_cases(block, 64)
        table = dispatch_table(block)
        if cases is None or table is None or not _algorithm_shape(symbol, table, instructions):
            continue
        keys = _key_table(cases, table, keystream, data, reader, instructions)
        if keys is not None:
            models[symbol] = {'key_table': keys, 'parameter_count': 2, 'absolute_addresses': _absolute_addresses(symbol, table, instructions)}
    return models


__all__ = ['extract_constant_pool_models']
