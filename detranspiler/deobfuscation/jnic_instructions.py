from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detranspiler.jni.vtable import decode_jni_offset

_REG_ALIASES = {
    'EAX': 'RAX', 'AX': 'RAX', 'AL': 'RAX',
    'EBX': 'RBX', 'BX': 'RBX', 'BL': 'RBX',
    'ECX': 'RCX', 'CX': 'RCX', 'CL': 'RCX',
    'EDX': 'RDX', 'DX': 'RDX', 'DL': 'RDX',
    'ESI': 'RSI', 'EDI': 'RDI', 'EBP': 'RBP', 'ESP': 'RSP',
    'R8D': 'R8', 'R9D': 'R9', 'R10D': 'R10', 'R11D': 'R11',
    'R12D': 'R12', 'R13D': 'R13', 'R14D': 'R14', 'R15D': 'R15',
}
_REG_RE = re.compile(r'^R(?:AX|BX|CX|DX|SI|DI|BP|SP|8|9|10|11|12|13|14|15)$')
_ABS_MEMORY_RE = re.compile(r'^(?:qword|dword|word|byte) ptr \[(0x[0-9a-fA-F]+)]$')
_STACK_MEMORY_RE = re.compile(r'^(?:qword|dword|word|byte) ptr \[RSP \+ (0x[0-9a-fA-F]+)]$')
_BASE_OFFSET_RE = re.compile(r'^(?:qword|dword|word|byte) ptr \[(R\w+) \+ (0x[0-9a-fA-F]+)]$')
_DIRECT_OFFSET_CALL_RE = re.compile(r'^qword ptr \[(R\w+) \+ (0x[0-9a-fA-F]+)]$')
_IMMEDIATE_RE = re.compile(r'^-?0x[0-9a-fA-F]+$|^-?\d+$')


def _reg(raw: str) -> Optional[str]:
    value = str(raw or '').strip().upper()
    value = _REG_ALIASES.get(value, value)
    return value if _REG_RE.match(value) else None


def _split_operands(text: str) -> List[str]:
    raw = text.split(None, 1)[1] if ' ' in text else ''
    parts: List[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(raw):
        if char == '[':
            depth += 1
        elif char == ']':
            depth = max(0, depth - 1)
        elif char == ',' and depth == 0:
            parts.append(raw[start:index].strip())
            start = index + 1
    if raw[start:].strip():
        parts.append(raw[start:].strip())
    return parts


def _memory_symbol(raw: str) -> Optional[str]:
    match = _ABS_MEMORY_RE.match(raw)
    return f'DAT_{int(match.group(1), 16):x}' if match else None


def _value(raw: str, values: Dict[str, str]) -> str:
    register = _reg(raw)
    if register:
        return values.get(register, f'asm_{register.lower()}')
    symbol = _memory_symbol(raw)
    if symbol:
        return symbol
    value = raw.strip()
    if _IMMEDIATE_RE.match(value):
        try:
            return str(int(value, 16 if '0x' in value.lower() else 10))
        except ValueError:
            return value
    return value


def _function_existing_counts(calls: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for call in calls:
        function = call.get('function')
        if isinstance(function, str):
            counts[function] = counts.get(function, 0) + 1
    return counts


def augment_jni_calls_from_instructions(
    jni_calls: Optional[Dict[str, Any]],
    *,
    functions_json_path: Optional[Path],
    function_aliases: Optional[Dict[str, str]]=None,
) -> Dict[str, Any]:
    if not isinstance(jni_calls, dict) or functions_json_path is None or not functions_json_path.is_file():
        return jni_calls or {'status': 'SKIPPED'}
    try:
        document = json.loads(functions_json_path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return jni_calls
    functions = document.get('functions') if isinstance(document, dict) else None
    if not isinstance(functions, list):
        return jni_calls
    calls = [dict(item) for item in jni_calls.get('calls') or [] if isinstance(item, dict)]
    existing = _function_existing_counts(calls)
    added = 0
    functions_augmented = 0
    seen_instruction_calls: set[tuple[str, str, str]] = set()
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get('name')
        entry = function.get('entry')
        instructions = function.get('instructions')
        entry_key = str(entry or '').lower().removeprefix('0x')
        canonical_name = (function_aliases or {}).get(entry_key, name)
        is_aliased_target = canonical_name != name
        if not isinstance(name, str) or not isinstance(canonical_name, str) or (canonical_name == name and existing.get(name, 0) > 0) or not isinstance(instructions, list):
            continue
        values: Dict[str, str] = {
            'RCX': 'param_1',
            'RDX': 'param_2',
            'R8': 'param_3',
            'R9': 'param_4',
        }
        vtables: set[str] = set()
        fn_offsets: Dict[str, int] = {}
        stack_args: Dict[int, str] = {}
        function_added = 0
        for instruction in instructions:
            if not isinstance(instruction, dict):
                continue
            mnemonic = str(instruction.get('mnemonic') or '').upper()
            text = str(instruction.get('text') or '')
            address = str(instruction.get('address') or '')
            operands = _split_operands(text)
            if mnemonic in {'MOV', 'MOVZX', 'MOVSX', 'MOVSXD'} and len(operands) == 2:
                destination, source = operands
                destination_reg = _reg(destination)
                source_reg = _reg(source)
                if destination_reg:
                    values[destination_reg] = _value(source, values)
                    if source_reg and source_reg in vtables:
                        vtables.add(destination_reg)
                    else:
                        base_match = _BASE_OFFSET_RE.match(source)
                        if base_match:
                            base = _reg(base_match.group(1))
                            offset = int(base_match.group(2), 16)
                            if base and base in vtables:
                                decoded = decode_jni_offset(offset)
                                if decoded.get('name'):
                                    fn_offsets[destination_reg] = offset
                        elif source.startswith(('qword ptr [', 'dword ptr [')):
                            base_only = re.match(r'^(?:qword|dword) ptr \[(R\w+)]$', source)
                            base = _reg(base_only.group(1)) if base_only else None
                            if base and values.get(base) == 'param_1':
                                vtables.add(destination_reg)
                    if source_reg and source_reg in fn_offsets:
                        fn_offsets[destination_reg] = fn_offsets[source_reg]
                    elif destination_reg in fn_offsets and not _BASE_OFFSET_RE.match(source):
                        fn_offsets.pop(destination_reg, None)
                else:
                    stack_match = _STACK_MEMORY_RE.match(destination)
                    if stack_match:
                        stack_args[int(stack_match.group(1), 16)] = _value(source, values)
                continue
            if mnemonic == 'LEA' and len(operands) == 2:
                destination_reg = _reg(operands[0])
                if destination_reg:
                    absolute = re.match(r'^\[(0x[0-9a-fA-F]+)]$', operands[1])
                    stack = re.match(r'^\[RSP \+ (0x[0-9a-fA-F]+)]$', operands[1])
                    if absolute:
                        values[destination_reg] = f'PTR_{int(absolute.group(1), 16):x}'
                    elif stack:
                        values[destination_reg] = f'&stack_{int(stack.group(1), 16):x}'
                continue
            if mnemonic != 'CALL' or not operands:
                continue
            target = operands[0]
            call_stack_args = dict(stack_args)
            stack_args.clear()
            offset: Optional[int] = None
            target_reg = _reg(target)
            if target_reg:
                offset = fn_offsets.get(target_reg)
            else:
                direct = _DIRECT_OFFSET_CALL_RE.match(target)
                if direct:
                    base = _reg(direct.group(1))
                    candidate = int(direct.group(2), 16)
                    if base and (base in vtables or is_aliased_target) and decode_jni_offset(candidate).get('name'):
                        vtables.add(base)
                        offset = candidate
            if offset is None:
                continue
            decoded = decode_jni_offset(offset)
            jni_name = decoded.get('name')
            if not isinstance(jni_name, str) or not jni_name:
                continue
            instruction_key = (canonical_name, address.lower(), jni_name)
            if instruction_key in seen_instruction_calls:
                continue
            seen_instruction_calls.add(instruction_key)
            args = [values.get(register, f'asm_{register.lower()}') for register in ('RCX', 'RDX', 'R8', 'R9')]
            for stack_offset in sorted(key for key in call_stack_args if key >= 0x20):
                args.append(call_stack_args[stack_offset])
            result_var = f'asm_result_{address.lower()}'
            calls.append({
                'function': canonical_name,
                'function_address': str(entry or '').lower(),
                'line': 0,
                'instruction_address': address.lower(),
                'result_var': result_var,
                'env_var': args[0] if args else None,
                'offset': hex(offset),
                'pointer_size': decoded.get('pointer_size'),
                'jni_index': decoded.get('index'),
                'jni_name': jni_name,
                'category': decoded.get('category'),
                'args': args[:16],
                'args_total': len(args),
                'resolved': {},
                'alternates': decoded.get('alternates') or [],
                'source_line': text,
                'source': 'ghidra_instructions',
            })
            values['RAX'] = result_var
            function_added += 1
            added += 1
        if function_added:
            functions_augmented += 1
    if not added:
        return jni_calls
    calls.sort(key=lambda item: (
        str(item.get('function') or ''),
        int(str(item.get('instruction_address') or item.get('function_address') or '0'), 16)
        if re.fullmatch(r'[0-9A-Fa-f]+', str(item.get('instruction_address') or item.get('function_address') or ''))
        else int(item.get('line') or 0),
    ))
    counts_by_name: Dict[str, int] = {}
    counts_by_category: Dict[str, int] = {}
    for call in calls:
        call_name = call.get('jni_name')
        category = str(call.get('category') or 'other')
        if isinstance(call_name, str) and call_name:
            counts_by_name[call_name] = counts_by_name.get(call_name, 0) + 1
        counts_by_category[category] = counts_by_category.get(category, 0) + 1
    updated = dict(jni_calls)
    updated['calls'] = calls
    updated['calls_total'] = len(calls)
    updated['counts_by_name'] = counts_by_name
    updated['counts_by_category'] = counts_by_category
    updated['jnic_instruction_calls_added'] = added
    updated['jnic_instruction_functions_augmented'] = functions_augmented
    return updated


__all__ = ['augment_jni_calls_from_instructions']
