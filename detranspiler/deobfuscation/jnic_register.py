from __future__ import annotations
import re
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple
_DAT_ENC_RE = re.compile('(?:^|\\s)(?:local_[0-9A-Za-z_]+\\s*=\\s*)?(?:_DAT_|_UNK_|DAT_)([0-9A-Fa-f]{6,})', re.MULTILINE)
_XOR_OFFSET_RE = re.compile('DAT_180035048\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)', re.IGNORECASE)
_BYTE_XOR_LOOP_RE = re.compile('\\*\\(byte \\*\\)\\((?:longlong )?&local_([0-9A-Za-z_]+)\\s*\\+\\s*lVar\\d+\\)\\s*=\\s*\\*\\(byte \\*\\)\\((?:longlong )?&local_\\1\\s*\\+\\s*lVar\\d+\\)\\s*\\^\\s*\\*\\(byte \\*\\)\\(DAT_180035048\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)', re.IGNORECASE)

def _parse_int(raw: str) -> Optional[int]:
    raw = str(raw or '').strip()
    if not raw:
        return None
    try:
        return int(raw, 16 if raw.lower().startswith('0x') else 10)
    except Exception:
        return None

def _read_dat_qwords(pseudo_c: str, read_u64_at_va) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for m in re.finditer('\\b(_DAT_|_UNK_|DAT_)([0-9A-Fa-f]{6,})\\b', pseudo_c):
        sym = f'{m.group(1)}{m.group(2)}'
        if sym in out:
            continue
        try:
            va = int(m.group(2), 16)
        except Exception:
            continue
        raw = read_u64_at_va(va)
        if isinstance(raw, int):
            out[sym] = raw
    return out

def _extract_local_blob(block: str, local_name: str, dat_values: Dict[str, int]) -> Optional[bytes]:
    pattern = re.compile(f'local_{re.escape(local_name)}\\s*=\\s*(?:_DAT_|_UNK_|DAT_)([0-9A-Fa-f]{ 6,} )', re.IGNORECASE)
    m = pattern.search(block)
    if not m:
        return None
    sym = m.group(0).split('=')[-1].strip()
    sym_match = re.search('(?:_DAT_|_UNK_|DAT_)([0-9A-Fa-f]{6,})', sym)
    if not sym_match:
        return None
    va = int(sym_match.group(1), 16)
    words: List[int] = []
    for suffix in ('',):
        raw = dat_values.get(sym)
        if isinstance(raw, int):
            words.append(raw & 4294967295)
            words.append(raw >> 32 & 4294967295)
    if not words:
        return None
    blob = b''.join((struct.pack('<I', w) for w in words))
    return blob[:32]

def _apply_block_xor(data: bytearray, *, keystream: bytes, base_offset: int, start: int=0, end: Optional[int]=None) -> None:
    if end is None:
        end = len(data)
    for idx in range(start, min(end, len(data))):
        ks_idx = base_offset + idx
        if ks_idx < 0 or ks_idx >= len(keystream):
            break
        data[idx] ^= keystream[ks_idx]

def _apply_paired_xor_loops(block: str, data: bytearray, keystream: bytes) -> None:
    for m in _BYTE_XOR_LOOP_RE.finditer(block):
        offset = _parse_int(m.group(2))
        if offset is None:
            continue
        _apply_block_xor(data, keystream=keystream, base_offset=offset, start=0, end=len(data))

def _decode_c_string(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    end = raw.find(b'\x00')
    if end >= 0:
        raw = raw[:end]
    if not raw:
        return None
    try:
        text = raw.decode('utf-8', errors='strict')
    except Exception:
        return None
    if not text:
        return None
    if not all((ch.isprintable() or ch in '\r\n\t' for ch in text)):
        return None
    return text

def decrypt_jnic_loader_register_methods(loader_block: str, *, keystream: bytes, read_u64_at_va) -> List[Dict[str, Any]]:
    if not isinstance(loader_block, str) or not loader_block.strip() or (not keystream):
        return []
    dat_values = _read_dat_qwords(loader_block, read_u64_at_va)
    methods: List[Dict[str, Any]] = []
    entry_re = re.compile('local_(?P<fn_var>[0-9A-Za-z_]+)\s*=\s*(?P<fn>FUN_[0-9A-Fa-f]+)\s*;(?:(?!local_[0-9A-Za-z_]+\s*=\s*FUN_).)*?local_(?P<name_var>[0-9A-Za-z_]+)\s*=\s*(?P<name_expr>&local_[0-9A-Za-z_]+|[0-9A-Za-z_ +]+)\s*;.*?local_(?P<sig_var>[0-9A-Za-z_]+)\s*=\s*(?P<sig_expr>&local_[0-9A-Fa-f]+|[0-9A-Za-z_ +]+)\s*;', re.DOTALL)
    for m in entry_re.finditer(loader_block):
        fn_symbol = m.group('fn')
        segment = m.group(0)
        name_local = _local_from_expr(m.group('name_expr'))
        sig_local = _local_from_expr(m.group('sig_expr'))
        name_blob = _extract_local_blob(segment, name_local, dat_values) if name_local else None
        sig_blob = _extract_local_blob(segment, sig_local, dat_values) if sig_local else None
        name_offset = _first_xor_offset(segment, name_local)
        sig_offset = _first_xor_offset(segment, sig_local)
        name = _decrypt_blob(name_blob, segment, name_offset, keystream)
        signature = _decrypt_blob(sig_blob, segment, sig_offset, keystream)
        if not fn_symbol:
            continue
        methods.append({'name': name, 'signature': signature, 'fn_symbol': fn_symbol})
    return methods

def _local_from_expr(expr: str) -> Optional[str]:
    m = re.search('local_([0-9A-Za-z_]+)', expr or '')
    if not m:
        return None
    return m.group(1)

def _first_xor_offset(segment: str, local_name: Optional[str]) -> Optional[int]:
    if not local_name:
        return None
    pat = re.compile(f'local_{re.escape(local_name)}[\\s\\S]{ 0,1200} ?DAT_180035048\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)', re.IGNORECASE)
    m = pat.search(segment)
    if not m:
        return None
    return _parse_int(m.group(1))

def _decrypt_blob(blob: Optional[bytes], segment: str, offset: Optional[int], keystream: bytes) -> Optional[str]:
    if blob is None:
        return None
    data = bytearray(blob)
    if isinstance(offset, int):
        _apply_block_xor(data, keystream=keystream, base_offset=offset, start=0, end=min(24, len(data)))
    _apply_paired_xor_loops(segment, data, keystream)
    return _decode_c_string(bytes(data))

def enrich_jnic_register_calls(jni_register: Optional[Dict[str, Any]], *, pseudo_c: Optional[str], keystream: Optional[bytes], read_u64_at_va) -> Dict[str, Any]:
    if not isinstance(jni_register, dict) or not isinstance(keystream, (bytes, bytearray)):
        return jni_register or {'status': 'SKIPPED'}
    if not isinstance(pseudo_c, str) or not pseudo_c.strip():
        return jni_register
    updated = dict(jni_register)
    calls = updated.get('register_calls')
    if not isinstance(calls, list):
        return updated
    new_calls: List[Dict[str, Any]] = []
    resolved_total = 0
    for call in calls:
        if not isinstance(call, dict):
            new_calls.append(call)
            continue
        fn = call.get('function')
        if not isinstance(fn, str) or not fn.startswith('Java_'):
            new_calls.append(call)
            continue
        block = _extract_function_block(pseudo_c, fn)
        if not block:
            new_calls.append(call)
            continue
        decrypted = decrypt_jnic_loader_register_methods(block, keystream=bytes(keystream), read_u64_at_va=read_u64_at_va)
        methods = call.get('methods')
        if not isinstance(methods, list):
            methods = []
        merged_methods: List[Dict[str, Any]] = []
        for idx, item in enumerate(methods):
            merged = dict(item) if isinstance(item, dict) else {}
            if idx < len(decrypted):
                dec = decrypted[idx]
                if dec.get('name'):
                    merged['name'] = dec['name']
                    resolved_total += 1
                if dec.get('signature'):
                    merged['signature'] = dec['signature']
                if dec.get('fn_symbol') and (not merged.get('fn_symbol')):
                    merged['fn_symbol'] = dec['fn_symbol']
            merged_methods.append(merged)
        if len(decrypted) > len(merged_methods):
            merged_methods.extend(decrypted[len(merged_methods):])
        call = dict(call)
        call['methods'] = merged_methods
        call['methods_parsed'] = sum((1 for m in merged_methods if isinstance(m, dict) and m.get('name') and m.get('signature')))
        new_calls.append(call)
    updated['register_calls'] = new_calls
    updated['jnic_strings_resolved'] = resolved_total
    return updated

def _extract_function_block(pseudo_c: str, fn_name: str) -> Optional[str]:
    m = re.search(f'/\\* FUNCTION {re.escape(fn_name)}\\s+[0-9A-Fa-f]+\\s+\\*/', pseudo_c)
    if not m:
        return None
    start = m.end()
    depth = 0
    idx = start
    while idx < len(pseudo_c):
        ch = pseudo_c[idx]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return pseudo_c[start:idx + 1]
        idx += 1
    return None
