from __future__ import annotations
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from detranspiler.binary.reader import BinaryReader
ReadU64 = Callable[[int], Optional[int]]

def _rotl32(value: int, shift: int) -> int:
    return value << shift & 4294967295 | value >> 32 - shift & 4294967295
from detranspiler.deobfuscation.jnic_onload import generate_jnic_onload_keystream

def _read_u32_at(data: bytes, va: int, read_u64_at_va: ReadU64) -> Optional[int]:
    raw = read_u64_at_va(va)
    if not isinstance(raw, int):
        off = None
        try:
            br = BinaryReader(data)
            off = br.va_to_offset(va)
        except Exception:
            off = None
        if off is None or off + 4 > len(data):
            return None
        return struct.unpack_from('<I', data, off)[0]
    return raw & 4294967295

def _read_u32_seq(data: bytes, va: int, count: int, read_u64_at_va: ReadU64) -> List[int]:
    words: List[int] = []
    for idx in range(count):
        word = _read_u32_at(data, va + idx * 4, read_u64_at_va)
        if word is None:
            break
        words.append(word)
    return words

def _resolve_ptr(data: bytes, ptr_va: int, read_u64_at_va: ReadU64) -> Optional[int]:
    raw = read_u64_at_va(ptr_va)
    if isinstance(raw, int) and raw > 65536:
        return raw
    try:
        br = BinaryReader(data)
        off = br.va_to_offset(ptr_va)
        if off is None:
            return None
        if br.pointer_size == 8:
            return struct.unpack_from('<Q', data, off)[0]
        return struct.unpack_from('<I', data, off)[0]
    except Exception:
        return None

@dataclass
class JnicKeystreamParams:
    version_ptr_va: int
    key_ptr_va: int
    buffer_base_va: Optional[int]
    buffer_offset: int = 32
    length: int = 8573

def _find_jnic_keystream_length(pseudo_c: str) -> int:
    matches = re.findall('local_90\\s*!=\\s*(0x[0-9A-Fa-f]+)', pseudo_c)
    for raw in reversed(matches):
        try:
            value = int(raw, 16)
            if 4096 <= value <= 2097152:
                return value
        except Exception:
            continue
    return 8573

def _find_version_ptr(pseudo_c: str, strings: Optional[Dict[int, str]]=None) -> Optional[int]:
    if isinstance(strings, dict):
        for addr, value in strings.items():
            if isinstance(value, str) and 'jnic.dev v' in value:
                return int(addr)
    for pat in ('PTR_s_jnic_dev[^\\s]*_([0-9A-Fa-f]{6,})', 'DAT_([0-9A-Fa-f]{6,}).*jnic\\.dev'):
        m = re.search(pat, pseudo_c)
        if m:
            try:
                return int(m.group(1), 16)
            except Exception:
                pass
    return None

def _find_key_ptr(pseudo_c: str) -> Optional[int]:
    m = re.search('uStack_d8\\s*=\\s*_DAT_([0-9A-Fa-f]{6,})', pseudo_c)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            return None
    return None

def _buffer_word_candidates(data: bytes, *, version_ptr_va: int, read_u64_at_va: ReadU64, image_base: int=6442450944) -> List[Tuple[int, int, int]]:
    candidates: List[Tuple[int, int, int]] = []
    seen: set[Tuple[int, int, int]] = set()

    def add(base_va: int) -> None:
        words = _read_u32_seq(data, base_va + 32, 3, read_u64_at_va)
        if len(words) == 3:
            key = (words[0], words[1], words[2])
            if key not in seen:
                seen.add(key)
                candidates.append(key)
    for base in range(image_base + 197120, image_base + 197632, 4):
        add(base)
    add(version_ptr_va)
    return candidates

def _score_keystream_on_register_blobs(keystream: bytes, *, data: bytes, read_u64_at_va: ReadU64, pseudo_c: str) -> int:
    score = 0
    probes = [(6442648892, 5320, 24), (6442648915, 5343, 24), (6442648939, 5367, 24), (6442647808, 6571, 16)]
    for va, offset, size in probes:
        enc = _read_bytes(data, va, size, read_u64_at_va)
        if not enc:
            continue
        plain = bytes((b ^ keystream[offset + i] for i, b in enumerate(enc) if offset + i < len(keystream)))
        text = plain.split(b'\x00')[0]
        if not text:
            continue
        try:
            decoded = text.decode('utf-8')
        except Exception:
            continue
        if not decoded:
            continue
        if decoded.startswith('(') and ')' in decoded:
            score += 40
        if decoded.replace('/', '').replace('_', '').replace('$', '').isalnum():
            score += 20
        if all((ch.isprintable() for ch in decoded)):
            score += 10
    return score

def _read_bytes(data: bytes, va: int, size: int, read_u64_at_va: ReadU64) -> bytes:
    try:
        br = BinaryReader(data)
        off = br.va_to_offset(va)
        if off is None or off + size > len(data):
            return b''
        return data[off:off + size]
    except Exception:
        return b''

def build_jnic_keystream(*, binary_path: Optional[Path]=None, pseudo_c: Optional[str]=None, read_u64_at_va: Optional[ReadU64]=None, strings_by_addr: Optional[Dict[int, str]]=None, params: Optional[JnicKeystreamParams]=None) -> Dict[str, object]:
    if not isinstance(pseudo_c, str) or not pseudo_c.strip():
        return {'status': 'SKIPPED_NO_PSEUDOC'}
    if read_u64_at_va is None and (binary_path is None or not binary_path.is_file()):
        return {'status': 'SKIPPED_NO_BINARY'}
    data = binary_path.read_bytes() if binary_path and binary_path.is_file() else b''
    if read_u64_at_va is None:
        br = BinaryReader(data)
        image_base = br.image_base or 6442450944

        def _read(va: int) -> Optional[int]:
            off = br.va_to_offset(va)
            if off is None or off + 8 > len(data):
                return None
            return struct.unpack_from('<Q', data, off)[0]
        read_u64_at_va = _read
    else:
        image_base = 6442450944
        if binary_path and binary_path.is_file() and (not data):
            data = binary_path.read_bytes()
    version_ptr_va = params.version_ptr_va if params else None
    key_ptr_va = params.key_ptr_va if params else None
    length = params.length if params else _find_jnic_keystream_length(pseudo_c)
    if version_ptr_va is None:
        version_ptr_va = _find_version_ptr(pseudo_c, strings_by_addr)
    if key_ptr_va is None:
        key_ptr_va = _find_key_ptr(pseudo_c)
    if version_ptr_va is None or key_ptr_va is None:
        return {'status': 'SKIPPED_NO_CONSTANTS', 'version_ptr_va': version_ptr_va, 'key_ptr_va': key_ptr_va}
    version_words = _read_u32_seq(data, version_ptr_va, 4, read_u64_at_va)
    if len(version_words) < 4:
        ptr_sym_va = _find_version_ptr(pseudo_c, None)
        if isinstance(ptr_sym_va, int):
            target = _resolve_ptr(data, ptr_sym_va, read_u64_at_va)
            if isinstance(target, int):
                version_words = _read_u32_seq(data, target, 4, read_u64_at_va)
    key_words = _read_u32_seq(data, key_ptr_va, 8, read_u64_at_va)
    if len(version_words) < 4 or len(key_words) < 8:
        return {'status': 'SKIPPED_INCOMPLETE_CONSTANTS', 'version_words': len(version_words), 'key_words': len(key_words)}
    candidates = _buffer_word_candidates(data, version_ptr_va=version_ptr_va, read_u64_at_va=read_u64_at_va)
    if not candidates:
        candidates = [(0, 0, 0)]
    best: Optional[Dict[str, object]] = None
    for buffer_words in candidates:
        keystream = generate_jnic_onload_keystream(local_e8=version_words[0], uStack_e4=version_words[1], uStack_e0=version_words[2], uStack_dc=version_words[3], uStack_d8=key_words[0], uStack_d8_hi=key_words[1], uStack_d0=key_words[2], uStack_d0_hi=key_words[3], uStack_c8=key_words[4], uStack_c8_hi=key_words[5], uStack_c0=key_words[6], uStack_c0_hi=key_words[7], uStack_b4=buffer_words[0], uStack_b0=buffer_words[1], uStack_ac=buffer_words[2], length=length)
        score = _score_keystream_on_register_blobs(keystream, data=data, read_u64_at_va=read_u64_at_va, pseudo_c=pseudo_c)
        item = {'status': 'OK', 'length': length, 'buffer_words': list(buffer_words), 'score': score, 'keystream_hex': keystream[:256].hex()}
        if best is None or int(item['score']) > int(best['score']):
            best = item
            best['keystream'] = keystream
    if best is None:
        return {'status': 'FAILED'}
    return best

def get_jnic_keystream_bytes(result: Dict[str, object]) -> Optional[bytes]:
    ks = result.get('keystream')
    return ks if isinstance(ks, (bytes, bytearray)) else None
