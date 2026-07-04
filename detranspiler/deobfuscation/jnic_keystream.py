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

def _find_version_pointer_symbol(pseudo_c: str) -> Optional[int]:
    match = re.search(r'PTR_s_jnic_dev[^\s]*_([0-9A-Fa-f]{6,})', pseudo_c)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def _find_key_ptr(pseudo_c: str) -> Optional[int]:
    m = re.search('uStack_d8\\s*=\\s*_DAT_([0-9A-Fa-f]{6,})', pseudo_c)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            return None
    return None

def _cp_member(cp: Sequence[object], index: int) -> Optional[Tuple[str, str, str]]:
    if not 0 < index < len(cp):
        return None
    ref = cp[index]
    if not (isinstance(ref, tuple) and len(ref) >= 3 and ref[0] in {'Methodref', 'InterfaceMethodref'}):
        return None
    class_info = cp[ref[1]] if isinstance(ref[1], int) and 0 < ref[1] < len(cp) else None
    name_type = cp[ref[2]] if isinstance(ref[2], int) and 0 < ref[2] < len(cp) else None
    if not (isinstance(class_info, tuple) and len(class_info) == 2 and class_info[0] == 'Class'):
        return None
    if not (isinstance(name_type, tuple) and len(name_type) == 3 and name_type[0] == 'NameAndType'):
        return None
    owner = cp[class_info[1]] if isinstance(class_info[1], int) and 0 < class_info[1] < len(cp) else None
    name = cp[name_type[1]] if isinstance(name_type[1], int) and 0 < name_type[1] < len(cp) else None
    descriptor = cp[name_type[2]] if isinstance(name_type[2], int) and 0 < name_type[2] < len(cp) else None
    if all(isinstance(value, str) for value in (owner, name, descriptor)):
        return owner, name, descriptor
    return None


def _bytecode_instructions(code: bytes):
    one = {0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc}
    two = {0x11, 0x13, 0x14, 0x84, *range(0x99, 0xa9), 0xc6, 0xc7,
           0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1}
    four = {0xb9, 0xba, 0xc8, 0xc9}
    pc = 0
    while pc < len(code):
        start = pc
        opcode = code[pc]
        pc += 1
        if opcode == 0xaa:
            pc += (-pc) & 3
            if pc + 12 > len(code):
                return
            low = struct.unpack_from('>i', code, pc + 4)[0]
            high = struct.unpack_from('>i', code, pc + 8)[0]
            pc += 12 + max(0, high - low + 1) * 4
        elif opcode == 0xab:
            pc += (-pc) & 3
            if pc + 8 > len(code):
                return
            pairs = struct.unpack_from('>i', code, pc + 4)[0]
            pc += 8 + max(0, pairs) * 8
        elif opcode == 0xc4:
            if pc >= len(code):
                return
            modified = code[pc]
            pc += 5 if modified == 0x84 else 3
        elif opcode in one:
            pc += 1
        elif opcode in two:
            pc += 2
        elif opcode == 0xc5:
            pc += 3
        elif opcode in four:
            pc += 4
        if pc > len(code):
            return
        yield start, opcode, code[start + 1:pc]


def _integer_constant(cp: Sequence[object], index: int) -> Optional[int]:
    if not 0 < index < len(cp):
        return None
    value = cp[index]
    if isinstance(value, tuple) and len(value) == 2 and value[0] == 'Integer' and isinstance(value[1], int):
        return value[1] & 0xffffffff
    return None


def _jnic_buffer_words_from_jar(jar_path: Optional[Path]) -> Optional[Tuple[int, int, int]]:
    if jar_path is None or not Path(jar_path).is_file():
        return None
    try:
        from detranspiler.jar.scan import _jar_scan_classes
        classes = _jar_scan_classes(Path(jar_path))
    except Exception:
        return None
    matches: List[Tuple[int, int, int]] = []
    for class_name, class_meta in (classes or {}).items():
        if not isinstance(class_name, str) or class_name.rsplit('/', 1)[-1] != 'JNICLoader':
            continue
        if not isinstance(class_meta, dict):
            continue
        code = (class_meta.get('methods_code') or {}).get(('<clinit>', '()V'))
        cp = class_meta.get('cp')
        if not isinstance(code, bytes) or not isinstance(cp, list):
            continue
        last_integer: Optional[int] = None
        puts: List[int] = []
        for _pc, opcode, operands in _bytecode_instructions(code):
            if 0x02 <= opcode <= 0x08:
                last_integer = (opcode - 3) & 0xffffffff
            elif opcode == 0x10 and operands:
                last_integer = struct.unpack('>b', operands)[0] & 0xffffffff
            elif opcode == 0x11 and len(operands) == 2:
                last_integer = struct.unpack('>h', operands)[0] & 0xffffffff
            elif opcode == 0x12 and operands:
                last_integer = _integer_constant(cp, operands[0])
            elif opcode in {0x13, 0x14} and len(operands) >= 2:
                last_integer = _integer_constant(cp, struct.unpack('>H', operands[:2])[0])
            elif opcode in {0xb6, 0xb7, 0xb8, 0xb9} and len(operands) >= 2:
                member = _cp_member(cp, struct.unpack('>H', operands[:2])[0])
                if member == ('java/nio/ByteBuffer', 'putInt', '(I)Ljava/nio/ByteBuffer;') and last_integer is not None:
                    puts.append(last_integer)
                last_integer = None
        # JNIC appends four platform-independent words after all platform branches.
        if len(puts) >= 4:
            matches.append((puts[-4], puts[-3], puts[-2]))
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 else None


def _buffer_word_candidates(*, jar_path: Optional[Path]) -> List[Tuple[int, int, int]]:
    words = _jnic_buffer_words_from_jar(jar_path)
    return [words] if words is not None else []

def _score_keystream_on_register_blobs(keystream: bytes, *, data: bytes, read_u64_at_va: ReadU64, pseudo_c: str) -> int:
    return 0


def _read_bytes(data: bytes, va: int, size: int, read_u64_at_va: ReadU64) -> bytes:
    try:
        br = BinaryReader(data)
        off = br.va_to_offset(va)
        if off is None or off + size > len(data):
            return b''
        return data[off:off + size]
    except Exception:
        return b''

def build_jnic_keystream(*, binary_path: Optional[Path]=None, pseudo_c: Optional[str]=None, read_u64_at_va: Optional[ReadU64]=None, strings_by_addr: Optional[Dict[int, str]]=None, jar_path: Optional[Path]=None, params: Optional[JnicKeystreamParams]=None) -> Dict[str, object]:
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
    pointer_symbol = _find_version_pointer_symbol(pseudo_c)
    if isinstance(pointer_symbol, int):
        target = _resolve_ptr(data, pointer_symbol, read_u64_at_va)
        if isinstance(target, int):
            target_words = _read_u32_seq(data, target, 4, read_u64_at_va)
            marker = b''.join(struct.pack('<I', word) for word in target_words).lower()
            if len(target_words) == 4 and b'jnic.dev' in marker:
                version_ptr_va = target
    version_words = _read_u32_seq(data, version_ptr_va, 4, read_u64_at_va)
    key_words = _read_u32_seq(data, key_ptr_va, 8, read_u64_at_va)
    if len(version_words) < 4 or len(key_words) < 8:
        return {'status': 'SKIPPED_INCOMPLETE_CONSTANTS', 'version_words': len(version_words), 'key_words': len(key_words)}
    candidates = _buffer_word_candidates(jar_path=jar_path)
    if not candidates:
        return {'status': 'SKIPPED_NO_BUFFER_SEED', 'source': 'jar_bytecode'}
    best: Optional[Dict[str, object]] = None
    for buffer_words in candidates:
        keystream = generate_jnic_onload_keystream(local_e8=version_words[0], uStack_e4=version_words[1], uStack_e0=version_words[2], uStack_dc=version_words[3], uStack_d8=key_words[0], uStack_d8_hi=key_words[1], uStack_d0=key_words[2], uStack_d0_hi=key_words[3], uStack_c8=key_words[4], uStack_c8_hi=key_words[5], uStack_c0=key_words[6], uStack_c0_hi=key_words[7], uStack_b4=buffer_words[0], uStack_b0=buffer_words[1], uStack_ac=buffer_words[2], length=length)
        score = _score_keystream_on_register_blobs(keystream, data=data, read_u64_at_va=read_u64_at_va, pseudo_c=pseudo_c)
        item = {'status': 'OK', 'length': length, 'buffer_words': list(buffer_words), 'buffer_words_source': 'jar_bytecode', 'score': score, 'keystream_hex': keystream[:256].hex()}
        if best is None or int(item['score']) > int(best['score']):
            best = item
            best['keystream'] = keystream
    if best is None:
        return {'status': 'FAILED'}
    return best

def get_jnic_keystream_bytes(result: Dict[str, object]) -> Optional[bytes]:
    ks = result.get('keystream')
    return ks if isinstance(ks, (bytes, bytearray)) else None
