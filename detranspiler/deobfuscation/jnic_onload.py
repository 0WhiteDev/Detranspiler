from __future__ import annotations
import struct
from typing import Dict

def _u32(value: int) -> int:
    return value & 4294967295

def _rotl32(value: int, shift: int) -> int:
    value = _u32(value)
    return _u32(value << shift | value >> 32 - shift)

def _jnic_onload_double_round(state: Dict[str, int]) -> None:
    s0 = state['local_154']
    s1 = state['uVar20']
    s2 = state['uVar13']
    s3 = state['uVar19']
    s4 = state['uVar9']
    s5 = state['uVar14']
    s6 = state['uVar6']
    s7 = state['uVar7']
    s8 = state['uVar8']
    s9 = state['local_158']
    s10 = state['uVar1']
    s11 = state['uVar12']
    s12 = state['uVar15']
    s13 = state['uVar16']
    s15 = state['uVar10']
    s16 = state['uVar5']
    s6 = _u32(s6 ^ _u32(s0 + s4))
    s6 = _rotl32(s6, 16)
    s7 = _u32(s7 + s6)
    s17 = _u32(s4 ^ s7)
    s17 = _rotl32(s17, 12)
    s0 = _u32(s0 + s4 + s17)
    s6 = _u32(s6 ^ s0)
    s6 = _rotl32(s6, 8)
    s7 = _u32(s7 + s6)
    s17 = _u32(s17 ^ s7)
    s18 = _rotl32(s17, 7)
    s8 = _u32(s8 ^ _u32(s1 + s5))
    s4 = _rotl32(s8, 16)
    s9 = _u32(s9 + s4)
    s8 = _u32(s5 ^ s9)
    s17 = _rotl32(s8, 12)
    s1 = _u32(s1 + s5 + s17)
    s4 = _u32(s4 ^ s1)
    s8 = _rotl32(s4, 8)
    s9 = _u32(s9 + s8)
    s17 = _u32(s17 ^ s9)
    s5 = _rotl32(s17, 7)
    s15 = _u32(s15 ^ _u32(s2 + s12))
    s4 = _rotl32(s15, 16)
    s10 = _u32(s10 + s4)
    s15 = _u32(s12 ^ s10)
    s17 = _rotl32(s15, 12)
    s2 = _u32(s2 + s12 + s17)
    s4 = _u32(s4 ^ s2)
    s15 = _rotl32(s4, 8)
    s10 = _u32(s10 + s15)
    s17 = _u32(s17 ^ s10)
    s12 = _rotl32(s17, 7)
    s16 = _u32(s16 ^ _u32(s3 + s13))
    s4 = _rotl32(s16, 16)
    s11 = _u32(s11 + s4)
    s16 = _u32(s13 ^ s11)
    s16 = _rotl32(s16, 12)
    s3 = _u32(s3 + s13 + s16)
    s4 = _u32(s4 ^ s3)
    s4 = _rotl32(s4, 8)
    s11 = _u32(s11 + s4)
    s16 = _u32(s16 ^ s11)
    s13 = _rotl32(s16, 7)
    s0 = _u32(s0 + s5)
    s4 = _u32(s4 ^ s0)
    s4 = _rotl32(s4, 16)
    s10 = _u32(s10 + s4)
    s5 = _u32(s5 ^ s10)
    s5 = _rotl32(s5, 12)
    s0 = _u32(s0 + s5)
    s4 = _u32(s4 ^ s0)
    s4 = _rotl32(s4, 8)
    s10 = _u32(s10 + s4)
    s5 = _u32(s5 ^ s10)
    s5 = _rotl32(s5, 7)
    s1 = _u32(s1 + s12)
    s6 = _u32(s6 ^ s1)
    s4 = _rotl32(s6, 16)
    s11 = _u32(s11 + s4)
    s12 = _u32(s12 ^ s11)
    s12 = _rotl32(s12, 12)
    s1 = _u32(s1 + s12)
    s4 = _u32(s4 ^ s1)
    s6 = _rotl32(s4, 8)
    s11 = _u32(s11 + s6)
    s12 = _u32(s12 ^ s11)
    s12 = _rotl32(s12, 7)
    s2 = _u32(s2 + s13)
    s8 = _u32(s8 ^ s2)
    s4 = _rotl32(s8, 16)
    s7 = _u32(s7 + s4)
    s13 = _u32(s13 ^ s7)
    s13 = _rotl32(s13, 12)
    s2 = _u32(s2 + s13)
    s4 = _u32(s4 ^ s2)
    s8 = _rotl32(s4, 8)
    s7 = _u32(s7 + s8)
    s13 = _u32(s13 ^ s7)
    s13 = _rotl32(s13, 7)
    s3 = _u32(s3 + s18)
    s15 = _u32(s15 ^ s3)
    s4 = _rotl32(s15, 16)
    s9 = _u32(s9 + s4)
    s18 = _u32(s18 ^ s9)
    s17 = _rotl32(s18, 12)
    s3 = _u32(s3 + s17)
    s4 = _u32(s4 ^ s3)
    s15 = _rotl32(s4, 8)
    s9 = _u32(s9 + s15)
    s17 = _u32(s17 ^ s9)
    s14 = _rotl32(s17, 7)
    state.update({'local_154': s0, 'uVar20': s1, 'uVar13': s2, 'uVar19': s3, 'uVar9': s4, 'uVar14': s5, 'uVar6': s6, 'uVar7': s7, 'uVar8': s8, 'local_158': s9, 'uVar1': s10, 'uVar12': s11, 'uVar15': s12, 'uVar16': s13, 'uVar18': s14, 'uVar10': s15, 'uVar5': s16})

def _quarter_round(words, a: int, b: int, c: int, d: int) -> None:
    words[a] = _u32(words[a] + words[b])
    words[d] = _rotl32(words[d] ^ words[a], 16)
    words[c] = _u32(words[c] + words[d])
    words[b] = _rotl32(words[b] ^ words[c], 12)
    words[a] = _u32(words[a] + words[b])
    words[d] = _rotl32(words[d] ^ words[a], 8)
    words[c] = _u32(words[c] + words[d])
    words[b] = _rotl32(words[b] ^ words[c], 7)


def _chacha_block(initial) -> list[int]:
    words = list(initial)
    for _ in range(10):
        _quarter_round(words, 0, 4, 8, 12)
        _quarter_round(words, 1, 5, 9, 13)
        _quarter_round(words, 2, 6, 10, 14)
        _quarter_round(words, 3, 7, 11, 15)
        _quarter_round(words, 0, 5, 10, 15)
        _quarter_round(words, 1, 6, 11, 12)
        _quarter_round(words, 2, 7, 8, 13)
        _quarter_round(words, 3, 4, 9, 14)
    return [_u32(value + initial[index]) for index, value in enumerate(words)]

def generate_jnic_onload_keystream(*, local_e8: int, uStack_e4: int, uStack_e0: int, uStack_dc: int, uStack_d8: int, uStack_d8_hi: int, uStack_d0: int, uStack_d0_hi: int, uStack_c8: int, uStack_c8_hi: int, uStack_c0: int, uStack_c0_hi: int, uStack_b4: int, uStack_b0: int, uStack_ac: int, length: int) -> bytes:
    init = {'local_e8': _u32(local_e8), 'uStack_e4': _u32(uStack_e4), 'uStack_e0': _u32(uStack_e0), 'uStack_dc': _u32(uStack_dc), 'uStack_d8': _u32(uStack_d8), 'uStack_d8_hi': _u32(uStack_d8_hi), 'uStack_d0': _u32(uStack_d0), 'uStack_d0_hi': _u32(uStack_d0_hi), 'uStack_c8': _u32(uStack_c8), 'uStack_c8_hi': _u32(uStack_c8_hi), 'uStack_c0': _u32(uStack_c0), 'uStack_c0_hi': _u32(uStack_c0_hi), 'uStack_b4': _u32(uStack_b4), 'uStack_b0': _u32(uStack_b0), 'uStack_ac': _u32(uStack_ac)}
    local_b8 = 0
    local_a8 = 64
    block = bytearray(64)
    out = bytearray()
    while len(out) < length:
        if local_a8 < 64:
            out.append(block[local_a8])
        else:
            initial = [
                init['local_e8'], init['uStack_e4'], init['uStack_e0'], init['uStack_dc'],
                init['uStack_d8'], init['uStack_d8_hi'], init['uStack_d0'], init['uStack_d0_hi'],
                init['uStack_c8'], init['uStack_c8_hi'], init['uStack_c0'], init['uStack_c0_hi'],
                local_b8, init['uStack_b4'], init['uStack_b0'], init['uStack_ac'],
            ]
            words = _chacha_block(initial)
            block = bytearray(b''.join((struct.pack('<I', word) for word in words)))
            local_b8 = _u32(local_b8 + 1)
            out.append(words[0] & 255)
            local_a8 = 0
        local_a8 += 1
    return bytes(out[:length])
