import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def _is_printable_string(s: str, *, min_len: int=3) -> bool:
    if not isinstance(s, str) or len(s) < min_len:
        return False
    if len(s) > 512:
        return False
    printable = sum((1 for ch in s if 32 <= ord(ch) <= 126 or ch in '\t\n\r'))
    if printable < max(min_len, int(len(s) * 0.75)):
        return False
    alnum = sum((1 for ch in s if ch.isalnum() or ch in ' _-.,!?/:+'))
    return alnum >= max(2, int(len(s) * 0.6))
_ENGLISH_FREQ = ' etaoinshrdlcumwfgypbvkjxqz'

def _score_decrypted_string(s: str) -> int:
    if not s:
        return -1
    score = 0
    score += sum((1 for ch in s if ch.isalpha())) * 2
    score += sum((1 for ch in s if ch.isdigit()))
    score -= sum((1 for ch in s if ord(ch) < 32)) * 5
    score -= sum((1 for ch in s if not ch.isalnum() and ch not in ' _-.,!?/:+')) * 3
    lower = s.lower()
    for ch in lower:
        if ch in _ENGLISH_FREQ:
            score += 3 - _ENGLISH_FREQ.index(ch)
    if lower in {'hello', 'world', 'error', 'secret', 'password', 'main', 'init', 'class', 'format'}:
        score += 50
    if ' ' in s and sum((1 for ch in s if ch.isalpha())) >= 5:
        score += 20
    if re.search('[A-Za-z]{2,}\\s+[A-Za-z]{2,}', s):
        score += 25
    return score

def _best_xor_decrypt(data: bytes) -> Optional[Tuple[int, str]]:
    best: Optional[Tuple[int, str, int]] = None
    for key in range(256):
        s = _try_xor_decrypt(data, key)
        if not s:
            continue
        sc = _score_decrypted_string(s)
        if best is None or sc > best[2]:
            best = (key, s, sc)
    if best is None:
        return None
    return best[0], best[1]

def _try_multibyte_xor(data: bytes, key: bytes) -> Optional[str]:
    if not data or not key:
        return None
    out = bytes((b ^ key[i % len(key)] for i, b in enumerate(data)))
    try:
        s = out.decode('utf-8', errors='ignore')
    except Exception:
        s = out.decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _english_likeness(s: str) -> int:
    if not s:
        return -1
    alpha = sum((1 for ch in s if ch.isalpha()))
    if alpha < max(3, len(s) // 4):
        return -1
    score = 0
    for ch in s.lower():
        if ch in _ENGLISH_FREQ:
            score += 14 - _ENGLISH_FREQ.index(ch)
    if re.search('[A-Za-z]{2,}\\s+[A-Za-z]{2,}', s):
        score += 40
    return score

def _best_multibyte_xor(data: bytes, *, max_key_len: int=2) -> Optional[Tuple[bytes, str]]:
    best: Optional[Tuple[bytes, str, int]] = None
    for klen in range(2, max_key_len + 1):
        if len(data) < klen + 2:
            continue
        if klen == 2:
            for k0 in range(256):
                for k1 in range(256):
                    key = bytes([k0, k1])
                    s = _try_multibyte_xor(data, key)
                    if not s:
                        continue
                    sc = _english_likeness(s)
                    if sc < 0:
                        continue
                    if best is None or sc > best[2]:
                        best = (key, s, sc)
    if best is None:
        return None
    single = _best_xor_decrypt(data)
    if single:
        single_like = _english_likeness(single[1])
        if best[2] <= single_like:
            return None
    return best[0], best[1]

def _try_xor_decrypt(data: bytes, key: int) -> Optional[str]:
    if not data:
        return None
    out = bytes((b ^ key & 255 for b in data))
    try:
        s = out.decode('utf-8', errors='ignore')
    except Exception:
        s = out.decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _try_reverse_xor(data: bytes, key: int) -> Optional[str]:
    if not data:
        return None
    xored = bytes((b ^ key & 255 for b in data))
    out = bytes(reversed(xored))
    try:
        s = out.decode('utf-8', errors='ignore')
    except Exception:
        s = out.decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _try_index_xor(data: bytes, base_key: int) -> Optional[str]:
    if not data or len(data) < 3:
        return None
    out = bytearray((b ^ base_key + i & 255 for i, b in enumerate(data)))
    try:
        s = bytes(out).decode('utf-8', errors='ignore')
    except Exception:
        s = bytes(out).decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _try_rolling_xor(data: bytes, start_key: int) -> Optional[str]:
    if not data or len(data) < 3:
        return None
    out = bytearray()
    k = start_key & 255
    for b in data:
        out.append(b ^ k)
        k = k + 1 & 255 or 1
    try:
        s = bytes(out).decode('utf-8', errors='ignore')
    except Exception:
        s = bytes(out).decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _try_rolling_sub(data: bytes, start_key: int) -> Optional[str]:
    if not data or len(data) < 3:
        return None
    out = bytearray()
    k = start_key & 255
    for b in data:
        out.append(b - k & 255)
        k = k + 1 & 255 or 1
    try:
        s = bytes(out).decode('utf-8', errors='ignore')
    except Exception:
        s = bytes(out).decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _try_rolling_add(data: bytes, start_key: int) -> Optional[str]:
    if not data or len(data) < 3:
        return None
    out = bytearray()
    k = start_key & 255
    for b in data:
        out.append(b + k & 255)
        k = k + 1 & 255 or 1
    try:
        s = bytes(out).decode('utf-8', errors='ignore')
    except Exception:
        s = bytes(out).decode('ascii', errors='ignore')
    if _is_printable_string(s):
        return s
    return None

def _extract_byte_arrays_from_pseudoc(pseudo_c: str) -> List[Tuple[str, bytes]]:
    arrays: List[Tuple[str, bytes]] = []
    pat = re.compile('(?m)^\s*(?:undefined\s+|byte\s+|char\s+|u_char\s+)?(DAT_[0-9A-Fa-f]+|local_[0-9A-Fa-f]+|\w+)\s*\[\s*\d+\s*]\s*=\s*\{([^}]{3,2000})}\s*;')
    for m in pat.finditer(pseudo_c):
        name = m.group(1)
        body = m.group(2)
        vals: List[int] = []
        for tok in re.findall('0x[0-9A-Fa-f]+|\\d+', body):
            try:
                v = int(tok, 16) if tok.lower().startswith('0x') else int(tok, 10)
                vals.append(v & 255)
            except Exception:
                continue
        if len(vals) >= 3:
            arrays.append((name, bytes(vals)))
    return arrays

def _extract_xor_loops(pseudo_c: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    loop_pat = re.compile('(?ms)for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(?P<limit>\d+)\s*;\s*\w+\+\+\s*\)\s*\{(?P<body>[^}]{1,800})}')
    for m in loop_pat.finditer(pseudo_c):
        body = m.group('body')
        xor_m = re.search('\\^\\s*(?:\\(?(?:byte|char|undefined)?\\)?\\s*)?(?:0x[0-9A-Fa-f]+|\\d+)', body)
        if not xor_m:
            continue
        key_m = re.search('\\^\\s*(?:\\(?(?:byte|char|undefined)?\\)?\\s*)?(0x[0-9A-Fa-f]+|\\d+)', body)
        key = None
        if key_m:
            try:
                key = int(key_m.group(1), 16) if key_m.group(1).lower().startswith('0x') else int(key_m.group(1))
            except Exception:
                key = None
        hits.append({'limit': int(m.group('limit')), 'key': key, 'body_snippet': body.strip()[:300]})
    return hits

def _simulate_stack_xor_decrypt(pseudo_c: str) -> List[str]:
    results: List[str] = []
    pat = re.compile('(?ms)for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)\s*;\s*\w+\+\+\s*\)\s*\{[^}]*?\[\w+]\s*=\s*(?:\(?(?:byte|char|undefined)[^)]*\)?\s*)?(DAT_[0-9A-Fa-f]+|\w+)\s*\[\w+]\s*(?P<op>[+\-^])\s*(0x[0-9A-Fa-f]+|\d+)')
    for m in pat.finditer(pseudo_c):
        array_name = m.group(2)
        op = m.group('op')
        key_raw = m.group(4)
        try:
            key = int(key_raw, 16) if key_raw.lower().startswith('0x') else int(key_raw)
        except Exception:
            continue
        init_pat = re.compile('(?ms)' + re.escape(array_name) + r'\\s*\\[\\s*d+]\\s*=\\s*\\{([^} ]+)\\}')
        init_m = init_pat.search(pseudo_c)
        if not init_m:
            continue
        vals: List[int] = []
        for tok in re.findall('0x[0-9A-Fa-f]+|\\d+', init_m.group(1)):
            try:
                vals.append(int(tok, 16) if tok.lower().startswith('0x') else int(tok))
            except Exception:
                pass
        if vals:
            data = bytes((v & 255 for v in vals))
            dec = None
            if op == '^':
                dec = _try_xor_decrypt(data, key)
            elif op == '-':
                dec = _try_rolling_sub(data, key)
            elif op == '+':
                dec = _try_rolling_add(data, key)
            if dec:
                results.append(dec)
    return results

def extract_decrypted_strings(*, pseudo_c_path: Optional[Path]=None, pseudo_c: Optional[str]=None, max_strings: int=500) -> Dict[str, Any]:
    text = pseudo_c or ''
    if pseudo_c_path is not None and pseudo_c_path.is_file() and (not text):
        text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(text) > 2000000:
            text = text[:2000000]
    if not text:
        return {'status': 'SKIPPED_NO_PSEUDO_C'}
    decrypted: List[Dict[str, Any]] = []
    seen = set()

    def add_string(value: str, *, method: str, source: str, key: Optional[int]=None) -> None:
        if not _is_printable_string(value):
            return
        if value in seen:
            return
        seen.add(value)
        decrypted.append({'value': value, 'method': method, 'source': source, 'key': key})
        if len(decrypted) >= max_strings:
            return
    byte_arrays = _extract_byte_arrays_from_pseudoc(text)
    for name, data in byte_arrays:
        best = _best_xor_decrypt(data)
        if best:
            add_string(best[1], method='single_xor', source=name, key=best[0])
        mb = _best_multibyte_xor(data)
        if mb:
            key_bytes, s = mb
            add_string(s, method='multibyte_xor', source=name, key=int.from_bytes(key_bytes[:4], 'little'))
        for key in range(256):
            s = _try_reverse_xor(data, key)
            if s and _english_likeness(s) >= 20:
                add_string(s, method='reverse_xor', source=name, key=key)
                break
        for start_key in range(1, 32):
            s = _try_index_xor(data, start_key)
            if s and _english_likeness(s) >= 20:
                add_string(s, method='index_xor', source=name, key=start_key)
                break
        for start_key in range(1, 32):
            s = _try_rolling_xor(data, start_key)
            if s:
                add_string(s, method='rolling_xor', source=name, key=start_key)
                break
        for start_key in range(1, 32):
            s = _try_rolling_sub(data, start_key)
            if s and _english_likeness(s) >= 20:
                add_string(s, method='rolling_sub', source=name, key=start_key)
                break
        for start_key in range(1, 32):
            s = _try_rolling_add(data, start_key)
            if s and _english_likeness(s) >= 20:
                add_string(s, method='rolling_add', source=name, key=start_key)
                break
    for s in _simulate_stack_xor_decrypt(text):
        add_string(s, method='loop_xor', source='stack_loop')
    xor_loops = _extract_xor_loops(text)
    for lit_m in re.finditer('"([^"\\\\]{3,200})"', text):
        s = lit_m.group(1)
        if _is_printable_string(s) and (not s.startswith('(')) and ('/' not in s):
            add_string(s, method='literal', source='pseudo_c')
    return {'status': 'OK', 'pseudo_c_path': str(pseudo_c_path.resolve()) if pseudo_c_path and pseudo_c_path.is_file() else None, 'strings_total': len(decrypted), 'xor_loops_detected': len(xor_loops), 'byte_arrays_scanned': len(byte_arrays), 'strings': decrypted[:max_strings], 'xor_loops': xor_loops[:50]}
