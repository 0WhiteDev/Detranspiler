import re
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.jar.method_lookup import _jar_infer_unique_method_descriptor
_JNIC_LOADER_OVERLOAD = '00024jnicLoader'

def _decode_jnic_overload(raw: str) -> str:
    piece = str(raw or '')
    if piece == _JNIC_LOADER_OVERLOAD or piece.startswith('00024'):
        tail = piece[5:] if piece.startswith('00024') else piece
        return '$' + tail
    return _decode_jni_identifier_piece(piece, slash_for_plain_underscore=True)

def _decode_jni_identifier_piece(piece: str, *, slash_for_plain_underscore: bool=False) -> str:
    out: List[str] = []
    i = 0
    while i < len(piece):
        ch = piece[i]
        if ch != '_':
            out.append(ch)
            i += 1
            continue
        if i + 1 < len(piece):
            nxt = piece[i + 1]
            if nxt == '1':
                out.append('_')
                i += 2
                continue
            if nxt == '2':
                out.append(';')
                i += 2
                continue
            if nxt == '3':
                out.append('[')
                i += 2
                continue
            if nxt == '0' and i + 5 < len(piece):
                raw = piece[i + 2:i + 6]
                if re.fullmatch('[0-9A-Fa-f]{4}', raw):
                    try:
                        out.append(chr(int(raw, 16)))
                        i += 6
                        continue
                    except Exception:
                        pass
        out.append('/' if slash_for_plain_underscore else '_')
        i += 1
    return ''.join(out)

def _split_jni_export_prefix(prefix: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    i = 0
    while i < len(prefix):
        ch = prefix[i]
        if ch == '_' and (not (i + 1 < len(prefix) and prefix[i + 1] in {'0', '1', '2', '3'})):
            parts.append(_decode_jni_identifier_piece(''.join(cur)))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append(_decode_jni_identifier_piece(''.join(cur)))
    return [p for p in parts if p]

def _normalize_jni_export_name(symbol: str) -> Optional[str]:
    s = str(symbol or '').strip()
    if not s:
        return None
    m = re.search('Java_[A-Za-z0-9_$]+(?:__[A-Za-z0-9_$]+)?', s)
    if not m:
        return None
    return m.group(0)

def _parse_jni_export_name(symbol: str, *, jar_meta: Optional[Dict[str, Any]]=None) -> Optional[Dict[str, Any]]:
    normalized = _normalize_jni_export_name(symbol)
    if normalized is None:
        return None
    body = normalized[len('Java_'):]
    overload_raw = None
    if '__' in body:
        prefix_raw, overload_raw = body.split('__', 1)
    else:
        prefix_raw = body
    parts = _split_jni_export_prefix(prefix_raw)
    if overload_raw == _JNIC_LOADER_OVERLOAD or (isinstance(overload_raw, str) and overload_raw.startswith('00024')):
        decoded = _decode_jnic_overload(overload_raw)
        if decoded == '$jnicLoader' and parts:
            return {'symbol': normalized, 'raw_symbol': symbol, 'class': '/'.join(parts), 'method': '$jnicLoader', 'args_descriptor': None, 'descriptor': '()V', 'is_jnic_loader': True}
    if len(parts) < 2:
        return None
    best_class = None
    best_method = None
    best_score = -1
    for split_at in range(1, len(parts)):
        cls = '/'.join(parts[:split_at])
        method = parts[split_at]
        score = 0
        if isinstance(jar_meta, dict):
            cm = jar_meta.get(cls)
            if isinstance(cm, dict):
                score += 10
                mm = cm.get('methods')
                if isinstance(mm, dict):
                    if any((isinstance(k, tuple) and len(k) == 2 and (k[0] == method) for k in mm.keys())):
                        score += 10
        if split_at == len(parts) - 1:
            score += 1
        if score > best_score:
            best_score = score
            best_class = cls
            best_method = method
    if not best_class or not best_method:
        return None
    args_desc = None
    if isinstance(overload_raw, str) and overload_raw:
        args_desc = _decode_jni_identifier_piece(overload_raw, slash_for_plain_underscore=True)
    descriptor = None
    if isinstance(jar_meta, dict):
        cm = jar_meta.get(best_class)
        mm = cm.get('methods') if isinstance(cm, dict) else None
        if isinstance(mm, dict):
            candidates = []
            for k in mm.keys():
                if not (isinstance(k, tuple) and len(k) == 2):
                    continue
                name, desc = k
                if name != best_method or not isinstance(desc, str):
                    continue
                if args_desc is None or desc.startswith(f'({args_desc})'):
                    candidates.append(desc)
            if len(candidates) == 1:
                descriptor = candidates[0]
    if descriptor is None and args_desc is None:
        descriptor = _jar_infer_unique_method_descriptor(jar_meta, internal_class=best_class, method_name=best_method)
    if descriptor is None and args_desc is not None:
        descriptor = f'({args_desc})V'
    return {'symbol': normalized, 'raw_symbol': symbol, 'class': best_class, 'method': best_method, 'args_descriptor': args_desc, 'descriptor': descriptor}
