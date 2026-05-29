from typing import List

def _sanitize_java_identifier(name: str) -> str:
    out: List[str] = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '$'):
            out.append(ch)
        else:
            out.append('_')
    ident = ''.join(out)
    if not ident:
        ident = '_'
    first = ident[0]
    if not (first.isalpha() or first in ('_', '$')):
        ident = '_' + ident
    return ident
