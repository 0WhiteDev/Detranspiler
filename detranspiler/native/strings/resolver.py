import re
from typing import Any, Dict, List, Optional, Set

def build_string_symbol_map(*, string_decrypt: Optional[Dict[str, Any]]=None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(string_decrypt, dict):
        return out
    for item in string_decrypt.get('strings') or []:
        if not isinstance(item, dict):
            continue
        source = item.get('source')
        value = item.get('value')
        if isinstance(source, str) and source and isinstance(value, str) and value:
            out[source] = value
    return out

def seeds_from_string_decrypt(*, string_decrypt: Optional[Dict[str, Any]]=None, existing: Optional[List[str]]=None) -> List[str]:
    seen: Set[str] = set(existing or [])
    out: List[str] = list(existing or [])
    if not isinstance(string_decrypt, dict):
        return out
    for item in string_decrypt.get('strings') or []:
        if not isinstance(item, dict):
            continue
        val = item.get('value')
        if isinstance(val, str) and val and (val not in seen):
            seen.add(val)
            out.append(val)
    return out

def resolve_symbol_in_expr(expr: str, symbol_map: Dict[str, str]) -> Optional[str]:
    if not expr or not symbol_map:
        return None
    sym = expr.strip()
    if sym in symbol_map:
        v = symbol_map[sym]
        return f'"{v.replace(chr(92), chr(92) + chr(92)).replace(chr(34), chr(92) + chr(34))}"'
    return None

def substitute_symbols_in_block(block: str, symbol_map: Dict[str, str]) -> str:
    if not block or not symbol_map:
        return block
    out = block
    for sym, val in sorted(symbol_map.items(), key=lambda x: -len(x[0])):
        if not sym or not val:
            continue
        esc = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        lit = f'"{esc}"'
        patterns = [(f'puts\\s*\\(\\s*{re.escape(sym)}\\s*\\)', f'puts({lit})'), (f'printf\\s*\\(\\s*{re.escape(sym)}\\s*,', f'printf({lit},'), (f'NewStringUTF\\s*\\(\\s*[^,]+,\\s*{re.escape(sym)}\\s*\\)', f'NewStringUTF(env, {lit})'), (f'FindClass\\s*\\(\\s*[^,]+,\\s*{re.escape(sym)}\\s*\\)', f'FindClass(env, {lit})'), (f'Get(?:Method|StaticMethod)ID\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*{re.escape(sym)}\\s*,', None)]
        for pat, repl in patterns:
            if repl is not None:
                out = re.sub(pat, repl, out)
    return out
