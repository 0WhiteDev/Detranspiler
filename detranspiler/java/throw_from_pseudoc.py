import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from detranspiler.jni.register import _resolve_string_expr

_EXCEPTION_CLASS_RE = (
    r'"(java/(?:[\w$]+/)*[A-Za-z$][\w$]*(?:Exception|Error))"'
)
_THROW_HELPER_RE = re.compile(
    r'FUN_[0-9A-Fa-f]+\(\s*(?:\([^)]*\)\s*)?(?:[\w&*,\s]){0,96}'
    + _EXCEPTION_CLASS_RE
    + r'\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(?:"([^"\n]{1,240})"|((?:&)?DAT_[0-9A-Fa-f]+(?:\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?))\s*,\s*(0x[0-9A-Fa-f]+|\d+)',
    re.DOTALL,
)
_THROW_WRAPPER_RE = re.compile(
    r'FUN_[0-9A-Fa-f]+\(\s*\w+\s*,\s*((?:&)?DAT_[0-9A-Fa-f]+(?:\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
)


def _java_escape(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def _parse_hex_or_int(value: str) -> Optional[int]:
    s = str(value or '').strip().lower()
    try:
        if s.startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None


def _normalize_throw_message(value: str, *, max_len: Optional[int] = None) -> Optional[str]:
    if not isinstance(value, str):
        return None
    msg = value.strip('\x00\r\n\t ')
    if not msg:
        return None
    for sep in ('C:\\Users\\', 'C:/Users/', '\x00', '.rs', '.java'):
        if sep in msg:
            msg = msg.split(sep, 1)[0].strip()
    if max_len is not None and max_len > 0:
        msg = msg[:max_len].strip()
    if len(msg) > 120:
        msg = msg[:120].strip()
    if not re.search(r'[A-Za-z]', msg):
        return None
    if msg.startswith('(') and ')' in msg and '/' in msg:
        return None
    if msg.startswith('java/'):
        return None
    if not re.search(r'[\s/]', msg) and len(msg) > 32:
        return None
    return msg


def _exception_simple_name(internal_or_java: str) -> str:
    name = internal_or_java.replace('/', '.')
    if name.startswith('java.lang.'):
        return name[len('java.lang.') :]
    return name.split('.')[-1]


def _resolve_throw_message(
    expr: str,
    *,
    max_len: Optional[int],
    strings_by_addr: Optional[Dict[int, str]],
    dat_ptr_values: Optional[Dict[str, int]],
    read_string_at_va: Optional[Callable[[int], Optional[str]]],
    var_assigns: Dict[str, str],
) -> Optional[str]:
    raw = str(expr or '').strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return _normalize_throw_message(raw[1:-1], max_len=max_len)
    if not isinstance(strings_by_addr, dict) or not isinstance(dat_ptr_values, dict):
        return None
    value, _meta = _resolve_string_expr(
        raw,
        strings_by_addr=strings_by_addr,
        dat_ptr_values=dat_ptr_values,
        stack_copy_sources={},
        read_string_at_va=read_string_at_va,
        var_assigns=var_assigns,
    )
    if isinstance(value, str):
        return _normalize_throw_message(value, max_len=max_len)
    return None


def _normalize_multiline_c_strings(text: str) -> str:
    if not text:
        return text
    return re.sub(r'"([^"\n]*)\n\s*"', r'"\1"', text)


def _dedupe_throw_lines(lines: List[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for line in lines:
        m = re.search(r'throw new \w+\("([^"]*)"\);', line)
        key = m.group(1)[:48] if m else line
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out


def infer_java_throw_lines_from_pseudoc(
    block: str,
    *,
    strings_by_addr: Optional[Dict[int, str]] = None,
    dat_ptr_values: Optional[Dict[str, int]] = None,
    read_string_at_va: Optional[Callable[[int], Optional[str]]] = None,
    max_lines: int = 12,
) -> Optional[List[str]]:
    if not isinstance(block, str) or not block.strip():
        return None
    block = _normalize_multiline_c_strings(block)
    var_assigns: Dict[str, str] = {}
    for m in re.finditer(r'(?m)^\s*(\w+)\s*=\s*([^;]+);', block):
        var_assigns[m.group(1)] = m.group(2).strip()
    seen: Set[Tuple[str, str]] = set()
    lines: List[str] = []
    for m in _THROW_HELPER_RE.finditer(block):
        cls = m.group(1)
        literal = m.group(3)
        dat_expr = m.group(4)
        raw_len = m.group(5)
        max_len = _parse_hex_or_int(raw_len) if isinstance(raw_len, str) else None
        msg = _normalize_throw_message(literal, max_len=max_len) if isinstance(literal, str) and literal else None
        if msg is None and isinstance(dat_expr, str):
            msg = _resolve_throw_message(
                dat_expr,
                max_len=max_len,
                strings_by_addr=strings_by_addr,
                dat_ptr_values=dat_ptr_values,
                read_string_at_va=read_string_at_va,
                var_assigns=var_assigns,
            )
        if not msg:
            continue
        key = (cls, msg)
        if key in seen:
            continue
        seen.add(key)
        simple = _exception_simple_name(cls)
        lines.append(f'throw new {simple}("{_java_escape(msg)}");')
        if len(lines) >= max_lines:
            break
    if len(lines) < max_lines:
        for m in _THROW_WRAPPER_RE.finditer(block):
            raw_len = m.group(2)
            max_len = _parse_hex_or_int(raw_len) if isinstance(raw_len, str) else None
            msg = _resolve_throw_message(
                m.group(1),
                max_len=max_len,
                strings_by_addr=strings_by_addr,
                dat_ptr_values=dat_ptr_values,
                read_string_at_va=read_string_at_va,
                var_assigns=var_assigns,
            )
            if not msg:
                continue
            key = ('java/lang/IllegalArgumentException', msg)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f'throw new IllegalArgumentException("{_java_escape(msg)}");')
            if len(lines) >= max_lines:
                break
    lines = _dedupe_throw_lines(lines)
    return lines if lines else None
