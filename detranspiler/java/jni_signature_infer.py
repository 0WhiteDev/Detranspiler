import re
from typing import Callable, List, Optional, Tuple

from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.type_mapping import _ghidra_type_to_java
from detranspiler.jni.register import _resolve_string_expr

_PSEUDOC_JNI_HEADER_RE = re.compile(
    r'\b(void|longlong|ulonglong|undefined4|undefined8|int|char\s*\*|size_t)\s+'
    r'Java_[A-Za-z0-9_$]+(?:__[A-Za-z0-9_$]+)?\s*\(',
    re.MULTILINE,
)


def _pseudoc_c_return_to_java(c_ret: str) -> str:
    t = str(c_ret or '').strip().lower().replace(' ', '')
    if t == 'void':
        return 'void'
    if t in {'longlong', 'ulonglong', 'undefined8', 'size_t'}:
        return 'long'
    if t in {'undefined4', 'int'}:
        return 'int'
    if 'char*' in t:
        return 'void'
    return 'long'


def infer_pseudoc_jni_return_type(block: Optional[str]) -> Optional[str]:
    if not isinstance(block, str) or not block.strip():
        return None
    m = _PSEUDOC_JNI_HEADER_RE.search(block)
    if not m:
        return None
    return _pseudoc_c_return_to_java(m.group(1))


def _block_hints(
    block: str,
    *,
    strings_by_addr: Optional[dict] = None,
    dat_ptr_values: Optional[dict] = None,
    read_string_at_va: Optional[Callable[[int], Optional[str]]] = None,
) -> set:
    hints = set()
    for m in re.finditer(r'"([^"\\]{2,120})"', block):
        msg = m.group(1).strip()
        if msg:
            hints.add(msg.lower())
    if isinstance(strings_by_addr, dict):
        for m in re.finditer(r'(?:&)?DAT_([0-9A-Fa-f]+)', block):
            expr = f'&DAT_{m.group(1)}'
            value, _meta = _resolve_string_expr(
                expr,
                strings_by_addr=strings_by_addr,
                dat_ptr_values=dat_ptr_values if isinstance(dat_ptr_values, dict) else {},
                stack_copy_sources={},
                read_string_at_va=read_string_at_va,
                var_assigns={},
            )
            if isinstance(value, str) and value.strip():
                hints.add(value.strip().lower())
    return hints


def _apply_param_hint(types: List[str], names: List[str], idx: int, java_type: str, java_name: str) -> None:
    if idx < 0 or idx >= len(types):
        return
    types[idx] = java_type
    names[idx] = _sanitize_java_identifier(java_name)


def refine_jni_export_java_signature(
    *,
    block: Optional[str],
    ghidra_ret: str,
    ghidra_params: List[Tuple[str, str]],
    strings_by_addr: Optional[dict] = None,
    dat_ptr_values: Optional[dict] = None,
    read_string_at_va: Optional[Callable[[int], Optional[str]]] = None,
) -> Tuple[str, List[str], List[str]]:
    """Refine Ghidra JNI signature (env + jclass + args) into Java return + arg types/names."""
    java_params = list(ghidra_params[2:]) if len(ghidra_params) > 2 else []
    param_types = [t for t, _n in java_params]
    param_names = [_sanitize_java_identifier(n) for _t, n in java_params]
    if not param_types:
        param_types = []
        param_names = []

    ret_java = _ghidra_type_to_java(ghidra_ret, is_return=True)
    pseudoc_ret = infer_pseudoc_jni_return_type(block)
    if pseudoc_ret is not None:
        if pseudoc_ret == 'void':
            ret_java = 'void'
        elif ret_java in {'long', 'void'} and pseudoc_ret in {'int', 'long'}:
            ret_java = pseudoc_ret

    if not isinstance(block, str) or not block.strip():
        return ret_java, param_types, param_names

    hints = _block_hints(
        block,
        strings_by_addr=strings_by_addr,
        dat_ptr_values=dat_ptr_values,
        read_string_at_va=read_string_at_va,
    )
    hint_blob = ' '.join(hints)

    if any('pattern string' in h for h in hints):
        for idx, t in enumerate(param_types):
            if t == 'long':
                _apply_param_hint(param_types, param_names, idx, 'String', 'pattern')
                break

    long_idxs = [i for i, t in enumerate(param_types) if t == 'long']
    has_handle = any('handle' in h for h in hints)
    has_buffer = any('directbytebuffer' in h or 'direct bytebuffer' in h for h in hints)
    if has_buffer and has_handle and len(long_idxs) >= 2:
        _apply_param_hint(param_types, param_names, long_idxs[0], 'long', 'handle')
        _apply_param_hint(param_types, param_names, long_idxs[1], 'ByteBuffer', 'buffer')
        long_idxs = long_idxs[2:]
    elif has_buffer and len(long_idxs) == 1:
        _apply_param_hint(param_types, param_names, long_idxs[0], 'ByteBuffer', 'buffer')
        long_idxs = []

    if 'offsets.length != lengths.length' in hint_blob or any('offsets array' in h or 'offsets length' in h for h in hints):
        if len(long_idxs) >= 2:
            _apply_param_hint(param_types, param_names, long_idxs[0], 'int[]', 'offsets')
            _apply_param_hint(param_types, param_names, long_idxs[1], 'int[]', 'lengths')
            long_idxs = long_idxs[2:]
        if long_idxs and any('outbits' in h for h in hints):
            _apply_param_hint(param_types, param_names, long_idxs[-1], 'byte[]', 'outBits')

    if has_handle and param_types and param_types[0] == 'long' and param_names[0].startswith('param_'):
        param_names[0] = 'handle'
    elif ret_java == 'void' and len(param_types) == 1 and param_types[0] == 'long':
        param_names[0] = 'handle'

    int_param_idxs = [i for i, p in enumerate(ghidra_params[2:], start=0) if p[0] == 'int']
    if len(int_param_idxs) >= 2 and 'offset/len out of bounds' in hint_blob:
        _apply_param_hint(param_types, param_names, int_param_idxs[0], 'int', 'offset')
        _apply_param_hint(param_types, param_names, int_param_idxs[1], 'int', 'len')

    return ret_java, param_types, param_names
