import json
import re
import struct
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from detranspiler.jni.vtable import ENV_VTABLE_CALL, decode_jni_offset, is_jni_offset
try:
    from detranspiler.binary.reader import BinaryReader
except Exception:
    BinaryReader = None

def _split_top_level_args(arg_str: str) -> List[str]:
    args: List[str] = []
    cur: List[str] = []
    depth = 0
    in_str = False
    esc = False
    for ch in arg_str:
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
            continue
        if ch == '(':
            depth += 1
            cur.append(ch)
            continue
        if ch == ')':
            if depth > 0:
                depth -= 1
            cur.append(ch)
            continue
        if ch == ',' and depth == 0:
            s = ''.join(cur).strip()
            if s:
                args.append(s)
            cur = []
            continue
        cur.append(ch)
    tail = ''.join(cur).strip()
    if tail:
        args.append(tail)
    return args

def _parse_int_literal(s: str) -> Optional[int]:
    s = s.strip()
    s = s.rstrip('uUlL')
    if not s:
        return None
    try:
        if s.lower().startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None

def _parse_addr_suffix(sym: str) -> Optional[int]:
    m = re.search('_([0-9A-Fa-f]{6,})$', sym)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None

def _normalize_addr_string(addr: str) -> Optional[int]:
    if not addr:
        return None
    a = addr.strip()
    if a.lower().startswith('0x'):
        a = a[2:]
    a = a.strip()
    a = a.lstrip('0') or '0'
    try:
        return int(a, 16)
    except Exception:
        return None

def _load_strings_json(path: Path) -> Dict[int, str]:
    try:
        obj = json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return {}
    out: Dict[int, str] = {}
    strings = obj.get('strings')
    if not isinstance(strings, list):
        return {}
    for it in strings:
        if not isinstance(it, dict):
            continue
        addr_raw = it.get('address')
        val = it.get('value')
        if not isinstance(addr_raw, str) or not isinstance(val, str):
            continue
        addr = _normalize_addr_string(addr_raw)
        if addr is None:
            continue
        if addr not in out:
            out[addr] = val
    return out

def _infer_dat_pointer_values(lines: List[str]) -> Dict[str, int]:
    fun_returns: Dict[str, int] = {}
    fun_name = None
    buf: List[str] = []

    def flush() -> None:
        nonlocal fun_name, buf
        if not fun_name:
            buf = []
            return
        block = '\n'.join(buf)
        m = re.search('\\breturn\\s+&DAT_([0-9A-Fa-f]+)\\s*;', block)
        if m:
            try:
                fun_returns[fun_name] = int(m.group(1), 16)
            except Exception:
                pass
        else:
            m = re.search('\\breturn\\s+(?:&)?(?:s|u|DAT)_[A-Za-z0-9_]*_([0-9A-Fa-f]{6,})\\s*;', block)
            if m:
                try:
                    fun_returns[fun_name] = int(m.group(1), 16)
                except Exception:
                    pass
        buf = []
    for line in lines:
        m = re.match('/\\* FUNCTION\\s+(\\w+)\\s+([0-9A-Fa-f]+)\\s+\\*/', line.strip())
        if m:
            flush()
            fun_name = m.group(1)
        if fun_name:
            buf.append(line)
    flush()
    dat_values: Dict[str, int] = {}
    assign_re = re.compile('\\b(DAT_[0-9A-Fa-f]+)\\s*=\\s*(FUN_[0-9A-Fa-f]+)\\(\\)\\s*;')
    for line in lines:
        m = assign_re.search(line)
        if not m:
            continue
        dat = m.group(1)
        fun = m.group(2)
        if fun in fun_returns:
            dat_values[dat] = fun_returns[fun]
    return dat_values

def _pe_rva_to_file_offset(data: bytes, rva: int) -> Optional[int]:
    if len(data) < 256:
        return None
    if data[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, 60)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return None
    file_hdr_off = e_lfanew + 4
    number_of_sections = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
    size_of_optional_header = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
    opt_off = file_hdr_off + 20
    sect_off = opt_off + size_of_optional_header
    if sect_off <= 0 or sect_off > len(data):
        return None
    for i in range(number_of_sections):
        sh = sect_off + i * 40
        if sh + 40 > len(data):
            return None
        virtual_size = struct.unpack_from('<I', data, sh + 8)[0]
        virtual_address = struct.unpack_from('<I', data, sh + 12)[0]
        size_of_raw_data = struct.unpack_from('<I', data, sh + 16)[0]
        pointer_to_raw_data = struct.unpack_from('<I', data, sh + 20)[0]
        span = virtual_size
        if span < size_of_raw_data:
            span = size_of_raw_data
        if span == 0:
            continue
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            off = pointer_to_raw_data + delta
            if 0 <= off < len(data):
                return off
            return None
    return None

def _pe_read_c_string(data: bytes, *, va: int, image_base: int, max_len: int=512) -> Optional[str]:
    if image_base <= 0:
        return None
    if va < image_base:
        return None
    rva = va - image_base
    off = _pe_rva_to_file_offset(data, rva)
    if off is None:
        return None
    end = min(len(data), off + max_len)
    raw = data[off:end]
    nul = raw.find(b'\x00')
    if nul != -1:
        raw = raw[:nul]
    if not raw:
        return None
    try:
        s = raw.decode('ascii', errors='ignore')
    except Exception:
        return None
    s = s.strip()
    if not s:
        return None
    printable = sum((1 for ch in s if 32 <= ord(ch) <= 126))
    if printable < max(1, len(s) // 2):
        return None
    return s

def _pe_pointer_size(data: bytes) -> int:
    if len(data) < 256 or data[:2] != b'MZ':
        return 8
    try:
        e_lfanew = struct.unpack_from('<I', data, 60)[0]
        opt_off = e_lfanew + 4 + 20
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic == 267:
            return 4
        if magic == 523:
            return 8
    except Exception:
        pass
    return 8

def _looks_like_jni_method_name(value: str) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) > 240:
        return False
    if v in {'<init>', '<clinit>'}:
        return True
    return re.fullmatch('[A-Za-z_$][A-Za-z0-9_$]{0,239}', v) is not None

def _looks_like_jni_signature(value: str) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 3 or len(v) > 512:
        return False
    if not (v.startswith('(') and ')' in v):
        return False
    return re.fullmatch('[A-Za-z0-9_$/;\\[\\]()]+', v) is not None

def _extract_static_jni_method_tables(*, binary_data: Optional[bytes], image_base: int, strings_by_addr: Dict[int, str], max_methods: int=4096, binary_fmt: str='PE') -> List[Dict[str, Any]]:
    if not isinstance(binary_data, (bytes, bytearray)) or not binary_data:
        return []
    if image_base <= 0 or not strings_by_addr:
        return []
    data = bytes(binary_data)
    reader = BinaryReader(data, fmt=binary_fmt, image_base=image_base) if BinaryReader else None
    ptr_size = reader.pointer_size if reader else _pe_pointer_size(data)
    stride = ptr_size * 3
    if len(data) < stride:
        return []

    def read_ptr(off: int) -> Optional[int]:
        if off < 0 or off + ptr_size > len(data):
            return None
        try:
            if ptr_size == 4:
                return struct.unpack_from('<I', data, off)[0]
            return struct.unpack_from('<Q', data, off)[0]
        except Exception:
            return None

    def read_known_string(va: int) -> Optional[str]:
        v = strings_by_addr.get(va)
        if isinstance(v, str) and v:
            return v
        if reader is not None:
            return reader.read_c_string(va)
        return _pe_read_c_string(data, va=va, image_base=image_base)

    def va_is_mapped(va: int) -> bool:
        if not isinstance(va, int) or va < image_base:
            return False
        if reader is not None:
            return reader.va_to_offset(va) is not None
        return _pe_rva_to_file_offset(data, va - image_base) is not None

    def candidate_at(off: int) -> Optional[Dict[str, Any]]:
        name_va = read_ptr(off)
        sig_va = read_ptr(off + ptr_size)
        fn_va = read_ptr(off + ptr_size * 2)
        if name_va is None or sig_va is None or fn_va is None:
            return None
        name = read_known_string(name_va)
        sig = read_known_string(sig_va)
        if not (isinstance(name, str) and isinstance(sig, str)):
            return None
        if not _looks_like_jni_method_name(name):
            return None
        if not _looks_like_jni_signature(sig):
            return None
        if not va_is_mapped(fn_va):
            return None
        return {'name': name, 'signature': sig, 'fn_symbol': f'FUN_{fn_va:x}', 'fn_address': f'{fn_va:x}', 'raw': {'table_file_offset': off, 'name_va': f'{name_va:x}', 'signature_va': f'{sig_va:x}', 'fn_va': f'{fn_va:x}', 'pointer_size': ptr_size}}
    groups: List[Dict[str, Any]] = []
    seen_offsets = set()
    step = ptr_size
    off = 0
    while off <= len(data) - stride:
        if off in seen_offsets:
            off += step
            continue
        first = candidate_at(off)
        if first is None:
            off += step
            continue
        methods = [first]
        seen_offsets.add(off)
        nxt = off + stride
        while nxt <= len(data) - stride and len(methods) < 256:
            item = candidate_at(nxt)
            if item is None:
                break
            methods.append(item)
            seen_offsets.add(nxt)
            nxt += stride
        groups.append({'source': 'static_jni_method_table', 'table_file_offset': off, 'pointer_size': ptr_size, 'class': None, 'methods': methods, 'methods_parsed': len(methods)})
        if sum((len(g.get('methods') or []) for g in groups)) >= max_methods:
            break
        off = max(nxt, off + step)
    return groups

def _resolve_string_expr(expr: str, *, strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int], stack_copy_sources: Dict[str, str], read_string_at_va: Optional[Callable[[int], Optional[str]]], var_assigns: Optional[Dict[str, str]], depth: int=0) -> Tuple[Optional[str], Dict[str, Any]]:
    global base_var
    meta: Dict[str, Any] = {'expr': expr}
    e = expr.strip()

    def _strip_casts(s: str) -> str:
        out = s.strip()
        for _ in range(6):
            m2 = re.match('^\\(\\s*[A-Za-z_][A-Za-z0-9_\\s\\*]*\\s*\\)\\s*(.+)$', out)
            if not m2:
                break
            out2 = m2.group(1).strip()
            if not out2 or out2 == out:
                break
            out = out2
        return out

    def _parse_int(s: str) -> Optional[int]:
        v = s.strip()
        if not v:
            return None
        if v.lower().startswith('0x'):
            try:
                return int(v, 16)
            except Exception:
                return None
        if re.fullmatch('\\d+', v):
            try:
                return int(v, 10)
            except Exception:
                return None
        return None
    e = _strip_casts(e)
    if depth > 4:
        meta['kind'] = 'max_depth'
        return None, meta
    m = re.match('\\b(DAT_[0-9A-Fa-f]+)\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)\\b', e)
    if m:
        dat = m.group(1)
        off_raw = m.group(2)
        off = int(off_raw, 16) if off_raw.lower().startswith('0x') else int(off_raw, 10)
        base = dat_ptr_values.get(dat)
        meta['kind'] = 'dat_plus_off'
        meta['dat'] = dat
        meta['off'] = f'{off:x}'
        if base is not None:
            addr2 = base + off
            meta['address'] = f'{addr2:x}'
            val = strings_by_addr.get(addr2)
            if val is not None:
                return val, meta
            if read_string_at_va is not None:
                v2 = read_string_at_va(addr2)
                if v2 is not None:
                    return v2, meta
        return None, meta
    m = re.fullmatch('\\b(DAT_[0-9A-Fa-f]+)\\b', e)
    if m:
        dat = m.group(1)
        base = dat_ptr_values.get(dat)
        meta['kind'] = 'dat'
        meta['dat'] = dat
        if base is not None:
            meta['address'] = f'{base:x}'
            val = strings_by_addr.get(base)
            if val is not None:
                return val, meta
            if read_string_at_va is not None:
                v2 = read_string_at_va(base)
                if v2 is not None:
                    return v2, meta
        return None, meta
    if re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', e) and var_assigns is not None:
        base_expr = var_assigns.get(e)
        if isinstance(base_expr, str) and base_expr.strip() and (base_expr.strip() != expr):
            meta['kind'] = 'var'
            meta['var'] = e
            val, meta2 = _resolve_string_expr(base_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=var_assigns, depth=depth + 1)
            meta['resolved'] = meta2
            return val, meta
    m = re.match('\\b(\\w+)\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)\\b', e)
    if m and var_assigns is not None:
        base_var = m.group(1)
        off_raw = m.group(2)
        if base_var.startswith('DAT_'):
            m = None
    if m and var_assigns is not None:
        base_expr = var_assigns.get(base_var)
        if isinstance(base_expr, str) and base_expr.strip() and (base_expr.strip() != e):
            meta['kind'] = 'var_plus_off'
            meta['var'] = base_var
            meta['off_raw'] = off_raw
            combined = f'{base_expr} + {off_raw}'
            val, meta2 = _resolve_string_expr(combined, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=var_assigns, depth=depth + 1)
            meta['resolved'] = meta2
            return val, meta
    if len(e) >= 2 and e[0] == '"' and (e[-1] == '"'):
        meta['kind'] = 'literal'
        return e[1:-1], meta
    m = re.fullmatch('0x[0-9A-Fa-f]+|\\d+', e)
    if m:
        addr0 = _parse_int(e)
        if addr0 is not None:
            meta['kind'] = 'address_const'
            meta['address'] = f'{addr0:x}'
            val = strings_by_addr.get(addr0)
            if val is not None:
                return val, meta
            if read_string_at_va is not None:
                v2 = read_string_at_va(addr0)
                if v2 is not None:
                    return v2, meta
        return None, meta
    m = re.match('\\b(0x[0-9A-Fa-f]+|\\d+)\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+)\\b', e)
    if m:
        base = _parse_int(m.group(1))
        off = _parse_int(m.group(2))
        if base is not None and off is not None:
            addr0 = base + off
            meta['kind'] = 'const_plus_off'
            meta['base'] = f'{base:x}'
            meta['off'] = f'{off:x}'
            meta['address'] = f'{addr0:x}'
            val = strings_by_addr.get(addr0)
            if val is not None:
                return val, meta
            if read_string_at_va is not None:
                v2 = read_string_at_va(addr0)
                if v2 is not None:
                    return v2, meta
        return None, meta
    if e in stack_copy_sources:
        src = stack_copy_sources[e]
        meta['kind'] = 'stack_copy'
        meta['source_symbol'] = src
        addr = _parse_addr_suffix(src)
        if addr is not None:
            meta['source_address'] = f'{addr:x}'
            val = strings_by_addr.get(addr)
            if val is not None:
                return val, meta
            if read_string_at_va is not None:
                v2 = read_string_at_va(addr)
                if v2 is not None:
                    return v2, meta
        return None, meta
    addr = _parse_addr_suffix(e)
    if addr is not None:
        meta['kind'] = 'symbol_addr_suffix'
        meta['address'] = f'{addr:x}'
        val = strings_by_addr.get(addr)
        if val is not None:
            return val, meta
        if read_string_at_va is not None:
            v2 = read_string_at_va(addr)
            if v2 is not None:
                return v2, meta
        return None, meta
    meta['kind'] = 'unknown'
    return None, meta

def _parse_fun_ptr(expr: str) -> Tuple[Optional[str], Optional[str]]:
    m = re.search('\\b(FUN|LAB)_([0-9A-Fa-f]+)\\b', expr)
    if not m:
        return None, None
    sym = f'{m.group(1)}_{m.group(2)}'
    return sym, m.group(2).lower()

def _parse_local_off(var: str) -> Optional[int]:
    m = re.match('local_([0-9A-Fa-f]+)$', var)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None

def extract_jni_register(*, pseudo_c_path: Optional[Path], strings_json_path: Optional[Path], binary_path: Optional[Path]=None, binary_fmt: str='PE') -> Dict[str, Any]:
    strings_by_addr: Dict[int, str] = {}
    if strings_json_path is not None and strings_json_path.is_file():
        strings_by_addr = _load_strings_json(strings_json_path)
    image_base = 0
    if strings_json_path is not None and strings_json_path.is_file():
        try:
            sj = json.loads(strings_json_path.read_text(encoding='utf-8', errors='replace'))
            prog = sj.get('program') if isinstance(sj, dict) else None
            if isinstance(prog, dict) and isinstance(prog.get('image_base'), str):
                ib = _normalize_addr_string(prog.get('image_base'))
                if ib is not None:
                    image_base = ib
        except Exception:
            image_base = 0
    binary_data: Optional[bytes] = None
    if binary_path is not None and binary_path.is_file():
        try:
            binary_data = binary_path.read_bytes()
        except Exception:
            binary_data = None
    static_tables = _extract_static_jni_method_tables(binary_data=binary_data, image_base=image_base, strings_by_addr=strings_by_addr, binary_fmt=binary_fmt)
    if pseudo_c_path is None or not pseudo_c_path.is_file():
        static_methods_total = sum((len(t.get('methods') or []) for t in static_tables))
        if static_tables:
            return {'status': 'OK_STATIC_ONLY', 'pseudo_c_path': None, 'strings_json_path': str(strings_json_path.resolve()) if strings_json_path is not None and strings_json_path.is_file() else None, 'register_calls': [], 'register_calls_total': 0, 'static_method_tables': static_tables, 'static_method_tables_total': len(static_tables), 'static_methods_total': static_methods_total, 'methods_total': static_methods_total}
        return {'status': 'SKIPPED_NO_PSEUDO_C'}

    def read_string_at_va(addr: int) -> Optional[str]:
        if binary_data is None or image_base <= 0:
            return None
        if BinaryReader is not None:
            return BinaryReader(binary_data, fmt=binary_fmt, image_base=image_base).read_c_string(addr)
        return _pe_read_c_string(binary_data, va=addr, image_base=image_base)
    lines = pseudo_c_path.read_text(encoding='utf-8', errors='replace').splitlines()
    dat_ptr_values = _infer_dat_pointer_values(lines)
    cur_fun_name: Optional[str] = None
    cur_fun_addr: Optional[str] = None
    last_assign: Dict[str, str] = {}
    stack_copy_sources: Dict[str, str] = {}
    class_var_to_expr: Dict[str, str] = {}
    last_param4: Optional[int] = None
    results: List[Dict[str, Any]] = []
    fun_header_re = re.compile('/\\* FUNCTION\\s+(\\w+)\\s+([0-9A-Fa-f]+)\\s+\\*/')
    assign_re = re.compile('^\\s*(\\w+)\\s*=\\s*(.+);\\s*$')
    stack_copy_re = re.compile('^\\s*(local_[0-9A-Fa-f]+)\\[\\d+\\]\\s*=\\s*(\\w+_[0-9A-Fa-f]+)\\[\\d+\\]\\s*;\\s*$')
    findclass_re = re.compile(f'^\\s*(?P<var>\\w+)\\s*=\\s*{ENV_VTABLE_CALL}\\(\\w+,\\s*(?P<class_expr>.+)\\)\\s*;\\s*$', re.IGNORECASE)
    register_call_re = re.compile(f'{ENV_VTABLE_CALL}\\((?P<args>[^;]*)\\)\\s*;', re.IGNORECASE)

    def reset_function() -> None:
        nonlocal last_assign, stack_copy_sources, class_var_to_expr, last_param4
        last_assign = {}
        stack_copy_sources = {}
        class_var_to_expr = {}
        last_param4 = None
    for line_no, line in enumerate(lines, start=1):
        m = fun_header_re.match(line.strip())
        if m:
            cur_fun_name = m.group(1)
            cur_fun_addr = m.group(2).lower()
            reset_function()
            continue
        m = stack_copy_re.match(line)
        if m:
            dst = m.group(1)
            src = m.group(2)
            if dst not in stack_copy_sources:
                stack_copy_sources[dst] = src
        m = findclass_re.match(line)
        if m:
            off_raw = m.group('offset')
            try:
                off_val = int(off_raw, 16) if str(off_raw).lower().startswith('0x') else int(off_raw, 10)
            except Exception:
                off_val = -1
            if is_jni_offset(off_val, 'FindClass'):
                var = m.group('var')
                expr = m.group('class_expr').strip()
                class_var_to_expr[var] = expr
        m = assign_re.match(line)
        if m:
            var = m.group(1)
            expr = m.group(2).strip()
            last_assign[var] = expr
            if var == 'param_4':
                v = _parse_int_literal(expr)
                if v is not None:
                    last_param4 = v
        m = register_call_re.search(line)
        if not m:
            continue
        off_raw = m.group('offset')
        try:
            off_val = int(off_raw, 16) if str(off_raw).lower().startswith('0x') else int(off_raw, 10)
        except Exception:
            continue
        if not is_jni_offset(off_val, 'RegisterNatives'):
            continue
        args = _split_top_level_args(m.group('args'))
        if len(args) < 3:
            continue
        env_arg = args[0]
        clazz_arg = args[1]
        table_arg = args[2]
        count_arg = args[3] if len(args) >= 4 else None
        count_val = _parse_int_literal(count_arg) if count_arg else None
        if count_val is None and len(args) == 3:
            count_val = last_param4
        class_expr = class_var_to_expr.get(clazz_arg)
        class_name = None
        class_meta: Dict[str, Any] = {'var': clazz_arg}
        if class_expr:
            class_name, class_meta2 = _resolve_string_expr(class_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=last_assign)
            class_meta.update(class_meta2)
        if class_name is None:
            candidates: List[Tuple[int, str, str]] = []
            start = max(0, line_no - 1 - 40)
            end = min(len(lines), line_no - 1 + 40)
            token_re = re.compile('"[^"]+"|\w+\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)|DAT_[0-9A-Fa-f]+(?:\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?|s_[A-Za-z0-9_]+_[0-9A-Fa-f]+')
            scan_assigns: Dict[str, str] = dict(last_assign)
            for idx in range(start, end):
                l = lines[idx]
                m2 = assign_re.match(l)
                if m2 and idx + 1 > line_no:
                    scan_assigns[m2.group(1)] = m2.group(2).strip()
                for tok in token_re.findall(l):
                    v, _m = _resolve_string_expr(tok, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=scan_assigns)
                    if not v:
                        continue
                    s = str(v)
                    if s.startswith('('):
                        continue
                    if ' ' in s or '\t' in s:
                        continue
                    if '.' in s and s.count('.') >= 2:
                        candidates.append((abs(idx + 1 - line_no), tok, s))
                    elif '/' in s and s.count('/') >= 1:
                        candidates.append((abs(idx + 1 - line_no) + 5, tok, s))
            if candidates:
                candidates.sort(key=lambda t: (t[0], -len(t[2])))
                _dist, tok, s = candidates[0]
                if '/' not in s and '.' in s:
                    s = s.replace('.', '/')
                class_name = s
                class_meta['inferred'] = True
                class_meta['inferred_from_expr'] = tok
                class_meta['inferred_from_window'] = [start + 1, end]
        base_var = table_arg.strip()
        if base_var.startswith('&'):
            base_var = base_var[1:].strip()
        base_off = _parse_local_off(base_var)
        methods: List[Dict[str, Any]] = []
        inferred_count = 0

        def try_add_method(start_off: int) -> bool:
            name_var = f'local_{start_off:x}'
            sig_var = f'local_{start_off - 8:x}'
            fn_var = f'local_{start_off - 16:x}'
            name_expr = last_assign.get(name_var)
            sig_expr = last_assign.get(sig_var)
            fn_expr = last_assign.get(fn_var)
            if name_expr is None or sig_expr is None or fn_expr is None:
                return False
            name, name_meta = _resolve_string_expr(name_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=last_assign)
            sig, sig_meta = _resolve_string_expr(sig_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=last_assign)
            fn_sym, fn_addr = _parse_fun_ptr(fn_expr)
            methods.append({'name': name, 'signature': sig, 'fn_symbol': fn_sym, 'fn_address': fn_addr, 'raw': {'name_var': name_var, 'name_expr': name_expr, 'name_meta': name_meta, 'sig_var': sig_var, 'sig_expr': sig_expr, 'sig_meta': sig_meta, 'fn_var': fn_var, 'fn_expr': fn_expr}})
            return True
        if base_off is not None:
            if count_val is not None and count_val > 0:
                for i in range(count_val):
                    start = base_off - i * 24
                    if try_add_method(start):
                        inferred_count += 1
            else:
                for i in range(0, 128):
                    start = base_off - i * 24
                    if not try_add_method(start):
                        break
                    inferred_count += 1
        results.append({'function': cur_fun_name, 'function_address': cur_fun_addr, 'line': line_no, 'env_arg': env_arg, 'clazz_arg': clazz_arg, 'class': class_name, 'class_raw': class_meta, 'table_arg': table_arg, 'count': count_val, 'methods': methods, 'methods_parsed': inferred_count})
    methods_total = 0
    for r in results:
        methods_total += len(r.get('methods') or [])
    static_methods_total = 0
    for t in static_tables:
        static_methods_total += len(t.get('methods') or [])
    return {'status': 'OK', 'pseudo_c_path': str(pseudo_c_path.resolve()), 'strings_json_path': str(strings_json_path.resolve()) if strings_json_path is not None and strings_json_path.is_file() else None, 'register_calls': results, 'register_calls_total': len(results), 'static_method_tables': static_tables, 'static_method_tables_total': len(static_tables), 'static_methods_total': static_methods_total, 'methods_total': methods_total + static_methods_total}
