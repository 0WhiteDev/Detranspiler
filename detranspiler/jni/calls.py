import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.jni.register import _infer_dat_pointer_values, _load_strings_json, _pe_read_c_string, _resolve_string_expr, _split_top_level_args
try:
    from detranspiler.binary.reader import BinaryReader
except Exception:
    BinaryReader = None
from detranspiler.jni.vtable import JNI_INDEX_NAMES, _function_category, decode_jni_offset

def _parse_hex_offset(value: str) -> Optional[int]:
    s = value.strip().lower()
    try:
        if s.startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None

def _unquote_c_string(expr: str) -> Optional[str]:
    s = str(expr or '').strip()
    for _ in range(4):
        m = re.match(r'^\(\s*[A-Za-z_][A-Za-z0-9_\s*]*\s*\)\s*(.+)$', s)
        if not m:
            break
        nxt = m.group(1).strip()
        if not nxt or nxt == s:
            break
        s = nxt
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return None
    body = s[1:-1]
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(body):
            out.append('\\')
            break
        nxt = body[i + 1]
        escapes = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"', '0': '\x00'}
        out.append(escapes.get(nxt, nxt))
        i += 2
    return ''.join(out)
_decode_jni_offset = decode_jni_offset


def _logical_statements(lines: List[str]):
    pending: List[str] = []
    start_line = 0
    depth = 0
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not pending and stripped.startswith('/* FUNCTION '):
            yield line_no, line
            continue
        if pending:
            pending.append(stripped)
        else:
            pending = [line]
            start_line = line_no
        depth += line.count('(') - line.count(')')
        if depth > 0 and ';' not in line:
            continue
        if depth > 0:
            continue
        yield start_line, ' '.join(part.strip() for part in pending)
        pending = []
        depth = 0
    if pending:
        yield start_line, ' '.join(part.strip() for part in pending)

def extract_jni_calls(*, pseudo_c_path: Optional[Path], strings_json_path: Optional[Path]=None, binary_path: Optional[Path]=None, max_calls: int=10000) -> Dict[str, Any]:
    if pseudo_c_path is None or not pseudo_c_path.is_file():
        return {'status': 'SKIPPED_NO_PSEUDO_C'}
    text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
    return extract_jni_calls_from_text(text, pseudo_c_path=str(pseudo_c_path.resolve()), strings_json_path=str(strings_json_path.resolve()) if strings_json_path is not None and strings_json_path.is_file() else None, binary_path=str(binary_path.resolve()) if binary_path is not None and binary_path.is_file() else None, max_calls=max_calls)

def extract_jni_calls_from_text(pseudo_c: str, *, pseudo_c_path: Optional[str]=None, strings_json_path: Optional[str]=None, binary_path: Optional[str]=None, max_calls: int=10000) -> Dict[str, Any]:
    lines = str(pseudo_c or '').splitlines()
    logical_lines = list(_logical_statements(lines))
    strings_by_addr: Dict[int, str] = {}
    image_base = 0
    if isinstance(strings_json_path, str) and strings_json_path:
        sjp = Path(strings_json_path)
        if sjp.is_file():
            strings_by_addr = _load_strings_json(sjp)
            try:
                import json
                sj = json.loads(sjp.read_text(encoding='utf-8', errors='replace'))
                prog = sj.get('program') if isinstance(sj, dict) else None
                if isinstance(prog, dict) and isinstance(prog.get('image_base'), str):
                    ib = prog['image_base'].strip()
                    if ib.lower().startswith('0x'):
                        ib = ib[2:]
                    image_base = int(ib, 16)
            except Exception:
                image_base = 0
    binary_data: Optional[bytes] = None
    if isinstance(binary_path, str) and binary_path:
        bp = Path(binary_path)
        if bp.is_file():
            try:
                binary_data = bp.read_bytes()
            except Exception:
                binary_data = None
    reader = BinaryReader(binary_data, fmt='PE', image_base=image_base) if BinaryReader is not None and binary_data is not None and (image_base > 0) else None
    dat_ptr_values = _infer_dat_pointer_values(lines)

    def read_string_at_va(addr: int) -> Optional[str]:
        if reader is not None:
            return reader.read_c_string(addr)
        if binary_data is not None and image_base > 0:
            return _pe_read_c_string(binary_data, va=addr, image_base=image_base)
        return None
    calls: List[Dict[str, Any]] = []
    counts_by_name: Dict[str, int] = {}
    counts_by_category: Dict[str, int] = {}
    cur_fun_name: Optional[str] = None
    cur_fun_addr: Optional[str] = None
    string_vars: Dict[str, str] = {}
    class_vars: Dict[str, str] = {}
    method_id_vars: Dict[str, Dict[str, Any]] = {}
    var_assigns: Dict[str, str] = {}
    stack_copy_sources: Dict[str, str] = {}
    fnptr_offsets: Dict[str, int] = {}
    fun_header_re = re.compile('/\\* FUNCTION\\s+(\\w+)\\s+([0-9A-Fa-f]+)\\s+\\*/')
    assign_re = re.compile('^\\s*(?P<var>\\w+)\\s*=\\s*(?P<expr>[^;]{1,500});\\s*$')
    stack_copy_re = re.compile(r'^\s*(local_[0-9A-Fa-f]+)\[\d+]\s*=\s*(\w+_[0-9A-Fa-f]+)\[\d+]\s*;\s*$')
    call_re = re.compile('(?:(?P<result>\\w+)\\s*=\\s*)?\\(\\*\\*\\(code\\s+\\*\\*\\)\\(\\*\\s*(?P<env>\\w+)\\s*\\+\\s*(?P<offset>0x[0-9A-Fa-f]+|\\d+)\\)\\)\\s*\\((?P<args>[^;]*)\\)\\s*;', re.IGNORECASE)
    fnptr_load_re = re.compile('^\\*\\(code\\s*\\*\\*\\)\\(\\*\\s*(?P<env>\\w+)\\s*\\+\\s*(?P<offset>0x[0-9A-Fa-f]+|\\d+)\\)$', re.IGNORECASE)
    deferred_call_re = re.compile('(?:(?P<result>\\w+)\\s*=\\s*)?\\(\\*(?P<ptr>[A-Za-z_]\\w*)\\)\\s*\\((?P<args>[^;]*)\\)\\s*;')

    def resolve_string_arg(expr: str) -> Optional[str]:
        literal = _unquote_c_string(expr)
        if isinstance(literal, str):
            return literal
        key = str(expr or '').strip()
        if key in string_vars:
            return string_vars[key]
        val, _meta = _resolve_string_expr(key, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources=stack_copy_sources, read_string_at_va=read_string_at_va, var_assigns=var_assigns)
        if isinstance(val, str) and val:
            return val
        return None

    def record_call(*, offset: int, env_var: str, raw_args: str, result_var: Optional[str], line_no: int, source_line: str) -> None:
        decoded = _decode_jni_offset(offset)
        fn_name = decoded.get('name')
        category = str(decoded.get('category') or 'unknown')
        if isinstance(fn_name, str) and fn_name:
            counts_by_name[fn_name] = counts_by_name.get(fn_name, 0) + 1
        counts_by_category[category] = counts_by_category.get(category, 0) + 1
        args = _split_top_level_args(raw_args)
        resolved: Dict[str, Any] = {}
        if fn_name == 'FindClass' and len(args) >= 2:
            class_name = resolve_string_arg(args[1])
            if isinstance(class_name, str) and class_name:
                resolved['class'] = class_name
                if isinstance(result_var, str) and result_var:
                    class_vars[result_var] = class_name
        if fn_name in {'GetMethodID', 'GetStaticMethodID'} and len(args) >= 4:
            class_expr = args[1]
            class_name = class_vars.get(class_expr)
            method_name = resolve_string_arg(args[2])
            signature = resolve_string_arg(args[3])
            if isinstance(class_name, str) and class_name:
                resolved['class'] = class_name
            if isinstance(method_name, str) and method_name:
                resolved['method'] = method_name
            if isinstance(signature, str) and signature:
                resolved['signature'] = signature
            if isinstance(result_var, str) and result_var:
                method_id_vars[result_var] = {'class': class_name, 'method': method_name, 'signature': signature, 'is_static': fn_name == 'GetStaticMethodID'}
        if isinstance(fn_name, str) and (fn_name.startswith('Call') or fn_name.startswith('NewObject')):
            method_arg_index = 2
            if len(args) > method_arg_index:
                method_info = method_id_vars.get(args[method_arg_index])
                if isinstance(method_info, dict):
                    resolved['target_method'] = method_info
        calls.append({'function': cur_fun_name, 'function_address': cur_fun_addr, 'line': line_no, 'result_var': result_var, 'env_var': env_var, 'offset': hex(offset), 'pointer_size': decoded.get('pointer_size'), 'jni_index': decoded.get('index'), 'jni_name': fn_name, 'category': category, 'args': args[:16], 'args_total': len(args), 'resolved': resolved, 'alternates': decoded.get('alternates') or [], 'source_line': source_line[:500]})
    for line_no, line in logical_lines:
        m_fun = fun_header_re.match(line.strip())
        if m_fun:
            cur_fun_name = m_fun.group(1)
            cur_fun_addr = m_fun.group(2).lower()
            string_vars = {}
            class_vars = {}
            method_id_vars = {}
            var_assigns = {}
            stack_copy_sources = {}
            fnptr_offsets = {}
            continue
        m_stack = stack_copy_re.match(line)
        if m_stack:
            stack_copy_sources.setdefault(m_stack.group(1), m_stack.group(2))
        m_assign = assign_re.match(line)
        if m_assign:
            assign_var = m_assign.group('var')
            assign_expr = m_assign.group('expr').strip()
            var_assigns[assign_var] = assign_expr
            literal = resolve_string_arg(assign_expr)
            if isinstance(literal, str):
                string_vars[assign_var] = literal
            m_load = fnptr_load_re.match(assign_expr)
            if m_load:
                off = _parse_hex_offset(m_load.group('offset'))
                if off is not None:
                    fnptr_offsets[assign_var] = off
            elif assign_var in fnptr_offsets:
                del fnptr_offsets[assign_var]
        for m in call_re.finditer(line):
            offset = _parse_hex_offset(m.group('offset'))
            if offset is None:
                continue
            record_call(offset=offset, env_var=m.group('env'), raw_args=m.group('args'), result_var=m.group('result'), line_no=line_no, source_line=line.strip())
            if len(calls) >= max_calls:
                break
        if len(calls) < max_calls and fnptr_offsets:
            for m in deferred_call_re.finditer(line):
                ptr = m.group('ptr')
                if ptr not in fnptr_offsets:
                    continue
                raw_args = m.group('args')
                env_var = _split_top_level_args(raw_args)[0] if raw_args.strip() else ''
                record_call(offset=fnptr_offsets[ptr], env_var=env_var, raw_args=raw_args, result_var=m.group('result'), line_no=line_no, source_line=line.strip())
                if len(calls) >= max_calls:
                    break
        if len(calls) >= max_calls:
            break
    return {'status': 'OK', 'pseudo_c_path': pseudo_c_path, 'strings_json_path': strings_json_path, 'binary_path': binary_path, 'calls_total': len(calls), 'counts_by_name': dict(sorted(counts_by_name.items())), 'counts_by_category': dict(sorted(counts_by_category.items())), 'functions': _summarize_calls_by_function(calls), 'calls': calls, 'truncated': len(calls) >= max_calls}

def _summarize_calls_by_function(calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for call in calls:
        if not isinstance(call, dict):
            continue
        key = str(call.get('function') or '<unknown>')
        item = grouped.get(key)
        if item is None:
            item = {'function': call.get('function'), 'function_address': call.get('function_address'), 'calls_total': 0, 'categories': {}, 'classes': [], 'methods': []}
            grouped[key] = item
        item['calls_total'] += 1
        category = str(call.get('category') or 'unknown')
        cats = item['categories']
        cats[category] = int(cats.get(category, 0)) + 1
        resolved = call.get('resolved')
        if not isinstance(resolved, dict):
            continue
        cls = resolved.get('class')
        if isinstance(cls, str) and cls and (cls not in item['classes']):
            item['classes'].append(cls)
        target = resolved.get('target_method')
        if isinstance(target, dict):
            method_item = {'class': target.get('class'), 'method': target.get('method'), 'signature': target.get('signature'), 'is_static': target.get('is_static'), 'call': call.get('jni_name'), 'line': call.get('line')}
            if method_item not in item['methods']:
                item['methods'].append(method_item)
            tcls = target.get('class')
            if isinstance(tcls, str) and tcls and (tcls not in item['classes']):
                item['classes'].append(tcls)
    out = list(grouped.values())
    out.sort(key=lambda x: str(x.get('function') or ''))
    return out
