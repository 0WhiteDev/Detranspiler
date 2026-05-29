import re
from typing import Dict, List, Optional

def _clean_expr(expr: str) -> str:
    e = expr.strip()
    e = re.sub('\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\*?\\s*\\)', '', e)
    return re.sub('\\s+', ' ', e).strip()

def _map_params(expr: str, param_map: Dict[str, str]) -> str:
    out = expr
    for c_var, j_var in sorted(param_map.items(), key=lambda x: -len(x[0])):
        out = re.sub(f'\\b{re.escape(c_var)}\\b', j_var, out)
    return out

def _is_simple_compare_expr(expr: str) -> bool:
    e = _clean_expr(expr)
    if not e or len(e) > 60:
        return False
    if re.search('[;\[\]*\->&]', e):
        return False
    return bool(re.search('(==|!=|<=|>=|<|>)', e))

def _infer_if_else_return(block: str, *, param_map: Dict[str, str], ret_java: str) -> Optional[str]:
    flat = re.sub('\\s+', ' ', block)
    m = re.search('if\s*\((?P<cond>[^)]+)\)\s*\{?\s*return\s+(?P<a>[^;]+);\s*}?\s*(?:else\s*\{?\s*)?return\s+(?P<b>[^;]+);', flat)
    if not m:
        return None
    cond = _clean_expr(m.group('cond'))
    a = _clean_expr(m.group('a'))
    b = _clean_expr(m.group('b'))
    if not (_is_simple_compare_expr(cond) or re.match('^[A-Za-z0-9_\\s]+$', cond)):
        return None
    cond = _map_params(cond, param_map)
    a = _map_params(a, param_map)
    b = _map_params(b, param_map)
    if ret_java == 'boolean':
        if a in ('1', 'true') and b in ('0', 'false'):
            return cond
        if a in ('0', 'false') and b in ('1', 'true'):
            return f'!({cond})'
    return f'({cond}) ? ({a}) : ({b})'

def _infer_switch_return(block: str, *, param_map: Dict[str, str]) -> Optional[str]:
    m = re.search('switch\s*\(\s*(?P<var>\w+)\s*\)\s*\{(?P<body>.*)}', block, re.DOTALL)
    if not m:
        return None
    var = m.group('var')
    jvar = param_map.get(var, var)
    cases: List[str] = []
    for cm in re.finditer('case\\s+(?P<val>0x[0-9A-Fa-f]+|\\d+)\\s*:\\s*return\\s+(?P<ret>[^;]+);', m.group('body')):
        val = cm.group('val')
        ret = _map_params(_clean_expr(cm.group('ret')), param_map)
        cases.append(f'case {val}: return {ret};')
    if len(cases) >= 2:
        return f'switch ({jvar}) {{' + ' '.join(cases[:8]) + '}}'
    return None

def _infer_string_equals_branch(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    return None

def _infer_exception_throw(block: str) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('puts\\s*\\(\\s*"([^"]*(?:exception|error|fail)[^"]*)"\\s*\\)', block, re.IGNORECASE):
        lines.append(f'System.err.println("{m.group(1)}");')
    if lines:
        return lines[:6]
    return None

def _infer_printf_format(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('printf\\s*\\(\\s*"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"\\s*(?:,\\s*(?P<args>[^)]+))?\\s*\\)', block):
        fmt = m.group(1)
        args_raw = m.group('args')
        if args_raw:
            args = [_map_params(_clean_expr(a.strip()), param_map) for a in args_raw.split(',') if a.strip()]
            if args:
                lines.append(f'''System.out.printf("{fmt}", {', '.join(args)});''')
                continue
        lines.append(f'System.out.print("{fmt}");')
    return lines if lines else None

def _infer_strcmp_return(block: str, *, param_map: Dict[str, str], ret_java: str) -> Optional[str]:
    if ret_java != 'boolean':
        return None
    flat = re.sub('\\s+', ' ', block)
    m = re.search('return\\s+(?:\\(\\s*)?strcmp\\s*\\(\\s*(?P<a>[^,]+)\\s*,\\s*(?P<b>[^)]+)\\)\\s*(?:==\\s*0|\\)\\s*==\\s*0)', flat)
    if not m:
        m = re.search('return\\s+(?:\\(\\s*)?0\\s*==\\s*strcmp\\s*\\(\\s*(?P<a>[^,]+)\\s*,\\s*(?P<b>[^)]+)\\)', flat)
    if not m:
        return None
    a = _map_params(_clean_expr(m.group('a')), param_map)
    b = _map_params(_clean_expr(m.group('b')), param_map)
    if a.startswith('"') and b.startswith('"'):
        return f'{a}.equals({b})'
    return f'Objects.equals(String.valueOf({a}), String.valueOf({b}))'

def _infer_for_loop_print(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    return None

def _infer_null_guard(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('if\\s*\\(\\s*(?P<var>\\w+)\\s*==\\s*(?:NULL|nullptr|0)\\s*\\)\\s*(?:return\\s*(?P<ret>[^;]+);|throw)', block):
        var = _map_params(m.group('var'), param_map)
        ret = m.group('ret')
        if ret:
            ret = _map_params(_clean_expr(ret.strip()), param_map)
            lines.append(f'if ({var} == null) {{ return {ret}; }}')
        else:
            lines.append(f'if ({var} == null) {{ throw new NullPointerException(); }}')
    return lines if lines else None

def _infer_while_loop_hint(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    return None

def _infer_array_index_access(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    return None

def _infer_simple_switch(block: str, *, param_map: Dict[str, str], ret_java: str) -> Optional[List[str]]:
    if 'while (true)' in block.lower():
        return None
    m = re.search('switch\\s*\\(\\s*(?P<var>\\w+)\\s*\\)\\s*\\{(?P<body>.*)\\}', block, re.DOTALL)
    if not m:
        return None
    jvar = param_map.get(m.group('var'), m.group('var'))
    case_lines: List[str] = []
    for cm in re.finditer('case\\s+(0x[0-9A-Fa-f]+|\\d+)\\s*:(?:.*?)(?:puts|printf)\\s*\\(\\s*\\"([^\\"\\\\]*(?:\\\\.[^\\"\\\\]*)*)\\"', m.group('body'), re.DOTALL):
        val = cm.group(1)
        msg = cm.group(2)
        if ret_java == 'void':
            case_lines.append(f'case {val}: System.out.println("{msg}"); break;')
        else:
            case_lines.append(f'case {val}: return {val}; break;')
    if len(case_lines) < 2:
        return None
    return [f'switch ({jvar}) {{', *[f'    {c}' for c in case_lines], '}']

def _infer_strcmp_puts_branches(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('if\\s*\\(\\s*strcmp\\s*\\(\\s*(?P<var>[^,]+)\\s*,\\s*"(?P<lit>[^"\\\\]*(?:\\\\.[^"\\\\]*)*)"\\s*\\)\\s*==\\s*0\\s*\\)\\s*\\{[^}]*(?:puts|printf)\\s*\\(\\s*"(?P<msg>[^"\\\\]*(?:\\\\.[^"\\\\]*)*)"', block, re.DOTALL):
        var = _map_params(_clean_expr(m.group('var')), param_map)
        lit = m.group('lit')
        msg = m.group('msg')
        lines.append(f'if ({var}.equals("{lit}")) {{ System.out.println("{msg}"); }}')
    return lines if lines else None

def _infer_memcmp_guard(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('if\\s*\\(\\s*memcmp\\s*\\(\\s*(?P<a>[^,]+)\\s*,\\s*(?P<b>[^,]+)\\s*,\\s*(?P<n>[^)]+)\\)\\s*(!=?\\s*0)?\\s*\\)\\s*(?:return\\s*(?P<ret>[^;]+);|throw)', block):
        a = _map_params(_clean_expr(m.group('a')), param_map)
        b = _map_params(_clean_expr(m.group('b')), param_map)
        n = _map_params(_clean_expr(m.group('n')), param_map)
        ret = m.group('ret')
        if ret:
            ret = _map_params(_clean_expr(ret.strip()), param_map)
            lines.append(f'if (!java.util.Arrays.equals({a}, 0, {n}, {b}, 0, {n})) {{ return {ret}; }}')
        else:
            lines.append(f'if (!java.util.Arrays.equals({a}, 0, {n}, {b}, 0, {n})) {{ throw new IllegalArgumentException(); }}')
    return lines if lines else None

def _infer_strncmp_guard(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('if\\s*\\(\\s*strncmp\\s*\\(\\s*(?P<a>[^,]+)\\s*,\\s*(?P<b>[^,]+)\\s*,\\s*(?P<n>[^)]+)\\)\\s*(!=?\\s*0)?\\s*\\)\\s*(?:return\\s*(?P<ret>[^;]+);|throw)', block):
        a = _map_params(_clean_expr(m.group('a')), param_map)
        b = _map_params(_clean_expr(m.group('b')), param_map)
        ret = m.group('ret')
        if ret:
            ret = _map_params(_clean_expr(ret.strip()), param_map)
            lines.append(f'if (!{a}.startsWith({b})) {{ return {ret}; }}')
        else:
            lines.append(f'if (!{a}.startsWith({b})) {{ throw new IllegalArgumentException(); }}')
    return lines if lines else None

def _infer_early_return_void(block: str, *, param_map: Dict[str, str]) -> Optional[List[str]]:
    lines: List[str] = []
    for m in re.finditer('if\\s*\\(\\s*(?P<cond>[^)]+)\\s*\\)\\s*(?:return\\s*;|\\{\\s*return\\s*;\\s*\\})', block):
        cond = _map_params(_clean_expr(m.group('cond')), param_map)
        if len(cond) <= 80:
            lines.append(f'if ({cond}) {{return;}} ')
    return lines if lines else None

def infer_java_lines_from_pseudoc(block: str, *, param_map: Optional[Dict[str, str]]=None, ret_java: str='void') -> Optional[List[str]]:
    if not block or not block.strip():
        return None
    param_map = dict(param_map or {})
    out: List[str] = []
    pending_return: Optional[str] = None
    if ret_java != 'void':
        sw = _infer_switch_return(block, param_map=param_map)
        if sw:
            out.append(sw)
        else:
            pending_return = _infer_if_else_return(block, param_map=param_map, ret_java=ret_java)
            if pending_return is None:
                pending_return = _infer_strcmp_return(block, param_map=param_map, ret_java=ret_java)
    for infer in (lambda: _infer_simple_switch(block, param_map=param_map, ret_java=ret_java), lambda: _infer_printf_format(block, param_map=param_map), lambda: _infer_for_loop_print(block, param_map=param_map), lambda: _infer_while_loop_hint(block, param_map=param_map), lambda: _infer_array_index_access(block, param_map=param_map), lambda: _infer_null_guard(block, param_map=param_map), lambda: _infer_strcmp_puts_branches(block, param_map=param_map), lambda: _infer_strncmp_guard(block, param_map=param_map), lambda: _infer_memcmp_guard(block, param_map=param_map), lambda: _infer_early_return_void(block, param_map=param_map) if ret_java == 'void' else None):
        extra = infer()
        if extra:
            out.extend(extra)
    branches = _infer_string_equals_branch(block, param_map=param_map)
    if branches:
        out.extend(branches)
    throws = _infer_exception_throw(block)
    if throws:
        out.extend(throws)
    if pending_return and ret_java != 'void':
        if not any((ln.strip().startswith('return ') for ln in out)):
            out.append(f'return {pending_return};')
    return out if out else None

def infer_java_return_from_pseudoc(block: str, *, param_map: Optional[Dict[str, str]]=None, ret_java: str='void') -> Optional[str]:
    lines = infer_java_lines_from_pseudoc(block, param_map=param_map, ret_java=ret_java)
    if not lines or ret_java == 'void':
        return None
    for line in lines:
        s = line.strip()
        if s.startswith('return '):
            return s[len('return '):].rstrip(';')
    return None
