import re
import struct
from typing import Callable, Dict, List, Optional, Set, Tuple
from detranspiler.jni.register import _resolve_string_expr

def _infer_simple_java_return(block: str, *, param_map: Dict[str, str], ret_java: Optional[str]=None, java_param_names: Optional[List[str]]=None, strings_by_addr: Optional[Dict[int, str]]=None, dat_ptr_values: Optional[Dict[str, int]]=None, read_string_at_va: Optional[Callable[[int], Optional[str]]]=None, read_u64_at_va: Optional[Callable[[int], Optional[int]]]=None) -> Optional[str]:
    if not block:
        return None

    def clean_expr(expr: str) -> str:
        e = expr.strip()
        e = re.sub('\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\*?\\s*\\)', '', e)
        e = re.sub('\\s+', ' ', e).strip()
        return e

    def _parse_addr_suffix(sym: str) -> Optional[int]:
        m = re.search('(?:^|\\b)(?:DAT|FUN|LAB|s)_([0-9A-Fa-f]{6,})(?:$|\\b)', sym)
        if not m:
            return None
        try:
            return int(m.group(1), 16)
        except Exception:
            return None
    if java_param_names is None:
        try:
            java_param_names = list(param_map.values())
        except Exception:
            java_param_names = []
    if (ret_java or '').strip() == 'double' and read_u64_at_va is not None:
        m_ret = re.search('\\breturn\\s+CONCAT44\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*\\)\\s*;', block)
        if m_ret is not None:
            hi_var = m_ret.group(1)
            lo_var = m_ret.group(2)
            lo_addr = None
            hi_addr = None
            for m2 in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*\\(undefined4\\)\\s*(DAT_[0-9A-Fa-f]+)\\s*;\\s*$', block):
                if m2.group(1) == lo_var:
                    lo_addr = _parse_addr_suffix(m2.group(2))
            for m2 in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*\\(undefined4\\)\\s*\\(\\(ulonglong\\)\\s*(DAT_[0-9A-Fa-f]+)\\s*>>\\s*0x20\\)\\s*;\\s*$', block):
                if m2.group(1) == hi_var:
                    hi_addr = _parse_addr_suffix(m2.group(2))
            if lo_addr is not None and hi_addr is not None and (lo_addr == hi_addr):
                bits = read_u64_at_va(lo_addr)
                if isinstance(bits, int):
                    try:
                        dv = struct.unpack('<d', struct.pack('<Q', bits & 18446744073709551615))[0]
                    except Exception:
                        dv = None
                    if isinstance(dv, float):
                        if abs(dv - 3.141592653589793) < 1e-12:
                            return 'Math.PI'
                        if abs(dv - 2.718281828459045) < 1e-12:
                            return 'Math.E'
    if (ret_java or '').strip() == 'double' and isinstance(strings_by_addr, dict) and isinstance(dat_ptr_values, dict):
        flat_ws = re.sub('\\s+', ' ', block).strip()
        var_assigns_for_resolve: Dict[str, str] = {}
        for m in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*([^;]{1,240});', block):
            var = m.group(1)
            rhs = m.group(2).strip()
            if isinstance(var, str) and var and isinstance(rhs, str) and rhs:
                var_assigns_for_resolve[var] = clean_expr(rhs)
        get_static_mid_re = re.compile('\\b(\\w+)\\s*=\\s*\\(\\*\\*\\(code\\s*\\*\\*\\)\\(\\*\\w+\\s*\\+\\s*0x388\\)\\)\\s*\\(\\s*\\w+\\s*,\\s*([^,]+)\\s*,\\s*([^,]+)\\s*,\\s*([^)]+?)\\s*\\)\\s*;', flags=re.IGNORECASE)
        math_method = None
        for m in get_static_mid_re.finditer(flat_ws):
            name_expr = clean_expr(m.group(3))
            sig_expr = clean_expr(m.group(4))
            name_val, _ = _resolve_string_expr(name_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources={}, read_string_at_va=read_string_at_va, var_assigns=var_assigns_for_resolve)
            sig_val, _ = _resolve_string_expr(sig_expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources={}, read_string_at_va=read_string_at_va, var_assigns=var_assigns_for_resolve)
            if not isinstance(name_val, str) or not name_val.strip():
                continue
            nm = name_val.strip()
            if nm not in {'abs', 'round', 'max', 'min', 'pow', 'sqrt'}:
                continue
            if isinstance(sig_val, str) and sig_val.strip():
                sv = sig_val.strip()
                if nm in {'abs', 'sqrt'} and sv not in {'(D)D', '(F)F'}:
                    continue
                if nm in {'max', 'min', 'pow'} and sv not in {'(DD)D', '(FF)F'}:
                    continue
                if nm == 'round' and sv not in {'(D)J', '(F)I'}:
                    continue
            math_method = nm
            break
        if isinstance(math_method, str) and math_method:
            args = list(java_param_names or [])
            if math_method in {'abs', 'round', 'sqrt'} and len(args) >= 1:
                return f'Math.{math_method}({args[0]})'
            if math_method in {'max', 'min', 'pow'} and len(args) >= 2:
                return f'Math.{math_method}({args[0]}, {args[1]})'

    def is_const_int(expr: str) -> bool:
        e = clean_expr(expr)
        return re.match('^[+-]?(?:0x[0-9A-Fa-f]+|\\d+)(?:[uUlL]+)?$', e) is not None

    def is_simple_expr(expr: str) -> bool:
        e = clean_expr(expr)
        if not e:
            return False

        def _has_unary_deref(st: str) -> bool:
            for mm in re.finditer('\\*', st):
                i = mm.start()
                j = i - 1
                while j >= 0 and st[j].isspace():
                    j -= 1
                prev = st[j] if j >= 0 else ''
                k = i + 1
                while k < len(st) and st[k].isspace():
                    k += 1
                nxt = st[k] if k < len(st) else ''
                if (nxt.isalpha() or nxt == '_') and (not (prev.isalnum() or prev == '_' or prev == ')')):
                    return True
            return False
        if '->' in e or '[' in e or ']' in e:
            return False
        if re.search('\\b[A-Za-z_][A-Za-z0-9_]*\\s*\\(', e):
            return False
        if re.search('(?<![\w)])\*\s*\(', e):
            return False
        if _has_unary_deref(e):
            return False
        if re.search('(?<![\w)])&\s*[A-Za-z_][A-Za-z0-9_]*', e):
            return False
        if re.match('^[A-Za-z0-9_\\s+\\-*/%&|^~!<>=()?:\'\\"\\\\]+$', e) is None:
            return False
        return True
    assigns_all: Dict[str, List[str]] = {}
    for m in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*([^;]+);', block):
        var = m.group(1)
        rhs = m.group(2)
        if not isinstance(var, str) or not var:
            continue
        if not is_simple_expr(rhs):
            continue
        assigns_all.setdefault(var, []).append(clean_expr(rhs))

    def assign_score(rhs: str) -> int:
        e = clean_expr(rhs)
        if is_const_int(e):
            return 0
        params = set(re.findall('\\bparam_\\d+\\b', e))
        if params:
            return 8 + min(6, len(params))
        if re.search('(==|!=|<=|>=|<|>|&&|\\|\\||!)', e):
            return 5
        if re.search('[+\\-*/%]', e):
            return 4
        return 2

    def best_assign(var: str) -> Optional[str]:
        vs = assigns_all.get(var)
        if not isinstance(vs, list) or not vs:
            return None
        return max(vs, key=assign_score)
    assigns: Dict[str, str] = {}
    for v in assigns_all.keys():
        ba = best_assign(v)
        if isinstance(ba, str) and ba:
            assigns[v] = ba
    flat = ' '.join((line.strip() for line in block.splitlines() if line.strip()))
    assign_if_m = re.search('(?P<var>\w+)\s*=\s*(?P<b>[^;]+);\s*if\s*\((?P<cond>[^)]+)\)\s*\{?\s*(?P=var)\s*=\s*(?P<a>[^;]+);\s*}?[\s\S]{0,3000}?return\s+(?P=var);', flat)
    if_else_assign_m = re.search('if\s*\((?P<cond>[^)]+)\)\s*\{?\s*(?P<var>\w+)\s*=\s*(?P<a>[^;]+);\s*}?\s*else\s*\{?\s*(?P=var)\s*=\s*(?P<b>[^;]+);\s*}?[\s\S]{0,3000}?return\s+(?P=var);', flat)
    cond_m = re.search('if\s*\((?P<cond>[^)]+)\)\s*\{?\s*return\s+(?P<a>[^;]+);\s*}?\s*return\s+(?P<b>[^;]+);', flat)
    returns: List[str] = []
    if assign_if_m is not None:
        var = assign_if_m.group('var')
        cond = assign_if_m.group('cond')
        a = assign_if_m.group('a')
        b = assign_if_m.group('b')
        if is_simple_expr(cond) and is_simple_expr(a) and is_simple_expr(b):
            returns.append(f'({clean_expr(cond)}) ? ({clean_expr(a)}) : ({clean_expr(b)})')
    if if_else_assign_m is not None:
        cond = if_else_assign_m.group('cond')
        a = if_else_assign_m.group('a')
        b = if_else_assign_m.group('b')
        if is_simple_expr(cond) and is_simple_expr(a) and is_simple_expr(b):
            returns.append(f'({clean_expr(cond)}) ? ({clean_expr(a)}) : ({clean_expr(b)})')
    if cond_m is not None:
        cond = cond_m.group('cond')
        a = cond_m.group('a')
        b = cond_m.group('b')
        if is_simple_expr(cond) and is_simple_expr(a) and is_simple_expr(b):
            returns.append(f'({clean_expr(cond)}) ? ({clean_expr(a)}) : ({clean_expr(b)})')
    for m in re.finditer('\\breturn\\s+([^;]+);', block):
        returns.append(m.group(1).strip())
    if not returns:
        if assigns:
            returns = list(assigns.keys())
        else:
            return None
    non_const_returns = [r for r in returns if not is_const_int(r)]
    if non_const_returns:
        returns = non_const_returns

    def score(expr: str) -> int:
        e = clean_expr(expr)
        if not e:
            return -10
        if is_const_int(e):
            return 0
        s = 0
        params = set(re.findall('\\bparam_\\d+\\b', e))
        s += 10 * len(params)
        if '?' in e and ':' in e:
            s += 4
        s += min(10, len(re.findall('(==|!=|<=|>=|<|>|&&|\\|\\|)', e)) * 2)
        s += min(8, len(re.findall('[+\\-*/%&|^]', e)))
        if e in assigns:
            rhs = assigns[e]
            rhs_params = set(re.findall('\\bparam_\\d+\\b', rhs))
            s += 5 * len(rhs_params)
            if not is_const_int(rhs):
                s += 2
        if re.match('^[A-Za-z_][A-Za-z0-9_]*$', e):
            s -= 1
        return s
    allowed_expr_re = re.compile('^[A-Za-z0-9_\\s+\\-*/%&|^~!<>=()?:\'\\"\\\\]+$')

    def _extract_identifiers(expr: str) -> List[str]:
        tmp = re.sub('(?<![A-Za-z0-9_])[+-]?(?:0x[0-9A-Fa-f]+|\\d+)(?:[uUlL]+)?(?![A-Za-z0-9_])', '0', expr)
        return re.findall('\\b[A-Za-z_][A-Za-z0-9_]*\\b', tmp)

    def finalize_candidate(expr: str) -> Optional[str]:
        ret_expr = clean_expr(expr)
        ba = best_assign(ret_expr)
        if ba is not None:
            ret_expr = ba
        for _ in range(6):
            changed = False
            for var, rhs in assigns.items():
                if re.search(f'\\b{re.escape(var)}\\b', ret_expr):
                    ret_expr = re.sub(f'\\b{re.escape(var)}\\b', f'({rhs})', ret_expr)
                    changed = True
            if not changed:
                break
        for c_var, j_var in param_map.items():
            ret_expr = re.sub(f'\\b{re.escape(c_var)}\\b', j_var, ret_expr)
        ret_expr = clean_expr(ret_expr)
        if not ret_expr:
            return None
        if allowed_expr_re.match(ret_expr) is None:
            return None
        allowed_names = set(param_map.values()) | {'true', 'false', 'null'}
        names = set(_extract_identifiers(ret_expr))
        if not names.issubset(allowed_names):
            return None
        return ret_expr
    safe: List[Tuple[str, str]] = []
    for r in returns:
        fr = finalize_candidate(r)
        if isinstance(fr, str) and fr:
            safe.append((r, fr))
    if not safe:
        return None
    best_raw, ret_expr = max(safe, key=lambda t: score(t[0]))
    rj = (ret_java or '').strip()
    if rj == 'boolean':
        if ret_expr in ('0', 'false'):
            return 'false'
        if ret_expr in ('1', 'true'):
            return 'true'
        m = re.match('^\\((?P<cond>.+)\\)\\s*\\?\\s*\\((?P<a>.+)\\)\\s*:\\s*\\((?P<b>.+)\\)$', ret_expr)
        if m is not None:
            cond = m.group('cond').strip()
            a = m.group('a').strip()
            b = m.group('b').strip()
            if a == '1' and b == '0':
                return cond
            if a == '0' and b == '1':
                return f'!({cond})'
        if re.search('(==|!=|<=|>=|<|>|&&|\\|\\||!)', ret_expr):
            return ret_expr
        return f'({ret_expr}) != 0'
    if allowed_expr_re.match(ret_expr) is None:
        return None
    return ret_expr
