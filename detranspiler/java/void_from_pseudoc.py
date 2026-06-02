import re
from typing import Callable, Dict, List, Optional, Set, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.java.throw_from_pseudoc import infer_java_throw_lines_from_pseudoc
from detranspiler.jni.register import _resolve_string_expr

def _infer_simple_java_void_body(block: str, *, param_map: Dict[str, str], strings_by_addr: Optional[Dict[int, str]]=None, dat_ptr_values: Optional[Dict[str, int]]=None, read_string_at_va: Optional[Callable[[int], Optional[str]]]=None, extra_seed_strings: Optional[List[str]]=None, hint_main: bool=False) -> Optional[List[str]]:
    if not block:
        return None
    throws = infer_java_throw_lines_from_pseudoc(
        block,
        strings_by_addr=strings_by_addr,
        dat_ptr_values=dat_ptr_values,
        read_string_at_va=read_string_at_va,
    )
    if throws:
        return throws

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

    def java_escape_string_literal(s: str) -> str:
        out = s.replace('\\', '\\\\')
        out = out.replace('"', '\\"')
        out = out.replace('\r', '\\r')
        out = out.replace('\n', '\\n')
        return out

    def looks_like_descriptor(s: str) -> bool:
        v = s.strip()
        if not v:
            return False
        if v.startswith('(') and ')' in v and re.fullmatch('[A-Za-z0-9_/;\\[\\]()]+', v):
            return True
        if re.match('^L[A-Za-z0-9_/\\$]+;$', v):
            return True
        if re.fullmatch('[A-Za-z0-9_/\\$]+', v) and ('/' in v or v.startswith('java/')):
            return True
        if re.match('^(INVOKE\\w+|ANEWARRAY|NEWARRAY|CHECKCAST|GETFIELD|PUTFIELD|GETSTATIC|PUTSTATIC)\\b', v):
            return True
        if v in {'println', 'format'}:
            return True
        return False

    def should_print_string(s: str) -> bool:
        v = s.strip()
        if not v:
            return False
        if looks_like_descriptor(v):
            return False
        if re.search('\\s', v):
            return True
        if re.search('[\\.!\\?,:;\\-_=+%]', v):
            return True
        return False

    def _extract_identifiers(expr: str) -> List[str]:
        tmp = re.sub('(?<![A-Za-z0-9_])[+-]?(?:0x[0-9A-Fa-f]+|\\d+)(?:[uUlL]+)?(?![A-Za-z0-9_])', '0', expr)
        return re.findall('\\b[A-Za-z_][A-Za-z0-9_]*\\b', tmp)

    def is_simple_arith_expr(expr: str) -> bool:
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
        if re.search('(?<![\\w\\)])\\*\\s*\\(', e):
            return False
        if _has_unary_deref(e):
            return False
        if re.search('(?<![\\w\\)])&\\s*[A-Za-z_][A-Za-z0-9_]*', e):
            return False
        if re.search('(==|!=|<=|>=|<|>|&&|\\|\\||!|\\?|:)', e):
            return False
        if re.match('^[A-Za-z0-9_\\s+\\-*/%()]+$', e) is None:
            return False
        return True

    def is_const_int(expr: str) -> bool:
        e = clean_expr(expr)
        return re.match('^[+-]?(?:0x[0-9A-Fa-f]+|\\d+)(?:[uUlL]+)?$', e) is not None

    def parse_int(expr: str) -> Optional[int]:
        e = clean_expr(expr)
        e = e.rstrip('uUlL')
        if not e:
            return None
        try:
            if e.lower().startswith('0x'):
                return int(e, 16)
            return int(e, 10)
        except Exception:
            return None

    def extract_concat44_low_const(expr: str) -> Optional[str]:
        e = clean_expr(expr)
        m = re.match('^CONCAT44\\(\\s*[^,]+,\\s*([^)]+)\\)\\s*$', e)
        if m is None:
            return None
        rhs = clean_expr(m.group(1))
        if is_const_int(rhs):
            return rhs
        return None
    pre_lines: List[str] = []
    loop_lines: List[str] = []
    assign_lines: List[str] = []
    post_lines: List[str] = []
    flat = ' '.join((line.strip() for line in block.splitlines() if line.strip()))
    loop_var: Optional[str] = None
    loop_m = re.search('\\b(?P<var>iVar\\d+)\\s*=\\s*(?P<start>\\d+)\\s*;(?:(?!/\\* FUNCTION).){0,6000}?while\\(\\s*true\\s*\\)\\s*\\{(?:(?!/\\* FUNCTION).){0,8000}?if\\s*\\(\\s*(?P<limit>\\d+)\\s*<\\s*(?P=var)\\s*\\)\\s*break\\s*;(?:(?!/\\* FUNCTION).){0,8000}?(?P=var)\\s*=\\s*(?P=var)\\s*\\+\\s*1\\s*;', flat, flags=re.IGNORECASE)
    if loop_m is not None:
        loop_var = loop_m.group('var')
    last_assigned: Optional[str] = None
    candidates: List[Tuple[str, str, bool]] = []
    lhs_order: List[str] = []
    seen_lhs = set()
    for m in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*([^;]+);', block):
        lhs = m.group(1)
        rhs_raw = m.group(2)
        if not isinstance(lhs, str) or not lhs:
            continue
        if lhs in seen_lhs:
            continue
        if lhs == loop_var:
            continue
        if lhs.startswith('DAT_'):
            continue
        allow_local = False
        if lhs.startswith('local_'):
            if re.match('^local_[0-9A-Fa-f]+$', lhs) is None:
                continue
            allow_local = True
        if not (lhs.startswith('iVar') or lhs.startswith('uVar') or lhs.startswith('lVar') or allow_local):
            continue
        rhs = clean_expr(rhs_raw)
        if allow_local:
            rhs2 = extract_concat44_low_const(rhs)
            if rhs2 is not None:
                rhs = rhs2
        if not rhs or len(rhs) > 80:
            continue
        if not is_const_int(rhs) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', rhs):
            continue
        if is_const_int(rhs):
            v = parse_int(rhs)
            if v == 0:
                continue
            if allow_local and v == 1:
                continue
        if allow_local and (not is_const_int(rhs)):
            if re.search('\\b(?:CONCAT|SUB|SEXT|ZEXT)\\d*\\b', rhs):
                continue
        if not is_simple_arith_expr(rhs):
            continue
        candidates.append((lhs, rhs, allow_local))
        lhs_order.append(lhs)
        seen_lhs.add(lhs)
    if candidates:
        all_lhs = {lhs for lhs, _rhs, _al in candidates}
        allowed_names = set(param_map.keys()) | all_lhs
        rhs_by_lhs: Dict[str, str] = {}
        deps_by_lhs: Dict[str, set[str]] = {}
        for lhs, rhs, _al in candidates:
            names = set(_extract_identifiers(rhs))
            if not names.issubset(allowed_names):
                continue
            rhs_by_lhs[lhs] = rhs
            deps_by_lhs[lhs] = {n for n in names if n in all_lhs}
        ordered_lhs = [lhs for lhs in lhs_order if lhs in rhs_by_lhs]
        indeg: Dict[str, int] = {lhs: 0 for lhs in ordered_lhs}
        rev: Dict[str, List[str]] = {lhs: [] for lhs in ordered_lhs}
        for lhs in ordered_lhs:
            deps = deps_by_lhs.get(lhs, set())
            indeg[lhs] = len(deps)
            for d in deps:
                if d in rev:
                    rev[d].append(lhs)
        done: List[str] = []
        ready = [lhs for lhs in ordered_lhs if indeg.get(lhs, 0) == 0]
        while ready:
            best = min(ready, key=lambda x: lhs_order.index(x))
            ready.remove(best)
            done.append(best)
            for out_dep in rev.get(best, []):
                indeg[out_dep] = max(0, indeg.get(out_dep, 0) - 1)
                if indeg[out_dep] == 0 and out_dep not in done and (out_dep not in ready):
                    ready.append(out_dep)
        if len(done) < len(ordered_lhs):
            for lhs in ordered_lhs:
                if lhs not in done:
                    done.append(lhs)
        local_name_map: Dict[str, str] = {}
        local_counter = 0
        for lhs in done:
            if lhs.startswith('local_'):
                local_name_map[lhs] = _sanitize_java_identifier(lhs)
            else:
                local_name_map[lhs] = f'v{local_counter}'
                local_counter += 1
        emitted_assigns = 0
        for lhs in done:
            rhs = rhs_by_lhs.get(lhs)
            if not isinstance(rhs, str) or not rhs:
                continue
            for c_var, j_var in param_map.items():
                rhs = re.sub(f'\\b{re.escape(c_var)}\\b', j_var, rhs)
            for c_var, j_var in local_name_map.items():
                rhs = re.sub(f'\\b{re.escape(c_var)}\\b', j_var, rhs)
            java_type = 'int'
            if lhs.startswith('lVar'):
                java_type = 'long'
            jlhs = local_name_map.get(lhs, _sanitize_java_identifier(lhs))
            assign_lines.append(f'{java_type} {jlhs} = {rhs};')
            last_assigned = jlhs
            emitted_assigns += 1
            if emitted_assigns >= 6:
                break
    str_lits: List[str] = []
    for m in re.finditer('"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"', block):
        s = m.group(1)
        if not isinstance(s, str) or not s:
            continue
        s = s.strip('\r\n')
        if not s.strip():
            continue
        if s not in str_lits:
            str_lits.append(s)
        if len(str_lits) >= 12:
            break
    seed_strings: List[str] = []
    for s in str_lits:
        if isinstance(s, str) and s.strip():
            seed_strings.append(s)
    extra_strings: List[str] = []
    if isinstance(extra_seed_strings, list) and extra_seed_strings:
        seen_extra = set()
        for s in extra_seed_strings:
            if not isinstance(s, str):
                continue
            v = s.strip('\r\n')
            if not v.strip():
                continue
            if len(v) > 160:
                continue
            if v in seed_strings:
                continue
            if v in seen_extra:
                continue
            seen_extra.add(v)
            extra_strings.append(v)
            if len(extra_strings) >= (768 if hint_main else 256):
                break
    if isinstance(strings_by_addr, dict) and isinstance(dat_ptr_values, dict) and strings_by_addr:
        var_assigns: Dict[str, str] = {}
        for m in re.finditer('(?m)^\\s*(\\w+)\\s*=\\s*([^;]+);', block):
            var = m.group(1)
            rhs = clean_expr(m.group(2))
            if not isinstance(var, str) or not var:
                continue
            if not isinstance(rhs, str) or not rhs:
                continue
            if len(rhs) > 200:
                continue
            var_assigns[var] = rhs
        cand_exprs: List[str] = []
        for m in re.finditer('\\b(?:DAT_[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]*)\\s*\\+\\s*(?:0x[0-9A-Fa-f]+|\\d+)\\b', block):
            cand_exprs.append(clean_expr(m.group(0)))
        for m in re.finditer('(?:\\(\\s*[A-Za-z_][A-Za-z0-9_\\s\\*]*\\s*\\)\\s*)?(?:0x[0-9A-Fa-f]{6,}|\\d{7,})\\s*\\+\\s*(?:0x[0-9A-Fa-f]+|\\d+)\\b', block):
            cand_exprs.append(clean_expr(m.group(0)))
        for m in re.finditer('\\bDAT_[0-9A-Fa-f]+\\b', block):
            cand_exprs.append(m.group(0))
        for m in re.finditer('\\b0x[0-9A-Fa-f]{6,}\\b', block):
            cand_exprs.append(m.group(0))
        seen_vals = set(seed_strings)
        for expr in cand_exprs:
            val, _meta = _resolve_string_expr(expr, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, stack_copy_sources={}, read_string_at_va=read_string_at_va, var_assigns=var_assigns)
            if not isinstance(val, str) or not val:
                continue
            v = val.strip('\r\n')
            if not v.strip():
                continue
            if len(v) > 160:
                continue
            if not re.search('[A-Za-z]', v):
                continue
            if v in seen_vals:
                continue
            seen_vals.add(v)
            seed_strings.append(v)
            if len(seen_vals) >= 8:
                break
    saw_printstream = any((isinstance(s, str) and ('java/io/PrintStream' in s or 'PrintStream' in s) for s in seed_strings))
    saw_println = any((isinstance(s, str) and s.strip() == 'println' for s in seed_strings))
    saw_format = any((isinstance(s, str) and s.strip() == 'format' for s in seed_strings))
    concat_prefix_candidates: List[str] = []
    for s in seed_strings:
        if not isinstance(s, str):
            continue
        if len(s) > 40:
            continue
        if not s.endswith(' '):
            continue
        if not re.search('[A-Za-z0-9]', s):
            continue
        if looks_like_descriptor(s):
            continue
        concat_prefix_candidates.append(s)
        if len(concat_prefix_candidates) >= 3:
            break
    post_concat_prefix: Optional[str] = None
    if concat_prefix_candidates and isinstance(last_assigned, str):
        post_concat_prefix = concat_prefix_candidates[0]
    loop_concat_prefix: Optional[str] = None
    if loop_m is not None and saw_printstream and saw_println and (post_concat_prefix is None) and concat_prefix_candidates:
        loop_concat_prefix = concat_prefix_candidates[0]
    format_literal: Optional[str] = None
    if saw_printstream and saw_println and saw_format:

        def _format_score_main(x: str) -> Tuple[float, float, int, int, int]:
            letters = sum((ch.isalpha() for ch in x))
            vowels = sum((ch.lower() in 'aeiou' for ch in x if ch.isalpha()))
            vr = vowels / letters if letters else 1.0
            digits = sum((ch.isdigit() for ch in x))
            uniq = len(set(x))
            len_pen = -min(abs(len(x) - 11), abs(len(x) - 12), abs(len(x) - 13))
            return (-digits, -vr, uniq, len_pen, len(x))

        def _format_score_generic(x: str) -> Tuple[int, int, int, int, int]:
            has_percent = 1 if '%' in x else 0
            has_brace = 1 if '{' in x or '}' in x else 0
            punct = sum((1 for ch in x if not ch.isalnum()))
            digits = sum((ch.isdigit() for ch in x))
            return (has_percent, has_brace, punct, len(x), -digits)

        def _format_score_obfuscated(x: str) -> Tuple[float, float, int, int]:
            letters = sum((ch.isalpha() for ch in x))
            vowels = sum((ch.lower() in 'aeiou' for ch in x if ch.isalpha()))
            vr = vowels / letters if letters else 1.0
            digits = sum((ch.isdigit() for ch in x))
            uniq = len(set(x))
            return (-digits, -vr, uniq, len(x))
        score_fn = _format_score_main if hint_main else _format_score_generic
        cands: List[str] = []
        tier1: List[str] = []
        tier2: List[str] = []
        for s in seed_strings + extra_strings:
            if not isinstance(s, str):
                continue
            v = s.strip()
            if not v:
                continue
            if looks_like_descriptor(v):
                continue
            if v in {'out', 'println', 'format'}:
                continue
            if hint_main:
                if v.endswith(' '):
                    continue
                if re.search('\\s', v):
                    continue
            if '/' in v:
                continue
            if len(v) < 6 or len(v) > 120:
                continue
            if not re.search('[A-Za-z]', v):
                continue
            if hint_main:
                vl = v.lower()
                if re.fullmatch('[a-z0-9]{6,80}', vl) is None:
                    continue
                if any((tok in vl for tok in ('invoke', 'reverse', 'throw', 'error', 'exception', 'println', 'format', 'classloader'))):
                    continue
            if not hint_main:
                vl = v.lower()
                if any((tok in vl for tok in ('invoke', 'reverse', 'throw', 'throwable', 'exception', 'classloader'))):
                    continue
                likely = '%' in v or ('{' in v or '}' in v) or bool(re.search('\\s', v)) or bool(re.search('[\\.!\\?,:;\\-_=+%]', v))
                if likely:
                    tier1.append(v)
                else:
                    tier2.append(v)
            else:
                cands.append(v)
        if hint_main:
            if cands:
                format_literal = max(cands, key=score_fn)
        elif tier1:
            format_literal = max(tier1, key=_format_score_generic)
        elif tier2:
            format_literal = max(tier2, key=_format_score_obfuscated)
    if format_literal is not None:
        esc = java_escape_string_literal(format_literal)
        pre_lines.append(f'System.out.println(String.format("{esc}"));')
    used_prefixes = set()
    if isinstance(post_concat_prefix, str) and post_concat_prefix:
        used_prefixes.add(post_concat_prefix)
    if isinstance(loop_concat_prefix, str) and loop_concat_prefix:
        used_prefixes.add(loop_concat_prefix)
    if not hint_main:
        str_i = 0
        for s in seed_strings:
            if not isinstance(s, str) or not s.strip():
                continue
            if looks_like_descriptor(s):
                continue
            if format_literal is not None and s == format_literal:
                continue
            if s in used_prefixes:
                continue
            if loop_concat_prefix is not None and s == loop_concat_prefix:
                continue
            esc = java_escape_string_literal(s)
            if should_print_string(s):
                if re.search('\\b(exception|error|fail)\\b', s, flags=re.IGNORECASE):
                    pre_lines.append(f'System.err.println("{esc}");')
                else:
                    pre_lines.append(f'System.out.println("{esc}");')
            else:
                pre_lines.append(f'final String _s{str_i} = "{esc}";')
                str_i += 1
                if str_i >= 6:
                    break
    if loop_m is not None:
        start = loop_m.group('start')
        limit = loop_m.group('limit')
        loop_lines.append(f'for (int i = {start}; i <= {limit}; i++) {{')
        if saw_printstream and saw_println or hint_main:
            if loop_concat_prefix is not None:
                esc = java_escape_string_literal(loop_concat_prefix)
                loop_lines.append(f'  System.out.println("{esc}" + i);')
            else:
                loop_lines.append('  System.out.println(i);')
        loop_lines.append('}')
    if (post_concat_prefix is not None or hint_main) and loop_m is not None:
        try:
            ta_val = int(loop_m.group('limit'))
        except Exception:
            ta_val = 0
        ne_val: Optional[int] = None
        for mm in re.finditer('\\bCONCAT44\\(\\s*[^,]+,\\s*(0x[0-9A-Fa-f]+|\\d+)\\s*\\)', block):
            v = parse_int(mm.group(1))
            if v is None or v in {0, 1}:
                continue
            if ne_val is None or v > ne_val:
                ne_val = v
        local_const_vals: Dict[str, int] = {}
        for mm in re.finditer('(?m)^\\s*(local_[0-9A-Fa-f]+)\\s*=\\s*(0x[0-9A-Fa-f]+|\\d+)\\s*;', block):
            lhs = mm.group(1)
            v = parse_int(mm.group(2))
            if not isinstance(lhs, str) or not lhs:
                continue
            if v is None or v in {0, 1}:
                continue
            local_const_vals[lhs] = v
        ta_var: Optional[str] = None
        for k, v in local_const_vals.items():
            if v == ta_val:
                ta_var = k
                break
        ne_var: Optional[str] = None
        if ne_val is not None:
            for k, v in local_const_vals.items():
                if v == ne_val:
                    ne_var = k
                    break
        if ne_val is None:
            for k, v in local_const_vals.items():
                if v != ta_val:
                    ne_val = v
                    ne_var = k
                    break
        base_expr: Optional[str] = None
        if ta_var is not None and ne_var is not None:
            mul_re = re.compile('(?P<base>(?:0x[0-9A-Fa-f]+|\\d+))\\s*\\+\\s*(?P<a>local_[0-9A-Fa-f]+)\\s*\\*\\s*(?P<b>local_[0-9A-Fa-f]+)', flags=re.IGNORECASE)
            for mm in re.finditer('(?m)^\\s*(local_[0-9A-Fa-f]+)\\s*=\\s*([^;]+);', block):
                rhs = clean_expr(mm.group(2))
                m2 = mul_re.search(rhs)
                if m2 is None:
                    continue
                a, b = (m2.group('a'), m2.group('b'))
                if {a, b} != {ta_var, ne_var}:
                    continue
                base_expr = clean_expr(m2.group('base'))
                break
        result_val: Optional[int] = None
        for _k, v in local_const_vals.items():
            if result_val is None or v > result_val:
                result_val = v
        if ta_val > 0 and ne_val is not None:
            if base_expr is not None:
                assign_lines = [f'int ta = {ta_val};', f'int ne = {ne_val};', f'int result = {base_expr} + ta * ne;']
                last_assigned = 'result'
            elif result_val is not None:
                base = result_val - ta_val * ne_val
                if base > 0 and base <= 10000:
                    assign_lines = [f'int ta = {ta_val};', f'int ne = {ne_val};', f'int result = {base} + ta * ne;']
                    last_assigned = 'result'
        if hint_main and post_concat_prefix is None and (last_assigned == 'result'):
            post_concat_prefix = 'xx '
    if post_concat_prefix is not None and isinstance(last_assigned, str) and (saw_printstream and saw_println or hint_main):
        esc = java_escape_string_literal(post_concat_prefix)
        post_lines.append(f' System.out.println("{esc}" + {last_assigned});'.strip())
    out_lines: List[str] = []
    out_lines.extend(pre_lines)
    out_lines.extend(loop_lines)
    out_lines.extend(assign_lines)
    out_lines.extend(post_lines)
    if not out_lines:
        return None
    return out_lines
