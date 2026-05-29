import re
from typing import List, Optional

from detranspiler.jar.radioegor.context import _int_literal
from detranspiler.jar.radioegor.util import _format_body

def _split_java_top_level(src: str) -> List[str]:
    units: List[str] = []
    cur: List[str] = []
    depth = 0
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if ch == '/' and nxt == '/':
            j = src.find('\n', i)
            j = n if j == -1 else j
            cur.append(src[i:j])
            i = j
            continue
        if ch == '/' and nxt == '*':
            j = src.find('*/', i + 2)
            j = n if j == -1 else j + 2
            cur.append(src[i:j])
            i = j
            continue
        if ch == '"' or ch == "'":
            quote = ch
            cur.append(ch)
            i += 1
            while i < n:
                c = src[i]
                cur.append(c)
                if c == '\\' and i + 1 < n:
                    cur.append(src[i + 1])
                    i += 2
                    continue
                i += 1
                if c == quote:
                    break
            continue
        cur.append(ch)
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                units.append(''.join(cur))
                cur = []
        elif ch == ';' and depth == 0:
            units.append(''.join(cur))
            cur = []
        i += 1
    tail = ''.join(cur)
    if tail.strip():
        units.append(tail)
    return units

def _split_java_params(params: str) -> List[str]:
    out: List[str] = []
    depth = 0
    cur = ''
    for ch in params:
        if ch in '<([{':
            depth += 1
        elif ch in '>)]}':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            if cur.strip():
                out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out

def _param_type_and_name(param: str) -> Optional[tuple[str, str]]:
    p = re.sub('^\\s*final\\s+', '', param.strip())
    p = re.sub('@[\\w.]+(?:\\([^)]*\\))?\\s*', '', p).strip()
    m = re.match('^(?P<type>.+?)\\s+(?P<name>[A-Za-z_$][\\w$]*)\\s*$', p, re.DOTALL)
    if not m:
        return None
    return (re.sub('\\s+', ' ', m.group('type')).strip(), m.group('name'))

_RECORD_CLASS_RE = re.compile('(?P<indent>^[ \\t]*)(?P<mods>(?:(?:public|protected|private|final|static|abstract)[ \\t]+)*)class[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)[ \\t\\r\\n]*(?P<generics><[^{}]*?>)?[ \\t\\r\\n]*extends[ \\t\\r\\n]+Record\\b[ \\t\\r\\n]*(?P<impl>implements[ \\t][^{]*?)?\\{', re.MULTILINE)

def _match_brace(src: str, open_idx: int) -> Optional[int]:
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if ch == '/' and nxt == '/':
            j = src.find('\n', i)
            i = n if j == -1 else j
            continue
        if ch == '/' and nxt == '*':
            j = src.find('*/', i + 2)
            i = n if j == -1 else j + 2
            continue
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None

def _member_decl_name(member: str) -> tuple[str, Optional[str], str]:
    stripped = member.strip()
    if not stripped:
        return ('other', None, '')
    no_anno = re.sub('^\\s*(?:@[\\w.]+(?:\\([^{}]*\\))?\\s*)+', '', member)
    brace = no_anno.find('{')
    head = no_anno[:brace] if brace != -1 else no_anno
    head_nostr = re.sub('"(?:\\\\.|[^"\\\\])*"', '""', head)
    if re.search('\\b(class|interface|enum|record)\\b', head_nostr) and brace != -1:
        return ('type', _class_decl_name(head_nostr), head.strip())
    has_eq = False
    has_paren = False
    depth = 0
    for ch in head_nostr:
        if depth == 0 and ch == '(':
            has_paren = True
            break
        if depth == 0 and ch == '=':
            has_eq = True
            break
        if ch in '<([':
            depth += 1
        elif ch in '>)]':
            depth = max(0, depth - 1)
    if has_paren and (not has_eq):
        m = re.search('([A-Za-z_$][\\w$]*)\\s*\\(', head_nostr)
        return ('method', m.group(1) if m else None, head.strip())
    declarator = head.strip().rstrip(';')
    if not declarator:
        if brace != -1 and re.fullmatch('\\s*(?:static)?\\s*', head):
            return ('init', None, head.strip())
        return ('other', None, head.strip())
    m = re.search('([A-Za-z_$][\\w$]*)\\s*$', re.split('=', declarator, 1)[0])
    return ('field', m.group(1) if m else None, declarator)

def _method_signature_params(member: str) -> str:
    no_anno = re.sub('^\\s*(?:@[\\w.]+(?:\\([^{}]*\\))?\\s*)+', '', member)
    depth = 0
    start = -1
    for i, ch in enumerate(no_anno):
        if ch == '(':
            if depth == 0 and start == -1:
                start = i + 1
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0 and start != -1:
                return no_anno[start:i]
    return ''

def _method_body(member: str) -> Optional[str]:
    open_idx = member.find('{')
    if open_idx == -1:
        return None
    close_idx = _match_brace(member, open_idx)
    if close_idx is None:
        return None
    return member[open_idx + 1:close_idx]

def _build_record(text: str, header: re.Match[str], open_idx: int, close_idx: int) -> Optional[str]:
    indent = header.group('indent')
    name = header.group('name')
    generics = header.group('generics') or ''
    impl = (header.group('impl') or '').strip()
    inner = text[open_idx + 1:close_idx]
    members = _split_java_top_level(inner)
    ctor: Optional[str] = None
    fields: List[tuple[str, str]] = []
    kept: List[str] = []
    static_or_other = False
    for member in members:
        if not member.strip():
            kept.append(member)
            continue
        kind, mname, head = _member_decl_name(member)
        if kind == 'field':
            if re.search('\\bstatic\\b', head):
                kept.append(member)
                continue
            if mname is None:
                return None
            fields.append((mname, member))
            continue
        if kind == 'method' and mname == name:
            if ctor is not None:
                return None
            ctor = member
            continue
        if kind in {'type', 'init'}:
            kept.append(member)
            continue
        if kind != 'method':
            return None
        kept.append(member)
    if ctor is None or not fields:
        return None
    comps: List[tuple[str, str]] = []
    for raw_param in _split_java_params(_method_signature_params(ctor)):
        tn = _param_type_and_name(raw_param)
        if tn is None:
            return None
        comps.append(tn)
    if not comps:
        return None
    comp_names = [n for _t, n in comps]
    if {n for n, _r in fields} != set(comp_names) or len(comp_names) != len(set(comp_names)):
        return None
    ctor_body = _method_body(ctor)
    if ctor_body is None:
        return None
    compact_stmts: List[str] = []
    for stmt in _split_java_top_level(ctor_body):
        s = stmt.strip()
        if not s:
            continue
        trivial = re.fullmatch('this\\.([A-Za-z_$][\\w$]*)\\s*=\\s*([A-Za-z_$][\\w$]*)\\s*;?', s)
        if trivial and trivial.group(1) == trivial.group(2) and (trivial.group(1) in comp_names):
            continue
        if re.match('this\\.[A-Za-z_$][\\w$]*\\s*=', s):
            return None
        compact_stmts.append(s)
    final_members: List[str] = []
    for member in kept:
        if not member.strip():
            final_members.append(member)
            continue
        kind, mname, _head = _member_decl_name(member)
        if kind != 'method' or mname is None:
            final_members.append(member)
            continue
        params = _method_signature_params(member).strip()
        body = _method_body(member)
        body_norm = re.sub('\\s+', ' ', body).strip() if isinstance(body, str) else None
        is_native = body is None
        if mname in comp_names and (not params):
            if is_native or body_norm in {f'return this.{mname};', f'return {mname};', ''}:
                continue
        if mname == 'toString' and (not params) and (is_native or not body_norm):
            continue
        if mname == 'hashCode' and (not params) and (is_native or not body_norm):
            continue
        if mname == 'equals' and (is_native or not body_norm):
            ptype = _param_type_and_name(params)
            if ptype is not None and re.sub('\\s+', '', ptype[0]) in {'Object', 'java.lang.Object'}:
                continue
        final_members.append(member)
    mods_kept = [tok for tok in re.split('\\s+', header.group('mods').strip()) if tok in {'public', 'protected', 'private', 'static'}]
    mods_str = ' '.join(mods_kept) + ' ' if mods_kept else ''
    impl_str = ' ' + impl if impl else ''
    comp_str = ', '.join((f'{t} {n}' for t, n in comps))
    header_line = f'{indent}{mods_str}record {name}{generics}({comp_str}){impl_str} {{'
    parts: List[str] = []
    if compact_stmts:
        body_fmt = _format_body(compact_stmts, method_indent=indent + '    ')
        parts.append(f'\n{indent}    public {name} {{\n{body_fmt}\n{indent}    }}\n')
    for member in final_members:
        parts.append(member)
    inner_new = ''.join(parts)
    if not inner_new.strip():
        return f'{header_line}\n{indent}}}'
    return f'{header_line}{inner_new}\n{indent}}}'

def _canonicalize_records(text: str) -> str:
    out = text
    search_from = 0
    for _ in range(50):
        m = _RECORD_CLASS_RE.search(out, search_from)
        if not m:
            break
        open_idx = m.end() - 1
        close_idx = _match_brace(out, open_idx)
        if close_idx is None:
            search_from = m.end()
            continue
        try:
            rebuilt = _build_record(out, m, open_idx, close_idx)
        except Exception:
            rebuilt = None
        if rebuilt is None:
            search_from = close_idx + 1
            continue
        rebuilt = re.sub('\\{\\n[ \\t]*\\n', '{\n', rebuilt)
        rebuilt = re.sub('\\n[ \\t]*\\n(?=[ \\t]*\\})', '\n', rebuilt)
        rebuilt = re.sub('\\n{3,}', '\n\n', rebuilt)
        out = out[:m.start()] + rebuilt + out[close_idx + 1:]
        search_from = m.start() + len(rebuilt)
    return out
