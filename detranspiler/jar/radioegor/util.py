import re
from typing import List

_NATIVE_DECL_RE = re.compile('(?P<indent>^[ \\t]*)(?P<mods>(?:(?:public|private|protected|static|final|synchronized|strictfp)\\s+)*)native\\s+(?P<ret>[\\w\\[\\]<>, ?.]+?)\\s+(?P<name>\\w+)\\s*\\((?P<params>[^)]*)\\)(?:\\s+throws\\s+[\\w$.,\\s]+)?\\s*;', re.MULTILINE)

_METHOD_BODY_RE = re.compile('(?:public|private|protected|static|final|native|synchronized|abstract|\\s)+[\\w\\[\\]<>,\\s\\.]+\\s+(?P<name>\\w+)\\s*\\((?P<params>[^)]*)\\)\\s*(?:throws\\s+[\\w\\s,\\.]+)?\\s*\\{')

_NATIVE_JUNK_RE = re.compile('\\b(cVar\\d*|local_[0-9A-Za-z_]+|uVar\\d*|DAT_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+)\\b')

_FIELD_DECL_RE = re.compile('(?m)^\\s*(?:(?:public|private|protected|static|final|transient|volatile)\\s+)*(?P<type>[A-Za-z_$][\\w$]*(?:\\s*<[^;]+>)?(?:\\[\\])?)\\s+(?P<name>[A-Za-z_$][\\w$]*)\\s*(?:=[^;]*)?;')

def _format_body(body: List[str], *, method_indent: str) -> str:
    inner_indent = method_indent + '    '
    out = []
    depth = 0
    for line in body:
        raw = str(line).strip()
        s = raw.strip()
        if not s:
            continue
        if s.startswith('//'):
            continue
        if s.startswith('}'):
            depth = max(0, depth - 1)
        out.append(inner_indent + '    ' * depth + s)
        if s.endswith('{'):
            depth += 1
    return '\n'.join(out)

def _param_names(params_raw: str) -> List[str]:
    names: List[str] = []
    if not params_raw.strip():
        return names
    for part in params_raw.split(','):
        toks = part.strip().split()
        if toks:
            names.append(toks[-1].strip())
    return names

def _class_fields(text: str) -> List[tuple[str, str]]:
    fields: List[tuple[str, str]] = []
    for m in _FIELD_DECL_RE.finditer(text):
        name = m.group('name')
        typ = re.sub('\\s+', ' ', m.group('type')).strip()
        if name in {'serialVersionUID'}:
            continue
        fields.append((name, typ))
    return fields

def _translate_params(body: List[str], source_params: List[str], target_params: List[str]) -> List[str]:
    translated = list(body)
    for src, dst in zip(source_params, target_params):
        if not src or not dst or src == dst:
            continue
        translated = [re.sub(f'\\b{re.escape(src)}\\b', dst, ln) for ln in translated]
    return translated
