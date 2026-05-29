import re
from typing import Dict, List, Optional

def _sanitize(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '$'):
            out.append(ch)
        else:
            out.append('_')
    s = ''.join(out)
    return s if s and s[0].isalpha() else f'_{s}' if s else 'arg'

def enrich_param_map_from_block(block: Optional[str], param_map: Dict[str, str]) -> Dict[str, str]:
    if not isinstance(block, str) or not block.strip():
        return dict(param_map)
    out = dict(param_map)
    for m in re.finditer('\\b(local_[0-9A-Fa-f]+|uVar\\d+|iVar\\d+|lVar\\d+|puVar\\d+)\\s*=\\s*(?:\\([^)]+\\)\\s*)?(param_\\d+)\\b', block):
        alias, c_param = (m.group(1), m.group(2))
        if c_param in out:
            out[alias] = out[c_param]
    for m in re.finditer('\\b(param_\\d+)\\s*=\\s*(?:\\([^)]+\\)\\s*)?([A-Za-z_]\\w*)\\s*;', block):
        c_param, rhs = (m.group(1), m.group(2))
        if rhs in {'env', 'NULL', 'null', '0'} or rhs.startswith('DAT_'):
            continue
        if c_param in out and out[c_param].startswith('var'):
            out[c_param] = _sanitize(rhs)
        out[rhs] = out.get(c_param, _sanitize(rhs))
    for m in re.finditer('//\\s*(?P<name>[A-Za-z_]\\w*)\\s*[:=]\\s*(param_\\d+)', block):
        c_param = m.group(2)
        if c_param in out:
            out[c_param] = _sanitize(m.group('name'))
    return out

def enrich_java_param_names_from_block(block: Optional[str], param_names: List[str]) -> List[str]:
    if not isinstance(block, str) or not param_names:
        return param_names
    names = list(param_names)
    sig_m = re.search('FUNCTION\\s+\\w+\\s*\\((?P<args>[^)]*)\\)', block)
    if not sig_m:
        return names
    typed = re.findall('(?:jstring|jint|jlong|jboolean|jobject|jbyteArray|jchar|jshort|jfloat|jdouble)\\s+(\\w+)', sig_m.group('args'))
    java_idx = 0
    for ident in typed:
        if ident in {'env', 'param_1', 'param_2'} or ident.startswith('param_'):
            continue
        if java_idx < len(names):
            names[java_idx] = _sanitize(ident)
            java_idx += 1
    return names
