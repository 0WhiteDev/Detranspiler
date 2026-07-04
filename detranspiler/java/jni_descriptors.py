import re
from typing import List, Optional, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier

def _jni_descriptor_to_java_type(desc: str) -> Optional[Tuple[str, int]]:
    if not desc:
        return None
    array_dim = 0
    i = 0
    while i < len(desc) and desc[i] == '[':
        array_dim += 1
        i += 1
    if i >= len(desc):
        return None
    ch = desc[i]
    i += 1
    prim = {'V': 'void', 'Z': 'boolean', 'B': 'byte', 'C': 'char', 'S': 'short', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double'}
    if ch in prim:
        t = prim[ch]
        if t == 'void' and array_dim > 0:
            return None
        return t, array_dim
    if ch == 'L':
        semi = desc.find(';', i)
        if semi == -1:
            return None
        internal = desc[i:semi]
        i = semi + 1
        if internal == 'java/lang/String':
            base = 'String'
        elif internal == 'java/lang/Class':
            base = 'Class'
        elif internal.startswith('java/lang/'):
            base = internal.split('/')[-1]
        else:
            base = internal.replace('/', '.')
        return base, array_dim
    return None

def _jni_method_sig_to_java(sig: str) -> Optional[Tuple[str, List[str]]]:
    s = str(sig).strip()
    if not s.startswith('('):
        return None
    close = s.find(')')
    if close == -1:
        return None
    args = s[1:close]
    ret = s[close + 1:]
    params: List[str] = []
    i = 0
    while i < len(args):
        part = args[i:]
        parsed = _jni_descriptor_to_java_type(part)
        if parsed is None:
            return None
        base, arr = parsed
        j = i
        while j < len(args) and args[j] == '[':
            j += 1
        if j >= len(args):
            return None
        if args[j] == 'L':
            semi = args.find(';', j + 1)
            if semi == -1:
                return None
            i = semi + 1
        else:
            i = j + 1
        t = base + '[]' * arr
        params.append(t)
    ret_parsed = _jni_descriptor_to_java_type(ret)
    if ret_parsed is None:
        return None
    ret_base, ret_arr = ret_parsed
    if ret_arr != 0:
        ret_base = ret_base + '[]' * ret_arr
    return ret_base, params

def _jni_parameter_shape(sig: str) -> Optional[Tuple[str, ...]]:
    parsed = _jni_method_sig_to_java(sig)
    if parsed is None:
        return None
    shape: List[str] = []
    for java_type in parsed[1]:
        dimensions = len(java_type) - len(java_type.rstrip('[]'))
        base = java_type[:-dimensions] if dimensions else java_type
        simple = re.split(r'[.$]', base)[-1]
        shape.append(simple + ('[]' * (dimensions // 2)))
    return tuple(shape)

def _internal_class_to_package_and_class(internal: str) -> Tuple[Optional[str], str]:
    s = str(internal).strip().strip('/')
    if not s:
        return None, 'Unknown'
    parts = [p for p in s.split('/') if p]
    if not parts:
        return None, 'Unknown'
    if len(parts) == 1:
        return None, _sanitize_java_identifier(parts[0])
    pkg = '.'.join((_sanitize_java_identifier(p) for p in parts[:-1]))
    cls = _sanitize_java_identifier(parts[-1])
    return pkg, cls
