from typing import Any, Dict, List, Optional

def _sanitize(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '$'):
            out.append(ch)
        else:
            out.append('_')
    s = ''.join(out)
    return s if s and s[0].isalpha() else f'_{s}' if s else 'arg'

def infer_param_names_from_jar_meta(*, jar_meta: Optional[Dict[str, Any]], class_internal: str, method: str, descriptor: Optional[str], param_count: int, is_static: bool=True) -> Optional[List[str]]:
    if not isinstance(jar_meta, dict) or param_count <= 0:
        return None
    cm = jar_meta.get(class_internal)
    if not isinstance(cm, dict):
        return None
    methods_locals = cm.get('methods_locals')
    if not isinstance(methods_locals, dict):
        return None
    if not isinstance(descriptor, str):
        return None
    locals_map = methods_locals.get((method, descriptor))
    if not isinstance(locals_map, dict):
        return None
    offset = 0 if is_static else 1
    names: List[str] = []
    for i in range(param_count):
        li = offset + i
        nm = locals_map.get(li)
        if isinstance(nm, str) and nm:
            names.append(_sanitize(nm))
        else:
            names.append(f'var{i}')
    if all((n == f'var{i}' for i, n in enumerate(names))):
        return None
    return names

def resolve_java_param_names(*, param_types: List[str], class_internal: str, method: str, descriptor: Optional[str], is_static: bool, jar_meta: Optional[Dict[str, Any]]=None, jar_index: Optional[Dict[str, Any]]=None) -> List[str]:
    count = len(param_types)
    default = [f'var{i}' for i in range(count)]
    if method == 'main' and descriptor == '([Ljava/lang/String;)V' and (count == 1):
        default[0] = 'args'
        return default
    from detranspiler.jar.guided import get_jar_param_names
    cfr = get_jar_param_names(jar_index=jar_index, class_internal=class_internal, method=method, descriptor=descriptor)
    if isinstance(cfr, list) and len(cfr) == count:
        return [_sanitize(n) for n in cfr]
    lvt = infer_param_names_from_jar_meta(jar_meta=jar_meta, class_internal=class_internal, method=method, descriptor=descriptor, param_count=count, is_static=is_static)
    if isinstance(lvt, list) and len(lvt) == count:
        return lvt
    return default
