from typing import Any, Dict, List, Optional


def _jar_infer_unique_method_descriptor(jar_meta: Optional[Dict[str, Any]], *, internal_class: str, method_name: str) -> Optional[str]:
    if not isinstance(jar_meta, dict) or not jar_meta:
        return None
    if not isinstance(internal_class, str) or not internal_class:
        return None
    if not isinstance(method_name, str) or not method_name:
        return None
    cm = jar_meta.get(internal_class)
    if not isinstance(cm, dict):
        return None
    mm = cm.get('methods')
    if not isinstance(mm, dict) or not mm:
        return None
    cands: List[str] = []
    for k in mm.keys():
        if not isinstance(k, tuple) or len(k) != 2:
            continue
        n, desc = k
        if n != method_name:
            continue
        if not isinstance(desc, str) or not desc:
            continue
        cands.append(desc)
    if len(cands) == 1:
        return cands[0]
    cands2 = [d for d in cands if d.startswith('(') and ')' in d]
    if len(cands2) == 1:
        return cands2[0]
    return None

def _jar_infer_unique_method_name_by_descriptor(jar_meta: Optional[Dict[str, Any]], *, internal_class: str, method_desc: str) -> Optional[str]:
    if not isinstance(jar_meta, dict) or not jar_meta:
        return None
    if not isinstance(internal_class, str) or not internal_class:
        return None
    if not isinstance(method_desc, str) or not method_desc:
        return None
    cm = jar_meta.get(internal_class)
    if not isinstance(cm, dict):
        return None
    mm = cm.get('methods')
    if not isinstance(mm, dict) or not mm:
        return None
    names: List[str] = []
    for k in mm.keys():
        if not isinstance(k, tuple) or len(k) != 2:
            continue
        n, desc = k
        if not isinstance(n, str) or not n:
            continue
        if desc != method_desc:
            continue
        names.append(n)
    uniq = sorted(set(names))
    if len(uniq) == 1:
        return uniq[0]
    return None

def _jar_find_unique_class_for_method_descriptor(jar_meta: Optional[Dict[str, Any]], *, method_name: str, method_desc: str) -> Optional[str]:
    if not isinstance(jar_meta, dict) or not jar_meta:
        return None
    if not isinstance(method_name, str) or not method_name:
        return None
    if not isinstance(method_desc, str) or not method_desc:
        return None
    classes: List[str] = []
    for cls, cm in jar_meta.items():
        if not isinstance(cls, str) or not isinstance(cm, dict):
            continue
        mm = cm.get('methods')
        if not isinstance(mm, dict):
            continue
        if (method_name, method_desc) in mm:
            classes.append(cls)
    uniq = sorted(set(classes))
    if len(uniq) == 1:
        return uniq[0]
    return None
