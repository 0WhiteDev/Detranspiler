from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.jar.method_lookup import _jar_infer_unique_method_descriptor, _jar_infer_unique_method_name_by_descriptor


_ACC_NATIVE = 0x0100


def _jar_native_method_at(jar_meta: Any, class_internal: str, index: int) -> Optional[Tuple[str, str]]:
    if not isinstance(jar_meta, dict) or index < 0:
        return None
    class_meta = jar_meta.get(class_internal)
    methods = class_meta.get('methods') if isinstance(class_meta, dict) else None
    if not isinstance(methods, dict):
        return None
    ordered: List[Tuple[str, str]] = []
    for key, flags in methods.items():
        if not (isinstance(key, tuple) and len(key) == 2 and isinstance(flags, int)):
            continue
        name, descriptor = key
        if flags & _ACC_NATIVE == 0 or name == '$jnicLoader':
            continue
        if isinstance(name, str) and isinstance(descriptor, str):
            ordered.append((name, descriptor))
    return ordered[index] if index < len(ordered) else None

def resolve_register_method(cls: str, mi: int, m: Dict[str, Any], jar_meta: Any) -> Tuple[str, str, Optional[str]]:
    name = m.get('name')
    sig = m.get('signature')
    fn_symbol = m.get('fn_symbol')
    if (not isinstance(name, str) or not name) and (not isinstance(sig, str) or not sig):
        ordered = _jar_native_method_at(jar_meta, cls, mi)
        if ordered is not None:
            name, sig = ordered
    if not isinstance(sig, str) or not sig:
        if isinstance(name, str) and name:
            sig = _jar_infer_unique_method_descriptor(jar_meta, internal_class=cls, method_name=name)
        elif (not isinstance(name, str) or not name) and isinstance(jar_meta, dict):
            sig_main = _jar_infer_unique_method_descriptor(jar_meta, internal_class=cls, method_name='main')
            if isinstance(sig_main, str) and sig_main:
                name = 'main'
                sig = sig_main
    if (not isinstance(name, str) or not name) and isinstance(sig, str) and sig:
        inferred = _jar_infer_unique_method_name_by_descriptor(jar_meta, internal_class=cls, method_desc=sig)
        if isinstance(inferred, str) and inferred:
            name = inferred
        elif sig == '([Ljava/lang/String;)V':
            name = 'main'
    if not isinstance(name, str) or not name:
        if isinstance(fn_symbol, str) and fn_symbol:
            name = f'native_{_sanitize_java_identifier(fn_symbol)}'
        else:
            name = f'native_{mi}'
    if not isinstance(sig, str) or not sig:
        sig = '()V'
    fn = fn_symbol if isinstance(fn_symbol, str) else None
    return (name, sig, fn)

def unique_method_ident(base: str, used: set) -> str:
    ident = _sanitize_java_identifier(base)
    if ident not in used:
        used.add(ident)
        return ident
    suf = 2
    while f'{ident}_{suf}' in used:
        suf += 1
    ident = f'{ident}_{suf}'
    used.add(ident)
    return ident
