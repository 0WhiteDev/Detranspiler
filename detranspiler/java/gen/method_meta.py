from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.jar.method_lookup import _jar_infer_unique_method_descriptor, _jar_infer_unique_method_name_by_descriptor

def resolve_register_method(cls: str, mi: int, m: Dict[str, Any], jar_meta: Any) -> Tuple[str, str, Optional[str]]:
    name = m.get('name')
    sig = m.get('signature')
    fn_symbol = m.get('fn_symbol')
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
