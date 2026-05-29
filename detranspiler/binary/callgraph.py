import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

def _load_functions_json(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return None

def _fn_index(functions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by_name: Dict[str, Dict[str, Any]] = {}
    by_entry: Dict[str, Dict[str, Any]] = {}
    for f in functions:
        if not isinstance(f, dict):
            continue
        name = f.get('name')
        entry = f.get('entry')
        if isinstance(name, str) and name:
            by_name[name] = f
        if isinstance(entry, str) and entry:
            by_entry[entry] = f
    return {'by_name': by_name, 'by_entry': by_entry}

def _collect_reachable(start: str, by_name: Dict[str, Dict[str, Any]], *, max_depth: int=6) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    queue: List[tuple[str, int]] = [(start, 0)]
    while queue:
        name, depth = queue.pop(0)
        if name in seen or depth > max_depth:
            continue
        seen.add(name)
        out.append(name)
        fn = by_name.get(name)
        if not isinstance(fn, dict):
            continue
        callees = fn.get('callees')
        if not isinstance(callees, list):
            continue
        for c in callees:
            if isinstance(c, dict):
                cn = c.get('name')
                if isinstance(cn, str) and cn and (cn not in seen):
                    queue.append((cn, depth + 1))
    return out

def analyze_callgraph(*, functions_json_path: Optional[Path], jni_register: Optional[Dict[str, Any]]=None, cfg: Optional[Dict[str, Any]]=None, max_chains: int=100) -> Dict[str, Any]:
    ghidra = _load_functions_json(functions_json_path)
    if ghidra is None:
        return {'status': 'SKIPPED_NO_FUNCTIONS_JSON'}
    functions = ghidra.get('functions')
    if not isinstance(functions, list):
        return {'status': 'SKIPPED_EMPTY'}
    idx = _fn_index(functions)
    by_name = idx['by_name']
    jni_onload = by_name.get('JNI_OnLoad')
    by_name.get('JNI_OnUnload')
    entry_points: List[Dict[str, Any]] = []
    for ep_name in ('JNI_OnLoad', 'JNI_OnUnload', 'DllMain', '_init', 'init'):
        fn = by_name.get(ep_name)
        if isinstance(fn, dict):
            entry_points.append({'name': ep_name, 'entry': fn.get('entry'), 'callees_count': len(fn.get('callees') or [])})
    java_exports: List[Dict[str, Any]] = []
    for name, fn in by_name.items():
        if name.startswith('Java_'):
            callees = fn.get('callees') or []
            java_exports.append({'name': name, 'entry': fn.get('entry'), 'callees': [c.get('name') for c in callees if isinstance(c, dict) and c.get('name')][:20], 'callers': [c.get('name') for c in fn.get('callers') or [] if isinstance(c, dict) and c.get('name')][:10]})
    register_native_fns: Set[str] = set()
    if isinstance(jni_register, dict):
        for call in jni_register.get('register_calls') or []:
            if isinstance(call, dict):
                fn = call.get('function')
                if isinstance(fn, str):
                    register_native_fns.add(fn)
                for m in call.get('methods') or []:
                    if isinstance(m, dict):
                        sym = m.get('fn_symbol')
                        if isinstance(sym, str):
                            register_native_fns.add(sym)
    native_method_chains: List[Dict[str, Any]] = []
    for sym in sorted(register_native_fns):
        if sym in by_name:
            chain = _collect_reachable(sym, by_name)
            native_method_chains.append({'root': sym, 'reachable': chain[:30], 'depth': len(chain)})
    onload_chain: List[str] = []
    if jni_onload is not None:
        onload_chain = _collect_reachable('JNI_OnLoad', by_name, max_depth=8)
    helper_map: List[Dict[str, Any]] = []
    for item in java_exports[:max_chains]:
        root = item.get('name')
        if not isinstance(root, str):
            continue
        callees = item.get('callees') or []
        helpers = [c for c in callees if isinstance(c, str) and c.startswith('FUN_')]
        if helpers:
            helper_map.append({'java_export': root, 'helpers': helpers[:15]})
    edges = ghidra.get('callgraph_edges')
    edges_total = len(edges) if isinstance(edges, list) else 0
    cfg_enriched = 0
    if isinstance(cfg, dict) and cfg.get('status') == 'OK':
        cfg_by_name: Dict[str, str] = {}
        for item in cfg.get('functions_sample') or []:
            if isinstance(item, dict) and isinstance(item.get('name'), str) and isinstance(item.get('addr'), str):
                cfg_by_name[item['name']] = item['addr']
        for fn in functions:
            if not isinstance(fn, dict):
                continue
            nm = fn.get('name')
            if isinstance(nm, str) and nm in cfg_by_name and (not fn.get('entry')):
                fn['entry'] = cfg_by_name[nm]
                cfg_enriched += 1
    return {'status': 'OK', 'functions_json_path': str(functions_json_path.resolve()), 'functions_total': len(functions), 'callgraph_edges_total': edges_total, 'cfg_functions_enriched': cfg_enriched, 'entry_points': entry_points, 'java_exports_total': len(java_exports), 'java_exports': java_exports[:200], 'jni_onload_reachable': onload_chain[:50], 'register_native_functions': sorted(register_native_fns)[:200], 'native_method_chains': native_method_chains[:max_chains], 'java_export_helpers': helper_map[:max_chains]}
