from __future__ import annotations
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

@dataclass
class GraphNode:
    id: str
    label: str
    kind: str
    group: str = ''
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    kind: str
    label: str = ''

class ReGraph:

    def __init__(self, *, title: str='RE Map', subtitle: str='') -> None:
        self.title = title
        self.subtitle = subtitle
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._edge_keys: Set[Tuple[str, str, str]] = set()
        self._edge_seq = 0

    def upsert_node(self, *, node_id: str, label: str, kind: str, group: str='', meta: Optional[Dict[str, Any]]=None) -> None:
        payload = meta or {}
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = GraphNode(id=node_id, label=label, kind=kind, group=group or kind, meta=dict(payload))
            return
        if payload:
            merged = dict(existing.meta)
            merged.update(payload)
            existing.meta = merged
        if label and len(label) > len(existing.label):
            existing.label = label

    def add_edge(self, *, source: str, target: str, kind: str, label: str='') -> None:
        if not source or not target or source == target:
            return
        key = (source, target, kind)
        if key in self._edge_keys:
            return
        if source not in self.nodes or target not in self.nodes:
            return
        self._edge_keys.add(key)
        self._edge_seq += 1
        self.edges.append(GraphEdge(id=f'e{self._edge_seq}', source=source, target=target, kind=kind, label=label))

    def to_dict(self) -> Dict[str, Any]:
        return {'title': self.title, 'subtitle': self.subtitle, 'nodes': [asdict(n) for n in self.nodes.values()], 'edges': [asdict(e) for e in self.edges], 'stats': {'nodes_total': len(self.nodes), 'edges_total': len(self.edges), 'kinds': _count_by_kind([n.kind for n in self.nodes.values()]), 'edge_kinds': _count_by_kind([e.kind for e in self.edges])}}

def _count_by_kind(items: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        out[item] = out.get(item, 0) + 1
    return out

def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
        return data if isinstance(data, dict) else None
    except Exception:
        return None

def _native_id(name: str) -> str:
    return f'native:{name}'

def _java_method_id(class_internal: str, method: str, descriptor: Optional[str]=None) -> str:
    return f"java:{class_internal}#{method}#{descriptor or '?'}"

def _java_class_id(class_internal: str) -> str:
    return f'jclass:{class_internal}'

def _jni_id(name: str) -> str:
    return f'jni:{name}'

def _java_method_label(class_internal: str, method: str, descriptor: Optional[str]=None) -> str:
    simple = class_internal.rsplit('/', 1)[-1]
    short_desc = descriptor or '()'
    return f'{simple}.{method}{short_desc}'

def _ensure_native(graph: ReGraph, name: str, *, meta: Optional[Dict[str, Any]]=None) -> str:
    node_id = _native_id(name)
    kind = 'entry' if name in {'JNI_OnLoad', 'JNI_OnUnload', 'DllMain'} else 'native_fn'
    if name.startswith('Java_'):
        kind = 'java_export'
    graph.upsert_node(node_id=node_id, label=name, kind=kind, group=kind, meta=meta or {})
    return node_id

def _ensure_java_method(graph: ReGraph, class_internal: str, method: str, descriptor: Optional[str], *, meta: Optional[Dict[str, Any]]=None) -> str:
    node_id = _java_method_id(class_internal, method, descriptor)
    graph.upsert_node(node_id=node_id, label=_java_method_label(class_internal, method, descriptor), kind='java_method', group='java', meta=meta or {})
    cls_id = _java_class_id(class_internal)
    graph.upsert_node(node_id=cls_id, label=class_internal.replace('/', '.'), kind='java_class', group='java', meta={'internal': class_internal})
    graph.add_edge(source=cls_id, target=node_id, kind='declares', label='method')
    return node_id

def _ensure_jni_api(graph: ReGraph, name: str) -> str:
    node_id = _jni_id(name)
    graph.upsert_node(node_id=node_id, label=name, kind='jni_api', group='jni')
    return node_id

def _load_analysis_file(analysis_dir: Path, name: str) -> Optional[Dict[str, Any]]:
    return _read_json(analysis_dir / name)

def _collect_priority_native(*, callgraph: Optional[Dict[str, Any]], jni_register: Optional[Dict[str, Any]], native_index: Optional[Dict[str, Any]]) -> Set[str]:
    names: Set[str] = set()
    if isinstance(callgraph, dict):
        for ep in callgraph.get('entry_points') or []:
            if isinstance(ep, dict) and isinstance(ep.get('name'), str):
                names.add(ep['name'])
        for item in callgraph.get('java_exports') or []:
            if isinstance(item, dict) and isinstance(item.get('name'), str):
                names.add(item['name'])
                for helper in item.get('callees') or []:
                    if isinstance(helper, str):
                        names.add(helper)
        for sym in callgraph.get('register_native_functions') or []:
            if isinstance(sym, str):
                names.add(sym)
        for chain in callgraph.get('native_method_chains') or []:
            if isinstance(chain, dict):
                for sym in chain.get('reachable') or []:
                    if isinstance(sym, str):
                        names.add(sym)
    if isinstance(jni_register, dict):
        for call in jni_register.get('register_calls') or []:
            if not isinstance(call, dict):
                continue
            fn = call.get('function')
            if isinstance(fn, str):
                names.add(fn)
            for m in call.get('methods') or []:
                if isinstance(m, dict) and isinstance(m.get('fn_symbol'), str):
                    names.add(m['fn_symbol'])
    if isinstance(native_index, dict):
        for item in native_index.get('methods') or []:
            if isinstance(item, dict) and isinstance(item.get('fn_symbol'), str):
                names.add(item['fn_symbol'])
    return names

def _trim_graph(graph: ReGraph, *, max_nodes: int) -> None:
    if len(graph.nodes) <= max_nodes:
        return
    keep: Set[str] = set()
    for node in graph.nodes.values():
        if node.kind in {'entry', 'java_export', 'java_method', 'java_class'}:
            keep.add(node.id)
    for edge in graph.edges:
        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if src and src.kind != 'native_fn':
            keep.add(edge.source)
        if tgt and tgt.kind != 'native_fn':
            keep.add(edge.target)
        if edge.kind in {'registers', 'resolves', 'export_bridge'}:
            keep.add(edge.source)
            keep.add(edge.target)
    degree: Dict[str, int] = {node_id: 0 for node_id in graph.nodes}
    for edge in graph.edges:
        if edge.source in degree:
            degree[edge.source] += 1
        if edge.target in degree:
            degree[edge.target] += 1
    natives = [node_id for node_id, node in graph.nodes.items() if node.kind == 'native_fn' and node_id not in keep]
    natives.sort(key=lambda nid: (-degree.get(nid, 0), graph.nodes[nid].label))
    for node_id in natives:
        if len(keep) >= max_nodes:
            break
        keep.add(node_id)
    drop = [node_id for node_id in graph.nodes if node_id not in keep]
    for node_id in drop:
        del graph.nodes[node_id]
    graph.edges = [e for e in graph.edges if e.source in graph.nodes and e.target in graph.nodes]
    graph._edge_keys = {(e.source, e.target, e.kind) for e in graph.edges}

def build_re_graph_from_analysis_dir(analysis_dir: Path, *, job: Optional[Dict[str, Any]]=None, functions_json_path: Optional[Path]=None, max_nodes: int=400) -> ReGraph:
    analysis_dir = analysis_dir.expanduser().resolve()
    title = 'Detranspiler RE Map'
    subtitle = str(analysis_dir)
    if isinstance(job, dict):
        binary = job.get('input')
        if isinstance(binary, str) and binary:
            subtitle = Path(binary).name
    callgraph = _load_analysis_file(analysis_dir, 'callgraph.json')
    jni_register = _load_analysis_file(analysis_dir, 'jni_register.json')
    jni_calls = _load_analysis_file(analysis_dir, 'jni_calls.json')
    native_index = _load_analysis_file(analysis_dir, 'native_index.json')
    from detranspiler.native.index import resolve_native_index
    native_index = resolve_native_index(job=job, analysis_dir=analysis_dir, native_index=native_index)
    method_recovery = _load_analysis_file(analysis_dir, 'method_recovery.json')
    method_confidence = _load_analysis_file(analysis_dir, 'method_confidence.json')
    flattening = _load_analysis_file(analysis_dir, 'flattening.json')
    ghidra_path = functions_json_path
    if ghidra_path is None and isinstance(job, dict):
        artifacts = job.get('artifacts')
        if isinstance(artifacts, dict):
            raw = artifacts.get('ghidra_functions_json')
            if isinstance(raw, str):
                ghidra_path = Path(raw)
    if ghidra_path is None:
        ghidra_path = analysis_dir.parent / 'ghidra' / 'functions.json'
    ghidra = _read_json(ghidra_path) if ghidra_path else None
    graph = ReGraph(title=title, subtitle=subtitle)
    priority_native = _collect_priority_native(callgraph=callgraph, jni_register=jni_register, native_index=native_index)
    recovery_by_key: Dict[str, Dict[str, Any]] = {}
    if isinstance(method_recovery, dict):
        for item in method_recovery.get('methods') or []:
            if not isinstance(item, dict):
                continue
            key = _java_method_id(str(item.get('class') or ''), str(item.get('method') or ''), item.get('descriptor') if isinstance(item.get('descriptor'), str) else None)
            recovery_by_key[key] = item
    confidence_by_key: Dict[str, Dict[str, Any]] = {}
    if isinstance(method_confidence, dict):
        for item in method_confidence.get('methods') or []:
            if not isinstance(item, dict):
                continue
            key = _java_method_id(str(item.get('class') or ''), str(item.get('method') or ''), item.get('descriptor') if isinstance(item.get('descriptor'), str) else None)
            confidence_by_key[key] = item
    flatten_by_native: Dict[str, Dict[str, Any]] = {}
    if isinstance(flattening, dict):
        for item in flattening.get('functions') or []:
            if isinstance(item, dict) and isinstance(item.get('function'), str):
                flatten_by_native[item['function']] = item
    if isinstance(callgraph, dict):
        for ep in callgraph.get('entry_points') or []:
            if isinstance(ep, dict) and isinstance(ep.get('name'), str):
                _ensure_native(graph, ep['name'], meta={'entry': True})
        for item in callgraph.get('java_exports') or []:
            if not isinstance(item, dict):
                continue
            name = item.get('name')
            if not isinstance(name, str):
                continue
            _ensure_native(graph, name, meta={'java_export': True})
            for helper in item.get('callees') or []:
                if isinstance(helper, str):
                    helper_id = _ensure_native(graph, helper)
                    graph.add_edge(source=_native_id(name), target=helper_id, kind='calls', label='export→helper')
        for item in callgraph.get('java_export_helpers') or []:
            if not isinstance(item, dict):
                continue
            export = item.get('java_export')
            if not isinstance(export, str):
                continue
            export_id = _ensure_native(graph, export)
            for helper in item.get('helpers') or []:
                if isinstance(helper, str):
                    helper_id = _ensure_native(graph, helper)
                    graph.add_edge(source=export_id, target=helper_id, kind='export_bridge', label='helper')
    if isinstance(jni_register, dict):
        for call in jni_register.get('register_calls') or []:
            if not isinstance(call, dict):
                continue
            reg_fn = call.get('function')
            reg_fn_id = None
            if isinstance(reg_fn, str):
                reg_fn_id = _ensure_native(graph, reg_fn, meta={'registrar': True})
            cls = call.get('class')
            class_internal = cls.replace('.', '/') if isinstance(cls, str) else None
            for m in call.get('methods') or []:
                if not isinstance(m, dict):
                    continue
                method = m.get('name')
                desc = m.get('signature') if isinstance(m.get('signature'), str) else None
                sym = m.get('fn_symbol')
                if not isinstance(method, str) or not class_internal:
                    continue
                java_id = _ensure_java_method(graph, class_internal, method, desc, meta={'binding': 'register_natives'})
                if isinstance(sym, str):
                    native_id = _ensure_native(graph, sym, meta={'registered': True})
                    graph.add_edge(source=java_id, target=native_id, kind='registers', label='RegisterNatives')
                    if reg_fn_id:
                        graph.add_edge(source=reg_fn_id, target=native_id, kind='registrar', label='reg fn')
    if isinstance(native_index, dict):
        for item in native_index.get('methods') or []:
            if not isinstance(item, dict):
                continue
            cls = item.get('class')
            method = item.get('method')
            desc = item.get('descriptor') if isinstance(item.get('descriptor'), str) else None
            sym = item.get('fn_symbol')
            if not isinstance(cls, str) or not isinstance(method, str):
                continue
            java_id = _ensure_java_method(graph, cls, method, desc, meta={'sources': item.get('sources') or [], 'confidence': item.get('confidence')})
            rec = recovery_by_key.get(java_id)
            if rec:
                node = graph.nodes.get(java_id)
                if node:
                    node.meta['recovery_sources'] = rec.get('sources') or []
                    node.meta['recovery_score'] = rec.get('score')
            conf = confidence_by_key.get(java_id)
            if conf:
                node = graph.nodes.get(java_id)
                if node:
                    node.meta['confidence_level'] = conf.get('level')
            if isinstance(sym, str):
                native_id = _ensure_native(graph, sym)
                graph.add_edge(source=java_id, target=native_id, kind='implements', label='native impl')
    if isinstance(jni_calls, dict):
        for fn_item in jni_calls.get('functions') or []:
            if not isinstance(fn_item, dict):
                continue
            fn = fn_item.get('function')
            if not isinstance(fn, str):
                continue
            native_id = _ensure_native(graph, fn)
            for cls in fn_item.get('classes') or []:
                if isinstance(cls, str):
                    cls_id = _java_class_id(cls.replace('.', '/'))
                    graph.upsert_node(node_id=cls_id, label=cls, kind='java_class', group='java', meta={'internal': cls.replace('.', '/')})
                    graph.add_edge(source=native_id, target=cls_id, kind='resolves', label='FindClass')
            for method in fn_item.get('methods') or []:
                if isinstance(method, str) and '#' in method:
                    cls_part, method_part = method.split('#', 1)
                    java_id = _ensure_java_method(graph, cls_part.replace('.', '/'), method_part, None)
                    graph.add_edge(source=native_id, target=java_id, kind='resolves', label='JNI call')
        for call in jni_calls.get('calls') or []:
            if not isinstance(call, dict):
                continue
            fn = call.get('function')
            jni_name = call.get('jni_name')
            if not isinstance(fn, str) or not isinstance(jni_name, str):
                continue
            native_id = _ensure_native(graph, fn)
            jni_node = _ensure_jni_api(graph, jni_name)
            graph.add_edge(source=native_id, target=jni_node, kind='jni_invoke', label=jni_name)
            resolved = call.get('resolved')
            if isinstance(resolved, dict):
                cls = resolved.get('class')
                method = resolved.get('method')
                if isinstance(cls, str) and isinstance(method, str):
                    java_id = _ensure_java_method(graph, cls.replace('.', '/'), method, resolved.get('signature') if isinstance(resolved.get('signature'), str) else None)
                    graph.add_edge(source=native_id, target=java_id, kind='resolves', label=jni_name)
    if isinstance(ghidra, dict):
        fn_by_name: Dict[str, Dict[str, Any]] = {}
        for fn in ghidra.get('functions') or []:
            if isinstance(fn, dict) and isinstance(fn.get('name'), str):
                fn_by_name[fn['name']] = fn
        for name in priority_native:
            _ensure_native(graph, name, meta=flatten_by_native.get(name) or {})
            fn = fn_by_name.get(name)
            if not isinstance(fn, dict):
                continue
            for callee in fn.get('callees') or []:
                if not isinstance(callee, dict):
                    continue
                callee_name = callee.get('name')
                if not isinstance(callee_name, str):
                    continue
                if callee_name not in priority_native and callee_name.startswith('FUN_'):
                    continue
                src_id = _ensure_native(graph, name)
                tgt_id = _ensure_native(graph, callee_name)
                graph.add_edge(source=src_id, target=tgt_id, kind='calls')
        for edge in ghidra.get('callgraph_edges') or []:
            if not isinstance(edge, dict):
                continue
            src_name = edge.get('from_name')
            tgt_name = edge.get('to_name')
            if not isinstance(src_name, str) or not isinstance(tgt_name, str):
                continue
            if _native_id(src_name) not in graph.nodes:
                if src_name not in priority_native:
                    continue
            if tgt_name not in priority_native and tgt_name.startswith('FUN_'):
                continue
            src_id = _ensure_native(graph, src_name)
            tgt_id = _ensure_native(graph, tgt_name)
            graph.add_edge(source=src_id, target=tgt_id, kind='calls')
    for name, flat in flatten_by_native.items():
        node_id = _native_id(name)
        if node_id in graph.nodes:
            node = graph.nodes[node_id]
            node.meta['flatten_score'] = flat.get('flatten_score')
            node.meta['flatten_level'] = flat.get('recovery_hint')
    _trim_graph(graph, max_nodes=max_nodes)
    return graph

def build_demo_re_graph() -> ReGraph:
    graph = ReGraph(title='Detranspiler RE Map (demo)', subtitle='Sample JNI native library open in browser to explore')
    onload = _ensure_native(graph, 'JNI_OnLoad', meta={'entry': True})
    reg_fn = _ensure_native(graph, 'FUN_register_natives', meta={'registrar': True})
    graph.add_edge(source=onload, target=reg_fn, kind='calls')
    init_export = _ensure_native(graph, 'Java_com_example_App_init', meta={'java_export': True})
    graph.add_edge(source=onload, target=init_export, kind='calls')
    run_java = _ensure_java_method(graph, 'com/example/App', 'run', '()V', meta={'recovery_sources': ['jni', 'jar'], 'confidence': 82, 'confidence_level': 'HIGH'})
    calc_java = _ensure_java_method(graph, 'com/example/App', 'calc', '(I)I', meta={'recovery_sources': ['bytecode', 'pseudoc'], 'confidence': 74, 'confidence_level': 'MEDIUM'})
    decrypt_java = _ensure_java_method(graph, 'com/example/crypto/Util', 'decrypt', '(Ljava/lang/String;)Ljava/lang/String;', meta={'recovery_sources': ['flatten', 'pseudoc'], 'confidence': 58, 'confidence_level': 'LOW'})
    run_native = _ensure_native(graph, 'FUN_run', meta={'registered': True, 'flatten_score': 2})
    calc_native = _ensure_native(graph, 'FUN_calc', meta={'registered': True})
    decrypt_native = _ensure_native(graph, 'FUN_decrypt', meta={'flatten_score': 18, 'flatten_level': 'control-flow flattening'})
    helper = _ensure_native(graph, 'FUN_xor_loop')
    graph.add_edge(source=reg_fn, target=run_native, kind='registrar', label='RegisterNatives')
    graph.add_edge(source=reg_fn, target=calc_native, kind='registrar')
    graph.add_edge(source=run_java, target=run_native, kind='registers')
    graph.add_edge(source=calc_java, target=calc_native, kind='registers')
    graph.add_edge(source=decrypt_java, target=decrypt_native, kind='registers')
    graph.add_edge(source=init_export, target=run_native, kind='export_bridge', label='calls impl')
    graph.add_edge(source=run_native, target=decrypt_native, kind='calls')
    graph.add_edge(source=run_native, target=helper, kind='calls')
    graph.add_edge(source=decrypt_native, target=helper, kind='calls')
    graph.add_edge(source=calc_native, target=helper, kind='calls')
    find_class = _ensure_jni_api(graph, 'FindClass')
    get_method = _ensure_jni_api(graph, 'GetMethodID')
    call_void = _ensure_jni_api(graph, 'CallVoidMethod')
    new_string = _ensure_jni_api(graph, 'NewStringUTF')
    graph.add_edge(source=run_native, target=find_class, kind='jni_invoke')
    graph.add_edge(source=run_native, target=get_method, kind='jni_invoke')
    graph.add_edge(source=run_native, target=call_void, kind='jni_invoke')
    graph.add_edge(source=decrypt_native, target=new_string, kind='jni_invoke')
    app_class = _java_class_id('com/example/App')
    graph.add_edge(source=run_native, target=app_class, kind='resolves', label='FindClass')
    graph.add_edge(source=run_native, target=run_java, kind='resolves', label='CallVoidMethod')
    return graph
