from pathlib import Path
from typing import Any, Dict

def build_cfg(*, binary_path: Path, max_function_sample: int=200) -> Dict[str, Any]:
    try:
        import angr
    except Exception as e:
        return {'status': 'SKIPPED_MISSING_ANGR', 'error': repr(e)}
    try:
        proj = angr.Project(str(binary_path), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=False)
        funcs = cfg.kb.functions
        addrs = list(funcs.keys())
        sample = []
        for a in addrs[:max_function_sample]:
            f = funcs.get(a)
            name = getattr(f, 'name', None) if f is not None else None
            sample.append({'addr': hex(int(a)), 'name': str(name) if name else None})
        graph = getattr(cfg, 'graph', None)
        nodes = int(graph.number_of_nodes()) if graph is not None else None
        edges = int(graph.number_of_edges()) if graph is not None else None
        return {'status': 'OK', 'arch': str(getattr(proj, 'arch', None)), 'entry': hex(int(getattr(proj, 'entry', 0))), 'function_count': len(addrs), 'cfg_nodes': nodes, 'cfg_edges': edges, 'functions_sample': sample}
    except Exception as e:
        return {'status': 'ERROR', 'error': repr(e)}
