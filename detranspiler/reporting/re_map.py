import html
import json
from pathlib import Path
from typing import Any, Dict, Optional

from detranspiler.reporting.graph_model import ReGraph, build_demo_re_graph, build_re_graph_from_analysis_dir
from detranspiler.reporting.html_theme import RE_MAP_EXTRA_CSS, RE_THEME_CSS, artifact_links_from_job, render_nav

def _graph_payload(graph: ReGraph) -> Dict[str, Any]:
    return graph.to_dict()

def write_re_map_json(*, graph: ReGraph, out_path: Path) -> Dict[str, Any]:
    out_path = out_path.expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _graph_payload(graph)
    out_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return {'status': 'OK', 'output_path': str(out_path), 'nodes_total': len(graph.nodes)}

def write_re_map_html(*, graph: ReGraph, out_path: Path, json_path: Optional[Path]=None, report_href: Optional[str]='report.html', map_href: Optional[str]='re_map.html') -> Dict[str, Any]:
    out_path = out_path.expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _graph_payload(graph)
    if json_path is not None:
        write_re_map_json(graph=graph, out_path=json_path)
    embedded = json.dumps(payload, ensure_ascii=False)
    page = _render_re_map_page(payload, embedded_json=embedded, report_href=report_href, map_href=map_href)
    out_path.write_text(page, encoding='utf-8')
    return {'status': 'OK', 'output_path': str(out_path), 'nodes_total': len(graph.nodes), 'edges_total': len(graph.edges), 'json_path': str(json_path.resolve()) if json_path else None}

def write_re_map_from_job(*, job: Dict[str, Any], analysis_dir: Path, out_html: Optional[Path]=None, out_json: Optional[Path]=None, max_nodes: int=400) -> Dict[str, Any]:
    analysis_dir = analysis_dir.expanduser().resolve()
    out_html = (out_html or analysis_dir / 're_map.html').expanduser().resolve()
    out_json = (out_json or analysis_dir / 're_map.json').expanduser().resolve()
    graph = build_re_graph_from_analysis_dir(analysis_dir, job=job, max_nodes=max_nodes)
    if not graph.nodes:
        return {'status': 'SKIPPED_EMPTY_GRAPH'}
    report_href, map_href = artifact_links_from_job(job, analysis_dir)
    return write_re_map_html(graph=graph, out_path=out_html, json_path=out_json, report_href=report_href, map_href=map_href)

def write_demo_re_map(*, out_dir: Path) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    graph = build_demo_re_graph()
    return write_re_map_html(graph=graph, out_path=out_dir / 're_map_demo.html', json_path=out_dir / 're_map_demo.json')

def _render_re_map_page(payload: Dict[str, Any], *, embedded_json: str, report_href: Optional[str]='report.html', map_href: Optional[str]='re_map.html') -> str:
    title = html.escape(str(payload.get('title') or 'RE Map'))
    subtitle = html.escape(str(payload.get('subtitle') or ''))
    stats = payload.get('stats') if isinstance(payload.get('stats'), dict) else {}
    nodes_total = int(stats.get('nodes_total') or 0)
    edges_total = int(stats.get('edges_total') or 0)
    nav = render_nav(current='map', report_href=report_href, map_href=map_href)
    assets = Path(__file__).resolve().parent / 'assets'
    shell = (assets / 're_map_shell.html').read_text(encoding='utf-8')
    script = (assets / 're_map_script.js').read_text(encoding='utf-8')
    page = (
        shell.replace('__TITLE__', title)
        .replace('__SUBTITLE__', subtitle)
        .replace('__NAV__', nav)
        .replace('__NODES_TOTAL__', str(nodes_total))
        .replace('__EDGES_TOTAL__', str(edges_total))
        .replace('__RE_THEME_CSS__', RE_THEME_CSS)
        .replace('__RE_MAP_EXTRA_CSS__', RE_MAP_EXTRA_CSS)
        .replace('__EMBEDDED_JSON__', embedded_json)
    )
    return page + script + '\n</script>\n</body>\n</html>\n'

def get_analysis_dir_from_job(job: Dict[str, Any]) -> Optional[Path]:
    artifacts = job.get('artifacts')
    if isinstance(artifacts, dict):
        for key in ('callgraph_json', 'report_html', 'native_index_json'):
            raw = artifacts.get(key)
            if isinstance(raw, str):
                return Path(raw).parent
    out = job.get('out_dir')
    if isinstance(out, str):
        return Path(out) / 'analysis'
    return None
