import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
RE_THEME_CSS = '\n:root {\n  --bg: #0d1117;\n  --panel: #161b22;\n  --panel2: #1c2128;\n  --stroke: #30363d;\n  --text: #e6edf3;\n  --muted: #8b949e;\n  --accent: #58a6ff;\n  --ok: #3fb950;\n  --warn: #d29922;\n  --bad: #f85149;\n  --jni: #a371f7;\n  --entry: #f78166;\n  --java: #3fb950;\n  --mono: Consolas, "Cascadia Mono", Menlo, monospace;\n}\n* { box-sizing: border-box; }\nhtml, body {\n  margin: 0;\n  min-height: 100%;\n  background: var(--bg);\n  color: var(--text);\n  font-family: "Segoe UI", system-ui, sans-serif;\n  line-height: 1.45;\n}\na { color: var(--accent); text-decoration: none; }\na:hover { text-decoration: underline; }\ncode, pre { font-family: var(--mono); font-size: 12px; }\n.layout {\n  display: grid;\n  grid-template-columns: 260px minmax(0, 1fr);\n  min-height: 100vh;\n}\n.topbar {\n  grid-column: 1 / -1;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  padding: 10px 16px;\n  background: var(--panel);\n  border-bottom: 1px solid var(--stroke);\n  position: sticky;\n  top: 0;\n  z-index: 20;\n}\n.brand { font-weight: 600; font-size: 14px; margin-right: 8px; white-space: nowrap; }\n.topbar-author { margin-left: auto; color: var(--muted); font-size: 11px; white-space: nowrap; }\n.topbar-author a { color: var(--muted); text-decoration: none; }\n.topbar-author a:hover { color: var(--accent); text-decoration: underline; }\n.nav-links { display: flex; gap: 6px; flex-wrap: wrap; }\n.nav-link {\n  display: inline-block;\n  padding: 6px 10px;\n  border-radius: 6px;\n  border: 1px solid transparent;\n  color: var(--muted);\n  font-size: 13px;\n}\n.nav-link:hover { color: var(--text); border-color: var(--stroke); text-decoration: none; }\n.nav-link.active {\n  color: var(--text);\n  border-color: var(--stroke);\n  background: var(--panel2);\n}\n.sidebar {\n  background: var(--panel);\n  border-right: 1px solid var(--stroke);\n  padding: 16px 12px;\n  position: sticky;\n  top: 49px;\n  height: calc(100vh - 49px);\n  overflow: auto;\n}\n.sidebar h2 {\n  margin: 0 0 10px;\n  font-size: 11px;\n  color: var(--muted);\n  text-transform: uppercase;\n  letter-spacing: .05em;\n}\n.side-nav { display: grid; gap: 4px; margin-bottom: 18px; }\n.side-nav a {\n  display: block;\n  padding: 6px 8px;\n  border-radius: 6px;\n  color: var(--muted);\n  font-size: 13px;\n}\n.side-nav a:hover { background: var(--panel2); color: var(--text); text-decoration: none; }\n.main {\n  padding: 20px 24px 40px;\n  max-width: 1200px;\n}\n.page-title { margin: 0 0 4px; font-size: 22px; font-weight: 600; }\n.page-sub { color: var(--muted); font-size: 13px; margin-bottom: 18px; word-break: break-word; }\n.stats {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));\n  gap: 10px;\n  margin-bottom: 18px;\n}\n.stat {\n  background: var(--panel2);\n  border: 1px solid var(--stroke);\n  border-radius: 8px;\n  padding: 10px 12px;\n}\n.stat strong {\n  display: block;\n  font-size: 22px;\n  line-height: 1.1;\n  color: var(--accent);\n  margin-bottom: 4px;\n}\n.stat span { color: var(--muted); font-size: 12px; }\n.panel {\n  background: var(--panel2);\n  border: 1px solid var(--stroke);\n  border-radius: 8px;\n  padding: 14px 16px;\n  margin-bottom: 16px;\n}\n.panel > h2, .panel > h3 {\n  margin: 0 0 10px;\n  font-size: 13px;\n  color: var(--muted);\n  font-weight: 600;\n  text-transform: uppercase;\n  letter-spacing: .04em;\n}\n.panel h3 { font-size: 12px; margin-top: 14px; }\n.section { scroll-margin-top: 64px; margin-bottom: 8px; }\n.section > h2 {\n  margin: 22px 0 10px;\n  font-size: 16px;\n  font-weight: 600;\n}\n.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }\n@media (max-width: 900px) {\n  .layout { grid-template-columns: 1fr; }\n  .sidebar { position: static; height: auto; border-right: none; border-bottom: 1px solid var(--stroke); }\n  .grid-2 { grid-template-columns: 1fr; }\n}\n.data-table {\n  width: 100%;\n  border-collapse: collapse;\n  font-size: 13px;\n}\n.data-table th, .data-table td {\n  border-bottom: 1px solid var(--stroke);\n  padding: 8px 10px;\n  text-align: left;\n  vertical-align: top;\n}\n.data-table th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; }\n.data-table tr:hover td { background: rgba(88,166,255,.04); }\n.kv-table th { width: 220px; color: var(--muted); font-weight: 500; }\n.badge {\n  display: inline-block;\n  padding: 2px 8px;\n  border-radius: 999px;\n  font-size: 11px;\n  font-weight: 600;\n  border: 1px solid var(--stroke);\n}\n.badge.ok { color: var(--ok); border-color: rgba(63,185,80,.35); background: rgba(63,185,80,.08); }\n.badge.warn { color: var(--warn); border-color: rgba(210,153,34,.35); background: rgba(210,153,34,.08); }\n.badge.bad { color: var(--bad); border-color: rgba(248,81,73,.35); background: rgba(248,81,73,.08); }\n.badge.neutral { color: var(--muted); }\n.toolbar {\n  display: flex;\n  gap: 8px;\n  flex-wrap: wrap;\n  margin-bottom: 10px;\n  align-items: center;\n}\ninput[type="search"], select, .btn {\n  background: var(--panel);\n  border: 1px solid var(--stroke);\n  color: var(--text);\n  border-radius: 6px;\n  padding: 7px 10px;\n  font-size: 13px;\n}\n.btn { cursor: pointer; }\n.btn:hover, .btn.active { border-color: var(--accent); color: var(--accent); }\n.btn.active { background: rgba(88,166,255,.08); }\n.muted { color: var(--muted); }\n.list-compact { margin: 0; padding-left: 18px; }\n.list-compact li { margin: 4px 0; }\n.pre-block {\n  background: var(--panel);\n  border: 1px solid var(--stroke);\n  border-radius: 8px;\n  padding: 12px;\n  overflow: auto;\n  max-height: 480px;\n  white-space: pre-wrap;\n  word-break: break-word;\n}\ndetails.collapsible > summary {\n  cursor: pointer;\n  color: var(--accent);\n  font-size: 13px;\n  margin-bottom: 8px;\n}\n.diff-wrap {\n  font-family: var(--mono);\n  font-size: 12px;\n  background: var(--panel);\n  border: 1px solid var(--stroke);\n  border-radius: 8px;\n  overflow: auto;\n  max-height: 420px;\n}\n.diff-wrap .line { padding: 1px 10px; white-space: pre-wrap; word-break: break-word; }\n.diff-wrap .hdr { color: var(--accent); background: rgba(88,166,255,.08); }\n.diff-wrap .add { color: var(--ok); background: rgba(63,185,80,.08); }\n.diff-wrap .rem { color: var(--bad); background: rgba(248,81,73,.08); }\n.diff-wrap .ctx { color: var(--muted); }\n.method-card {\n  border: 1px solid var(--stroke);\n  border-radius: 8px;\n  background: var(--panel2);\n  margin-bottom: 12px;\n  overflow: hidden;\n}\n.method-card summary {\n  cursor: pointer;\n  list-style: none;\n  padding: 10px 12px;\n  display: flex;\n  gap: 10px;\n  align-items: center;\n  flex-wrap: wrap;\n}\n.method-card summary::-webkit-details-marker { display: none; }\n.method-card .body { padding: 0 12px 12px; }\n.match-ok { color: var(--ok); }\n.match-partial { color: var(--warn); }\n.match-bad { color: var(--bad); }\n.hidden { display: none !important; }\n.empty { color: var(--muted); font-style: italic; }\n'
RE_MAP_EXTRA_CSS = '\n#app { display: grid; grid-template-columns: 320px 1fr; height: calc(100vh - 49px); }\n#app aside {\n  background: var(--panel);\n  border-right: 1px solid var(--stroke);\n  padding: 16px;\n  overflow: auto;\n  display: flex;\n  flex-direction: column;\n  gap: 14px;\n}\n#app main {\n  position: relative;\n  overflow: hidden;\n  background: radial-gradient(circle at 50% 30%, #121820 0%, var(--bg) 70%);\n}\n#app h1 { font-size: 18px; margin: 0; font-weight: 600; }\n#app .sub { color: var(--muted); font-size: 12px; line-height: 1.4; word-break: break-word; }\n#app .filters { display: grid; gap: 6px; }\n#app .filters label.chk {\n  display: flex; align-items: center; gap: 8px; color: var(--text); cursor: pointer; font-size: 13px;\n}\n#app .legend { display: grid; gap: 6px; font-size: 12px; }\n#app .legend-row { display: flex; align-items: center; gap: 8px; }\n#app .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }\n#app .detail-title { font-size: 15px; font-weight: 600; margin-bottom: 6px; word-break: break-word; }\n#app .detail-kind { color: var(--accent); font-size: 12px; margin-bottom: 8px; }\n#app .detail-meta { font-size: 12px; line-height: 1.5; color: var(--muted); white-space: pre-wrap; word-break: break-word; }\n#app .toolbar { position: absolute; top: 12px; right: 12px; z-index: 2; }\n#app #canvas { width: 100%; height: 100%; display: block; cursor: grab; }\n#app #canvas.dragging { cursor: grabbing; }\n#app .hint {\n  position: absolute; left: 12px; bottom: 12px; color: var(--muted); font-size: 12px;\n  background: rgba(22,27,34,.85); border: 1px solid var(--stroke); border-radius: 6px; padding: 6px 10px;\n}\n.map-shell .layout { grid-template-columns: 1fr; }\n.map-shell .sidebar { display: none; }\n.map-shell .main { max-width: none; padding: 0; }\n'
JAR_DIFF_SHELL_CSS = '\nbody.jar-diff-shell .layout { grid-template-columns: 1fr; min-height: 100vh; }\nbody.jar-diff-shell .main {\n  max-width: none;\n  width: 100%;\n  padding: 16px 20px 32px;\n  box-sizing: border-box;\n}\nbody.jar-diff-shell .stats { grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }\nbody.jar-diff-shell .method-card { width: 100%; }\nbody.jar-diff-shell .diff-wrap { max-height: min(70vh, 900px); width: 100%; }\nbody.jar-diff-shell .panel { width: 100%; box-sizing: border-box; }\n'

def escape_html(text: Any) -> str:
    return html.escape(str(text if text is not None else ''))

def file_href(path_value: Optional[str], *, base_dir: Optional[Path]=None) -> Optional[str]:
    if not path_value or not isinstance(path_value, str):
        return None
    p = Path(path_value)
    if base_dir is not None:
        try:
            return p.resolve().relative_to(base_dir.resolve()).as_posix()
        except Exception:
            pass
    return 'file:///' + path_value.replace('\\', '/')

def file_link(path_value: Optional[str], *, base_dir: Optional[Path]=None, label: Optional[str]=None) -> str:
    href = file_href(path_value, base_dir=base_dir)
    if not href:
        return '<span class="empty">n/a</span>'
    text = label or path_value or href
    return f'<a href="{escape_html(href)}"><code>{escape_html(str(text))}</code></a>'

def badge(text: str, kind: str='neutral') -> str:
    return f'<span class="badge {escape_html(kind)}">{escape_html(text)}</span>'

def confidence_badge(level: Optional[str]) -> str:
    lv = str(level or 'MINIMAL').upper()
    kind = {'HIGH': 'ok', 'MEDIUM': 'warn', 'LOW': 'bad', 'MINIMAL': 'neutral'}.get(lv, 'neutral')
    return badge(lv, kind)

def risk_badge(level: Optional[str]) -> str:
    lv = str(level or 'UNKNOWN').upper()
    kind = {'NONE': 'ok', 'LOW': 'ok', 'MEDIUM': 'warn', 'HIGH': 'bad'}.get(lv, 'neutral')
    return badge(lv, kind)

def stat_card(value: str, label: str, *, extra: str='') -> str:
    extra_html = f'<div>{extra}</div>' if extra else ''
    return f'<div class="stat"><strong>{escape_html(value)}</strong><span>{escape_html(label)}</span>{extra_html}</div>'

def render_nav(*, current: str, report_href: Optional[str]=None, map_href: Optional[str]=None) -> str:
    items = [('Report', report_href or 'report.html', current == 'report'), ('RE Map', map_href or 're_map.html', current == 'map')]
    links = []
    for label, href, active in items:
        if not href:
            links.append(f'<span class="nav-link muted">{escape_html(label)}</span>')
            continue
        cls = 'nav-link active' if active else 'nav-link'
        links.append(f'<a class="{cls}" href="{escape_html(href)}">{escape_html(label)}</a>')
    return f"""<div class="brand">Detranspiler</div><div class="nav-links">{''.join(links)}</div><div class="topbar-author"><a href="https://github.com/0WhiteDev" target="_blank" rel="noopener noreferrer">0WhiteDev</a></div>"""

def render_page(*, title: str, subtitle: str='', current_nav: str, main_html: str, sidebar_html: str='', extra_css: str='', extra_script: str='', body_class: str='', report_href: Optional[str]='report.html', map_href: Optional[str]='re_map.html') -> str:
    nav = render_nav(current=current_nav, report_href=report_href, map_href=map_href)
    sidebar_block = f'<aside class="sidebar">{sidebar_html}</aside>' if sidebar_html else ''
    return f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>{escape_html(title)}</title>\n<style>\n{RE_THEME_CSS}\n{extra_css}\n</style>\n</head>\n<body class="{escape_html(body_class)}">\n<div class="layout">\n<header class="topbar">{nav}</header>\n{sidebar_block}\n<main class="main">\n<h1 class="page-title">{escape_html(title)}</h1>\n<div class="page-sub">{subtitle}</div>\n{main_html}\n</main>\n</div>\n{extra_script}\n</body>\n</html>'

def side_nav(items: Sequence[Tuple[str, str]]) -> str:
    links = ''.join((f'<a href="{escape_html(href)}">{escape_html(label)}</a>' for label, href in items))
    return f'<h2>Sections</h2><nav class="side-nav">{links}</nav>'

def panel(title: str, content: str) -> str:
    return f'<div class="panel"><h2>{escape_html(title)}</h2>{content}</div>'

def kv_table(rows: Sequence[Tuple[str, Any]]) -> str:
    body: List[str] = []
    for key, val in rows:
        if val is None:
            cell = '<span class="empty">n/a</span>'
        else:
            cell = str(val)
        body.append(f'<tr><th>{escape_html(key)}</th><td>{cell}</td></tr>')
    return f"""<table class="data-table kv-table">{''.join(body)}</table>"""

def artifact_links_from_job(job: Dict[str, Any], analysis_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
    report = file_href(str(artifacts.get('report_html') or analysis_dir / 'report.html'), base_dir=analysis_dir)
    re_map = file_href(artifacts.get('re_map_html') if isinstance(artifacts.get('re_map_html'), str) else None, base_dir=analysis_dir)
    return (report or 'report.html', re_map or 're_map.html')

def json_pre(data: Any) -> str:
    return f'<pre class="pre-block">{escape_html(json.dumps(data, ensure_ascii=False, indent=2))}</pre>'
