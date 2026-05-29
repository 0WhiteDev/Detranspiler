from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

def _native_map_json_path(out_dir: Path) -> Optional[Path]:
    out_dir = out_dir.expanduser().resolve()
    candidates = (out_dir / 'analysis' / 'native_map.json', out_dir / 'native_map.json')
    for path in candidates:
        if path.is_file():
            return path
    return None

def _method_id(method: Dict[str, Any]) -> str:
    cls = str(method.get('class_internal') or '')
    name = str(method.get('method') or '')
    desc = str(method.get('descriptor') or '')
    return f'{cls}::{name}::{desc}'

def build_native_map_tree(*, out_dir: Path) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    json_path = _native_map_json_path(out_dir)
    if json_path is None:
        map_dir = out_dir / 'native_map'
        if map_dir.is_dir():
            return {'status': 'SKIPPED', 'error': 'native_map folder exists but analysis/native_map.json is missing re-run analysis', 'methods_total': 0, 'packages': []}
        return {'status': 'SKIPPED', 'error': 'Native map not built for this session (run analysis with a JAR attached)', 'methods_total': 0, 'packages': []}
    try:
        data = json.loads(json_path.read_text(encoding='utf-8', errors='replace'))
    except Exception as e:
        return {'status': 'ERROR', 'error': str(e), 'methods_total': 0, 'packages': []}
    methods = [m for m in data.get('methods') or [] if isinstance(m, dict)]
    by_pkg: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for m in methods:
        pkg = m.get('package') or '(default package)'
        cls = m.get('class_simple') or '?'
        leaf = {'id': _method_id(m), 'method': m.get('method'), 'java_signature': m.get('java_signature'), 'descriptor': m.get('descriptor'), 'fn_symbol': m.get('fn_symbol'), 'address': m.get('address'), 'c_file': m.get('c_file'), 'body_found': bool(m.get('body_found')), 'confidence': m.get('confidence'), 'decompiled_c_lines': m.get('decompiled_c_lines')}
        by_pkg.setdefault(str(pkg), {}).setdefault(str(cls), []).append(leaf)
    packages: List[Dict[str, Any]] = []
    for pkg in sorted(by_pkg):
        classes: List[Dict[str, Any]] = []
        for cls in sorted(by_pkg[pkg]):
            items = sorted(by_pkg[pkg][cls], key=lambda x: str(x.get('method') or ''))
            classes.append({'name': cls, 'methods': items})
        packages.append({'name': pkg, 'classes': classes})
    map_dir = out_dir / 'native_map'
    return {'status': 'OK', 'methods_total': len(methods), 'bodies_found': data.get('bodies_found'), 'classes_total': data.get('classes_total'), 'binary': data.get('binary'), 'image_base': data.get('image_base'), 'packages': packages, 'native_map_dir': str(map_dir) if map_dir.is_dir() else data.get('output_dir'), 'readme_path': str(map_dir / 'README.md') if (map_dir / 'README.md').is_file() else data.get('readme_path')}

def read_native_map_method(*, out_dir: Path, method_id: str) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    json_path = _native_map_json_path(out_dir)
    if json_path is None:
        return {'status': 'ERROR', 'error': 'native_map.json not found'}
    try:
        data = json.loads(json_path.read_text(encoding='utf-8', errors='replace'))
    except Exception as e:
        return {'status': 'ERROR', 'error': str(e)}
    method: Optional[Dict[str, Any]] = None
    for m in data.get('methods') or []:
        if isinstance(m, dict) and _method_id(m) == method_id:
            method = m
            break
    if method is None:
        return {'status': 'ERROR', 'error': f'Method not found: {method_id}'}
    content: Optional[str] = None
    c_rel = method.get('c_file')
    map_dir = out_dir / 'native_map'
    if isinstance(c_rel, str) and c_rel.strip():
        c_path = map_dir / c_rel.replace('\\', '/').lstrip('/')
        if c_path.is_file():
            content = c_path.read_text(encoding='utf-8', errors='replace')
    return {'status': 'OK', 'id': method_id, 'method': method, 'content': content, 'has_content': content is not None}
