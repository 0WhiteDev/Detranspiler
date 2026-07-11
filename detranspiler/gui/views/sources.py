from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.provenance.lookup import read_line_provenance
from detranspiler.provenance.model import read_json, resolve_beneath

def _sources_root(pseudocode_dir: Path) -> Path:
    final = pseudocode_dir / 'sources'
    if final.is_dir():
        return final
    return final

def build_sources_tree(*, pseudocode_dir: Path, jar_sources_dir: Optional[Path]=None) -> Dict[str, Any]:
    del jar_sources_dir
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    root = _sources_root(pseudocode_dir)
    if not root.is_dir():
        return {'status': 'SKIPPED', 'error': 'Final sources not built yet (pseudocode/sources missing)', 'entries_total': 0, 'entries': []}
    provenance_doc = read_json(pseudocode_dir.parent / 'analysis' / 'source_provenance.json')
    provenance_files = provenance_doc.get('files') if isinstance(provenance_doc.get('files'), dict) else {}
    entries: List[Dict[str, Any]] = []
    for item in sorted(root.rglob('*.java')):
        if not item.is_file():
            continue
        rel = item.relative_to(root).as_posix()
        provenance = provenance_files.get(rel) if isinstance(provenance_files.get(rel), dict) else {}
        entries.append({'path': rel, 'name': item.name, 'provenance_ranges': len(provenance.get('ranges') or []), 'provenance_methods': len(provenance.get('methods') or [])})
    return {'status': 'OK', 'entries_total': len(entries), 'entries': entries, 'roots': {'pseudocode_dir': str(pseudocode_dir), 'sources_dir': str(root)}}

def read_source_file(*, rel_path: str, pseudocode_dir: Path, jar_sources_dir: Optional[Path]=None) -> Dict[str, Any]:
    del jar_sources_dir
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    rel = rel_path.replace('\\', '/').lstrip('/')
    root = _sources_root(pseudocode_dir)
    path = resolve_beneath(root, rel)
    if path is None:
        return {'status': 'ERROR', 'error': 'Source path is outside the active session', 'path': rel, 'content': None, 'has_content': False, 'provenance': {'ranges': [], 'methods': [], 'evidence': {}}}
    text = None
    if path.is_file():
        text = path.read_text(encoding='utf-8', errors='replace')
    provenance_doc = read_json(pseudocode_dir.parent / 'analysis' / 'source_provenance.json')
    provenance_files = provenance_doc.get('files') if isinstance(provenance_doc.get('files'), dict) else {}
    file_provenance = provenance_files.get(rel) if isinstance(provenance_files.get(rel), dict) else {}
    evidence_map = provenance_doc.get('evidence') if isinstance(provenance_doc.get('evidence'), dict) else {}
    referenced = {str(item.get('evidence_id')) for item in file_provenance.get('ranges') or [] if isinstance(item, dict) and item.get('evidence_id')}
    evidence = {}
    for evidence_id in referenced:
        value = evidence_map.get(evidence_id)
        if not isinstance(value, dict):
            continue
        summary = {key: item for key, item in value.items() if key != 'jni_calls'}
        evidence[evidence_id] = summary
    return {'status': 'OK' if text is not None else 'NOT_FOUND', 'path': rel, 'content': text, 'has_content': text is not None, 'provenance': {'ranges': file_provenance.get('ranges') or [], 'methods': file_provenance.get('methods') or [], 'evidence': evidence}}

def read_source_line_provenance(*, rel_path: str, line: int, pseudocode_dir: Path) -> Dict[str, Any]:
    return read_line_provenance(out_dir=pseudocode_dir.expanduser().resolve().parent, rel_path=rel_path, line=max(1, int(line)))
