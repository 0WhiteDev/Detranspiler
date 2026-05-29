from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    entries: List[Dict[str, Any]] = []
    for item in sorted(root.rglob('*.java')):
        if not item.is_file():
            continue
        rel = item.relative_to(root).as_posix()
        entries.append({'path': rel, 'name': item.name})
    return {'status': 'OK', 'entries_total': len(entries), 'entries': entries, 'roots': {'pseudocode_dir': str(pseudocode_dir), 'sources_dir': str(root)}}

def read_source_file(*, rel_path: str, pseudocode_dir: Path, jar_sources_dir: Optional[Path]=None) -> Dict[str, Any]:
    del jar_sources_dir
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    rel = rel_path.replace('\\', '/').lstrip('/')
    root = _sources_root(pseudocode_dir)
    path = root / rel
    text = None
    if path.is_file():
        text = path.read_text(encoding='utf-8', errors='replace')
    return {'path': rel, 'content': text, 'has_content': text is not None}
