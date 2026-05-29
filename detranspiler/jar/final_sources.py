from __future__ import annotations
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
_SKIP_NAMES = frozenset({'jni_stubs.java', 'NativeDecompiled.java'})
_LAYER_DIRS: Tuple[str, ...] = ('jar_sources', 'jni', 'jni_exports', 'jnic', 'radioegor_sources')

def _rel_java_path(path: Path, layer_root: Path, layer_name: str) -> str:
    rel = path.relative_to(layer_root).as_posix()
    if layer_name in {'jni', 'jni_exports', 'jnic', 'radioegor_sources'}:
        return rel
    return rel

def build_final_sources(*, pseudocode_dir: Path, out_subdir: str='sources') -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    if not pseudocode_dir.is_dir():
        return {'status': 'SKIPPED_NO_PSEUDOCODE_DIR'}
    out_root = pseudocode_dir / out_subdir
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    layers_used: List[str] = []
    files_written: Dict[str, str] = {}
    for layer_name in _LAYER_DIRS:
        layer_root = pseudocode_dir / layer_name
        if not layer_root.is_dir():
            continue
        layer_files = 0
        for java_file in sorted(layer_root.rglob('*.java')):
            if not java_file.is_file() or java_file.name in _SKIP_NAMES:
                continue
            rel = _rel_java_path(java_file, layer_root, layer_name)
            dest = out_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(java_file, dest)
            files_written[rel] = layer_name
            layer_files += 1
        if layer_files:
            layers_used.append(layer_name)
    if not files_written:
        return {'status': 'SKIPPED_NO_SOURCES', 'output_dir': str(out_root), 'files_total': 0, 'layers_used': []}
    manifest = {'status': 'OK', 'output_dir': str(out_root.resolve()), 'files_total': len(files_written), 'layers_used': layers_used, 'layer_priority': list(_LAYER_DIRS), 'files': [{'path': rel, 'source_layer': layer} for rel, layer in sorted(files_written.items())[:2000]]}
    manifest_path = pseudocode_dir / 'sources_manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'status': 'OK', 'output_dir': str(out_root.resolve()), 'manifest_path': str(manifest_path.resolve()), 'files_total': len(files_written), 'layers_used': layers_used}
