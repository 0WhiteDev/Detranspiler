from __future__ import annotations
import json
import shutil
from pathlib import Path
from typing import Any, Dict
from detranspiler.provenance.model import read_json

_SUMMARY_KEYS = (
    'files_total',
    'files_available',
    'lines_total',
    'truncated',
    'methods_total',
    'methods_with_body_evidence',
    'methods_with_generated_body_evidence',
    'native_methods_total',
    'native_methods_linked',
    'native_mapping_coverage',
    'evidence_total',
)

def attach_export_provenance(*, provenance_path: Path, export_dir: Path, summary: Dict[str, Any]) -> Dict[str, Any]:
    provenance_path = provenance_path.expanduser().resolve()
    export_dir = export_dir.expanduser().resolve()
    if not provenance_path.is_file():
        return {'status': 'SKIPPED_NO_PROVENANCE'}
    if not export_dir.is_dir():
        return {'status': 'SKIPPED_NO_EXPORT'}
    target = export_dir / 'PROVENANCE.json'
    shutil.copy2(provenance_path, target)
    manifest_path = export_dir / 'MANIFEST.json'
    manifest = dict(read_json(manifest_path))
    if manifest:
        values = {key: summary.get(key) for key in _SUMMARY_KEYS if summary.get(key) is not None}
        manifest['source_provenance'] = {'path': target.name, **values}
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'status': 'OK', 'output_path': str(target), 'manifest_updated': bool(manifest)}
