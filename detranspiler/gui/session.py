from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from detranspiler.reporting.re_map import get_analysis_dir_from_job

def _artifact_exists(path_value: Optional[str]) -> bool:
    if not isinstance(path_value, str) or not path_value.strip():
        return False
    return Path(path_value).is_file()

def load_job(out_dir: Path) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    job_path = out_dir / 'job.json'
    if not job_path.is_file():
        raise FileNotFoundError(f'job.json not found in {out_dir}')
    job = json.loads(job_path.read_text(encoding='utf-8'))
    if not isinstance(job, dict):
        raise ValueError('Invalid job.json')
    return job

def discover_artifacts(job: Dict[str, Any], out_dir: Optional[Path]=None) -> Dict[str, Any]:
    artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
    analysis_dir = get_analysis_dir_from_job(job)
    if analysis_dir is None and out_dir is not None:
        candidate = out_dir / 'analysis'
        if candidate.is_dir():
            analysis_dir = candidate
    analysis_path = str(analysis_dir.resolve()) if analysis_dir and analysis_dir.is_dir() else None
    report_html = artifacts.get('report_html')
    re_map_html = artifacts.get('re_map_html')
    if not _artifact_exists(report_html) and analysis_dir is not None:
        candidate = analysis_dir / 'report.html'
        if candidate.is_file():
            report_html = str(candidate)
    if not _artifact_exists(re_map_html) and analysis_dir is not None:
        candidate = analysis_dir / 're_map.html'
        if candidate.is_file():
            re_map_html = str(candidate)
    native_map_dir = artifacts.get('native_map_dir')
    native_map_json = None
    if out_dir is not None:
        nm_json = out_dir / 'analysis' / 'native_map.json'
        if nm_json.is_file():
            native_map_json = str(nm_json)
        if not isinstance(native_map_dir, str) or not Path(native_map_dir).is_dir():
            candidate = out_dir / 'native_map'
            if candidate.is_dir():
                native_map_dir = str(candidate)
    input_info = job.get('input') if isinstance(job.get('input'), dict) else {}
    mode_info = job.get('mode') if isinstance(job.get('mode'), dict) else {}
    recovery = job.get('analysis', {}).get('recovery') if isinstance(job.get('analysis'), dict) else {}
    if not isinstance(recovery, dict):
        recovery = {}
    try:
        from detranspiler.recovery.metrics import build_recovery_summary
        fresh = build_recovery_summary(job=job)
        if isinstance(fresh, dict) and fresh.get('status') == 'OK':
            recovery = fresh
    except Exception:
        pass
    artifact_doc = {'report_html': report_html if _artifact_exists(report_html) else None, 're_map_html': re_map_html if _artifact_exists(re_map_html) else None, 'native_map_dir': native_map_dir if isinstance(native_map_dir, str) and Path(native_map_dir).is_dir() else None, 'native_map_json': native_map_json if _artifact_exists(native_map_json) else None, 'job_json': artifacts.get('job_json'), 'pseudocode_dir': artifacts.get('pseudocode_dir'), 'sources_dir': artifacts.get('sources_dir'), 'recovered_project_dir': artifacts.get('recovered_project_dir')}
    return {'out_dir': str(out_dir.resolve()) if out_dir else artifacts.get('out_dir'), 'analysis_dir': analysis_path, 'job_id': job.get('job_id'), 'created_at': job.get('created_at'), 'input_name': input_info.get('name'), 'input_path': input_info.get('path'), 'mode_requested': mode_info.get('requested'), 'mode_resolved': mode_info.get('resolved'), 'recovery_rate': int(round(float(recovery.get('overall_recovery_rate') or recovery.get('recovery_rate') or 0) * 100)) if isinstance(recovery, dict) else None, 'methods_total': recovery.get('native_methods_total') or recovery.get('methods_total'), 'methods_with_body': recovery.get('native_methods_recovered') or recovery.get('methods_recovered'), 'methods_still_native': recovery.get('native_methods_remaining') or recovery.get('methods_stub'), 'artifacts': artifact_doc}

def open_session(out_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    out_dir = out_dir.expanduser().resolve()
    job = load_job(out_dir)
    summary = discover_artifacts(job, out_dir)
    return job, summary
