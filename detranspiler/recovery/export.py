import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

def export_recovered_project(*, pseudocode_dir: Path, out_dir: Path, job: Optional[Dict[str, Any]]=None, native_index: Optional[Dict[str, Any]]=None, method_confidence: Optional[Dict[str, Any]]=None, min_confidence_level: Optional[str]=None) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    if not pseudocode_dir.is_dir():
        return {'status': 'SKIPPED_NO_PSEUDOCODE_DIR'}
    src_root = out_dir / 'src'
    if src_root.exists():
        shutil.rmtree(src_root)
    src_root.mkdir(parents=True, exist_ok=True)
    copied: List[str] = []
    skipped_low_confidence: List[str] = []
    skip_names = {'jni_stubs.java', 'NativeDecompiled.java'}
    low_levels = {'MINIMAL'}
    if isinstance(min_confidence_level, str):
        order = ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH']
        try:
            idx = order.index(min_confidence_level.upper())
            low_levels = set(order[:idx + 1])
        except ValueError:
            pass
    conf_by_file: Dict[str, str] = {}
    if isinstance(method_confidence, dict):
        for m in method_confidence.get('methods') or []:
            if not isinstance(m, dict):
                continue
            cls = m.get('class')
            method = m.get('method')
            level = m.get('level')
            if isinstance(cls, str) and isinstance(method, str) and isinstance(level, str):
                conf_by_file[f'{cls}#{method}'] = level
    sources_root = pseudocode_dir / 'sources'
    scan_root = sources_root if sources_root.is_dir() else pseudocode_dir
    for java_file in sorted(scan_root.rglob('*.java')):
        if java_file.name in skip_names:
            continue
        rel = java_file.relative_to(scan_root)
        if not sources_root.is_dir() and rel.parts and (rel.parts[0] in {'jar_sources'}):
            continue
        rel_str = str(rel).replace('\\', '/')
        if conf_by_file:
            internal = rel_str[:-5] if rel_str.endswith('.java') else rel_str
            class_keys = {internal}
            if internal.startswith('jni/'):
                class_keys.add(internal[4:])
            if internal.startswith('jni_exports/'):
                class_keys.add(internal[len('jni_exports/'):])
            matched_levels = [lv for key, lv in conf_by_file.items() if any((key.startswith(ck + '#') for ck in class_keys))]
            if matched_levels and all((lv in low_levels for lv in matched_levels)):
                skipped_low_confidence.append(rel_str)
                continue
        dest = src_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(java_file, dest)
        copied.append(str(rel).replace('\\', '/'))
    manifest: Dict[str, Any] = {'status': 'OK', 'source_root': str(src_root), 'files_copied': len(copied), 'files_skipped_low_confidence': len(skipped_low_confidence), 'files': copied[:500]}
    if isinstance(job, dict):
        manifest['job_id'] = job.get('job_id')
        inp = job.get('input') if isinstance(job.get('input'), dict) else {}
        manifest['input'] = {'name': inp.get('name'), 'sha256': inp.get('sha256'), 'format': inp.get('format')}
        recovery = job.get('analysis', {}).get('recovery') if isinstance(job.get('analysis'), dict) else {}
        if isinstance(recovery, dict):
            manifest['recovery_rate'] = recovery.get('overall_recovery_rate')
            manifest['confidence'] = recovery.get('confidence')
    if isinstance(native_index, dict):
        manifest['native_methods_total'] = native_index.get('methods_total')
        manifest['native_classes_total'] = native_index.get('classes_total')
    if isinstance(job, dict):
        java_like = job.get('analysis', {}).get('java_like') if isinstance(job.get('analysis'), dict) else {}
        mr = java_like.get('method_recovery') if isinstance(java_like, dict) else None
        if isinstance(mr, list) and mr:
            manifest['method_recovery_total'] = len(mr)
            manifest['method_recovery_sample'] = mr[:50]
    validation = job.get('analysis', {}).get('java_validation') if isinstance(job, dict) and isinstance(job.get('analysis'), dict) else {}
    if isinstance(validation, dict) and validation:
        manifest['java_validation'] = {'status': validation.get('status'), 'files_total': validation.get('files_total'), 'files_ast_valid_before': validation.get('files_ast_valid_before'), 'files_ast_valid': validation.get('files_ast_valid'), 'files_repaired': validation.get('files_repaired'), 'repairs_total': validation.get('repairs_total'), 'remaining_ast_errors': validation.get('remaining_ast_errors'), 'javac': validation.get('javac')}
        (out_dir / 'VALIDATION.json').write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding='utf-8')
    (out_dir / 'MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    readme_lines = ['# Recovered Java Project', '', 'Auto-generated by Detranspiler from native library analysis.', '', f'- Files: {len(copied)}', f"- Recovery rate: {manifest.get('recovery_rate', 'n/a')}", '', '## Notes', '', '- Methods recovered from native DLL/SO via JNI heuristics.', '- Verify against original sources; stubs may remain.', '- See parent `analysis/report.html` for full pipeline report.', '']
    (out_dir / 'README.md').write_text('\n'.join(readme_lines), encoding='utf-8')
    return {'status': 'OK', 'output_dir': str(out_dir), 'source_root': str(src_root), 'files_copied': len(copied), 'files_skipped_low_confidence': len(skipped_low_confidence), 'manifest_path': str((out_dir / 'MANIFEST.json').resolve())}
