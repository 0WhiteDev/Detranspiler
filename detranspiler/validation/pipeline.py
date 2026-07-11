from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any, Dict, List
from detranspiler.validation.javac import compile_java_sources
from detranspiler.validation.java_ast import parse_java_source
from detranspiler.validation.repairs import apply_safe_repairs

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def validate_and_repair_java(*, sources_root: Path, compile_with_javac: bool=False, max_files: int=2000) -> Dict[str, Any]:
    sources_root = sources_root.expanduser().resolve()
    if not sources_root.is_dir():
        return {'status': 'SKIPPED_NO_SOURCES', 'parser': 'internal_java_ast', 'javac': {'status': 'DISABLED' if not compile_with_javac else 'SKIPPED_NO_SOURCES'}}
    files = sorted(sources_root.rglob('*.java'))[:max_files]
    file_reports: List[Dict[str, Any]] = []
    javac_before = compile_java_sources(sources_root, max_files=max_files) if compile_with_javac else {'status': 'DISABLED', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'diagnostics': []}
    repairs_total = 0
    files_repaired = 0
    for path in files:
        original = path.read_text(encoding='utf-8', errors='replace')
        before = parse_java_source(original, path=path)
        repaired, repairs = apply_safe_repairs(original, path=path)
        changed = repaired != original
        if changed:
            path.write_text(repaired, encoding='utf-8')
            files_repaired += 1
        after = parse_java_source(repaired, path=path)
        repairs_total += len(repairs)
        file_reports.append({'path': str(path), 'relative_path': path.relative_to(sources_root).as_posix(), 'changed': changed, 'sha256_before': _digest(original), 'sha256_after': _digest(repaired), 'repairs': repairs, 'ast_status_before': before.get('status'), 'ast_status_after': after.get('status'), 'remaining_diagnostics': after.get('diagnostics') or [], 'methods_total': after.get('methods_total', 0)})
    javac = compile_java_sources(sources_root, max_files=max_files) if compile_with_javac else {'status': 'DISABLED', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None}
    remaining_ast = sum(len(item.get('remaining_diagnostics') or []) for item in file_reports)
    files_ast_valid_before = sum(1 for item in file_reports if item.get('ast_status_before') == 'OK')
    files_ast_valid = sum(1 for item in file_reports if item.get('ast_status_after') == 'OK')
    categories: Dict[str, int] = {}
    for item in file_reports:
        for diagnostic in item.get('remaining_diagnostics') or []:
            code = str(diagnostic.get('code') or 'unknown')
            categories[code] = categories.get(code, 0) + 1
    for diagnostic in javac.get('diagnostics') or []:
        code = str(diagnostic.get('code') or 'javac_error')
        categories[code] = categories.get(code, 0) + 1
    status = 'OK'
    if remaining_ast or javac.get('status') in {'PARTIAL', 'ERROR', 'ERROR_UNATTRIBUTED', 'INCOMPLETE_DIAGNOSTICS', 'TIMEOUT'}:
        status = 'PARTIAL'
    return {'status': status, 'parser': 'internal_java_ast', 'sources_dir': str(sources_root), 'files_total': len(files), 'files_ast_valid_before': files_ast_valid_before, 'ast_valid_rate_before': round(files_ast_valid_before / len(files), 3) if files else 0.0, 'files_ast_valid': files_ast_valid, 'ast_valid_rate': round(files_ast_valid / len(files), 3) if files else 0.0, 'files_repaired': files_repaired, 'repairs_total': repairs_total, 'remaining_ast_errors': remaining_ast, 'remaining_error_categories': categories, 'javac_enabled': compile_with_javac, 'javac_before_repairs': javac_before, 'javac': javac, 'files': file_reports[:max_files]}
