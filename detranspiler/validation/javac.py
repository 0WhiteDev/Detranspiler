from __future__ import annotations
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

_ERROR_RE = re.compile(r'(?m)^(?P<path>.+?\.java):(?P<line>\d+): error: (?P<message>.+)$')
_TRUNCATED_RE = re.compile(r'only showing the first .* errors', re.IGNORECASE)

def _diagnostic_code(message: str) -> str:
    lowered = message.lower()
    patterns = (
        ('missing_semicolon', "';' expected"),
        ('unresolved_symbol', 'cannot find symbol'),
        ('type_mismatch', 'incompatible types'),
        ('unreachable_code', 'unreachable statement'),
        ('duplicate_method', 'is already defined in'),
        ('invalid_constructor', 'invalid method declaration; return type required'),
        ('invalid_cast', 'cannot be cast'),
        ('return_type_mismatch', 'missing return statement'),
        ('access_error', 'cannot be accessed from outside package'),
        ('preview_feature', 'preview feature'),
    )
    for code, marker in patterns:
        if marker in lowered:
            return code
    return 'javac_error'

def compile_java_sources(sources_root: Path, *, timeout_seconds: int=120, max_files: int=2000) -> Dict[str, Any]:
    files = sorted(sources_root.rglob('*.java'))[:max_files]
    if not files:
        return {'status': 'SKIPPED_NO_JAVA_SOURCES', 'files_total': 0, 'files_compilable': 0, 'compilation_rate': None, 'diagnostics': []}
    javac = shutil.which('javac')
    if not javac:
        return {'status': 'SKIPPED_JAVAC_NOT_FOUND', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'diagnostics': []}
    with tempfile.TemporaryDirectory(prefix='detranspiler-javac-') as temp_dir:
        temp = Path(temp_dir)
        classes = temp / 'classes'
        empty_path = temp / 'empty'
        classes.mkdir()
        empty_path.mkdir()
        argfile = temp / 'sources.args'
        argfile.write_text('\n'.join(f'"{path.resolve().as_posix()}"' for path in files), encoding='utf-8')
        command = [javac, '-J-Xmx512m', '-J-XX:ActiveProcessorCount=2', '-J-Duser.language=en', '-J-Duser.country=US', '-proc:none', '-implicit:none', '-Xlint:none', '-Xmaxerrs', '10000', '-classpath', str(empty_path), '-sourcepath', str(empty_path), '-d', str(classes), f'@{argfile}']
        environment = os.environ.copy()
        for key in ('JDK_JAVAC_OPTIONS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS'):
            environment.pop(key, None)
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', timeout=timeout_seconds, shell=False, env=environment)
        except subprocess.TimeoutExpired:
            return {'status': 'TIMEOUT', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'timeout_seconds': timeout_seconds, 'diagnostics': []}
        except OSError as exc:
            return {'status': 'ERROR', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'error': repr(exc), 'diagnostics': []}
        output = '\n'.join(part for part in (completed.stdout, completed.stderr) if part)
        if _TRUNCATED_RE.search(output):
            return {'status': 'INCOMPLETE_DIAGNOSTICS', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'exit_code': completed.returncode, 'diagnostic': output[-4000:], 'diagnostics': []}
        by_resolved = {str(path.resolve()).lower(): path for path in files}
        failed: set[Path] = set()
        diagnostics: List[Dict[str, Any]] = []
        for match in _ERROR_RE.finditer(output):
            resolved = str(Path(match.group('path')).resolve()).lower()
            path = by_resolved.get(resolved)
            if path is not None:
                failed.add(path)
            diagnostics.append({'code': _diagnostic_code(match.group('message')), 'path': str(path or match.group('path')), 'line': int(match.group('line')), 'message': match.group('message').strip()})
        if completed.returncode != 0 and not diagnostics:
            return {'status': 'ERROR_UNATTRIBUTED', 'files_total': len(files), 'files_compilable': None, 'compilation_rate': None, 'exit_code': completed.returncode, 'diagnostic': output[-4000:], 'diagnostics': []}
        compilable = len(files) - len(failed)
        return {'status': 'OK' if completed.returncode == 0 else 'PARTIAL', 'files_total': len(files), 'files_compilable': compilable, 'files_failed': len(failed), 'compilation_rate': round(compilable / len(files), 3), 'failed_files': [str(path.resolve()) for path in sorted(failed)[:200]], 'exit_code': completed.returncode, 'diagnostics': diagnostics[:5000]}
