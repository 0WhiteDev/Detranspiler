from __future__ import annotations

import traceback
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, List, Optional

from detranspiler.diffing import run_diff


def _is_completed_analysis(path: Path) -> bool:
    if path.is_file() and path.name.lower() == 'job.json':
        return True
    if path.is_dir() and (path / 'job.json').is_file():
        return True
    return path.is_dir() and path.name.lower() == 'analysis' and (path.parent / 'job.json').is_file()


class DiffWorker:

    def __init__(self) -> None:
        self._lock = Lock()
        self._thread: Optional[Thread] = None
        self._running = False
        self._percent = 0
        self._message = 'Ready'
        self._logs: List[str] = []
        self._error: Optional[str] = None
        self._result: Optional[Dict[str, Any]] = None

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'running': self._running,
                'percent': self._percent,
                'message': self._message,
                'logs': list(self._logs),
                'error': self._error,
                'result': self._result,
            }

    def _log(self, message: str) -> None:
        with self._lock:
            self._logs.append(message)
            if len(self._logs) > 200:
                self._logs = self._logs[-200:]

    def start(self, config: Dict[str, Any]) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError('Differential analysis is already running')
            self._running = True
            self._percent = 5
            self._message = 'Preparing differential analysis'
            self._logs = []
            self._error = None
            self._result = None
        self._thread = Thread(target=self._run, args=(config,), daemon=True)
        self._thread.start()

    def _run(self, config: Dict[str, Any]) -> None:
        try:
            old_raw = str(config.get('old') or '').strip()
            new_raw = str(config.get('new') or '').strip()
            out_raw = str(config.get('out') or '').strip()
            if not old_raw:
                raise ValueError('Old input is required')
            if not new_raw:
                raise ValueError('New input is required')
            if not out_raw:
                raise ValueError('Output directory is required')
            old_path = Path(old_raw).expanduser()
            new_path = Path(new_raw).expanduser()
            if not old_path.exists():
                raise FileNotFoundError(f'Old input not found: {old_path}')
            if not new_path.exists():
                raise FileNotFoundError(f'New input not found: {new_path}')
            old_jar_raw = str(config.get('old_jar') or '').strip()
            new_jar_raw = str(config.get('new_jar') or '').strip()
            old_jar = Path(old_jar_raw).expanduser() if old_jar_raw else None
            new_jar = Path(new_jar_raw).expanduser() if new_jar_raw else None
            if old_jar is not None and not old_jar.is_file():
                raise FileNotFoundError(f'Old JAR not found: {old_jar}')
            if new_jar is not None and not new_jar.is_file():
                raise FileNotFoundError(f'New JAR not found: {new_jar}')
            ghidra_raw = str(config.get('ghidra_install_dir') or '').strip()
            ghidra_dir = Path(ghidra_raw).expanduser() if ghidra_raw else None
            use_ghidra = bool(config.get('use_ghidra', True))
            requires_analysis = not _is_completed_analysis(old_path) or not _is_completed_analysis(new_path)
            if requires_analysis and use_ghidra and (ghidra_dir is None or not ghidra_dir.is_dir()):
                raise FileNotFoundError('A valid Ghidra install directory is required for raw native inputs')
            self._log(f'Old: {old_path}')
            self._log(f'New: {new_path}')
            self._log('Analyzing inputs and building stable snapshots')
            with self._lock:
                self._percent = 15
                self._message = 'Comparing native analysis evidence'
            result = run_diff(
                old_path=old_path,
                new_path=new_path,
                out_dir=Path(out_raw).expanduser(),
                old_jar=old_jar,
                new_jar=new_jar,
                mode=str(config.get('mode') or 'AUTO'),
                use_ghidra=use_ghidra,
                ghidra_install_dir=ghidra_dir if use_ghidra else None,
                decompile_jar=bool(config.get('decompile_jar', True)),
                validate_java=bool(config.get('validate_java', True)),
                force=bool(config.get('force')),
            )
            with self._lock:
                self._result = result
                self._running = False
                self._percent = 100
                self._message = 'Differential analysis complete'
            self._log('Reports generated successfully')
        except Exception as exc:
            with self._lock:
                self._running = False
                self._percent = 100
                self._message = 'Differential analysis failed'
                self._error = str(exc)
            self._log(f'ERROR: {exc}')
            self._log(traceback.format_exc())
