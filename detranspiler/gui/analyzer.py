from __future__ import annotations
import traceback
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Optional
from detranspiler.gui.session import discover_artifacts, open_session
from detranspiler.pipeline.runner import run_pipeline

class AnalysisWorker:

    def __init__(self, on_update: Optional[Callable[[Dict[str, Any]], None]]=None) -> None:
        self._lock = Lock()
        self._thread: Optional[Thread] = None
        self._running = False
        self._percent = 0
        self._phase = 'idle'
        self._message = 'Ready'
        self._logs: List[str] = []
        self._error: Optional[str] = None
        self._job: Optional[Dict[str, Any]] = None
        self._summary: Optional[Dict[str, Any]] = None
        self._on_update = on_update

    def _emit(self) -> None:
        if self._on_update is not None:
            try:
                self._on_update(self.snapshot())
            except Exception:
                pass

    def _log(self, line: str) -> None:
        with self._lock:
            self._logs.append(line)
            if len(self._logs) > 500:
                self._logs = self._logs[-500:]
        self._emit()

    def _set_progress(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._phase = str(payload.get('phase') or self._phase)
            self._percent = int(payload.get('percent') or self._percent)
            self._message = str(payload.get('message') or self._message)
        self._log(f'[{self._percent:>3}%] {self._message}')
        self._emit()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {'running': self._running, 'percent': self._percent, 'phase': self._phase, 'message': self._message, 'logs': list(self._logs), 'error': self._error, 'summary': self._summary}

    @property
    def job(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._job

    def load_existing(self, out_dir: Path) -> Dict[str, Any]:
        with self._lock:
            if self._running:
                raise RuntimeError('Analysis is already running')
        try:
            job, summary = open_session(out_dir)
            with self._lock:
                self._job = job
                self._summary = summary
                self._running = False
                self._percent = 100
                self._phase = 'loaded'
                self._message = 'Loaded existing analysis session'
                self._error = None
            self._log(f"Loaded session: {summary.get('out_dir')}")
            self._emit()
            return summary
        except Exception as e:
            with self._lock:
                self._error = str(e)
            self._log(f'ERROR: {e}')
            self._emit()
            raise

    def start(self, config: Dict[str, Any]) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError('Analysis is already running')
            self._running = True
            self._percent = 0
            self._phase = 'starting'
            self._message = 'Starting analysis…'
            self._error = None
            self._logs = []
            self._job = None
            self._summary = None
        self._emit()
        self._thread = Thread(target=self._run, args=(config,), daemon=True)
        self._thread.start()

    def _run(self, config: Dict[str, Any]) -> None:
        try:
            input_path = Path(str(config.get('input_dll') or '')).expanduser()
            out_dir = Path(str(config.get('out_dir') or '')).expanduser()
            if not input_path.is_file():
                raise FileNotFoundError(f'Input binary not found: {input_path}')
            if not str(out_dir):
                raise ValueError('Output directory is required')
            use_ghidra = bool(config.get('use_ghidra', True))
            ghidra_dir_raw = config.get('ghidra_install_dir')
            ghidra_install_dir = Path(str(ghidra_dir_raw)).expanduser() if ghidra_dir_raw else None
            if use_ghidra and (ghidra_install_dir is None or not ghidra_install_dir.is_dir()):
                raise FileNotFoundError('Ghidra install directory is required when Ghidra is enabled')
            use_jar = bool(config.get('use_jar'))
            jar_path = None
            if use_jar:
                jar_raw = config.get('jar_path')
                if not jar_raw:
                    raise ValueError('JAR path is required when JAR recovery is enabled')
                jar_path = Path(str(jar_raw)).expanduser()
                if not jar_path.is_file():
                    raise FileNotFoundError(f'JAR not found: {jar_path}')
            pseudo_c = config.get('pseudo_c')
            functions_json = config.get('functions_json')
            strings_json = config.get('strings_json')
            job = run_pipeline(input_path=input_path, out_dir=out_dir, requested_mode=str(config.get('mode') or 'AUTO'), use_ghidra=use_ghidra, ghidra_install_dir=ghidra_install_dir if use_ghidra else None, external_pseudo_c_path=Path(str(pseudo_c)).expanduser() if pseudo_c else None, external_functions_json_path=Path(str(functions_json)).expanduser() if functions_json else None, external_strings_json_path=Path(str(strings_json)).expanduser() if strings_json else None, jar_path=jar_path, force=bool(config.get('force')), decompile_jar=bool(config.get('decompile_jar', True)), validate_java=bool(config.get('validate_java', True)), compile_java=bool(config.get('compile_java', False)), progress_callback=self._set_progress)
            summary = discover_artifacts(job, out_dir)
            with self._lock:
                self._job = job
                self._summary = summary
                self._running = False
                self._percent = 100
                self._phase = 'done'
                self._message = 'Analysis complete'
            self._log('Analysis finished successfully')
        except Exception as e:
            with self._lock:
                self._running = False
                self._phase = 'error'
                self._error = str(e)
                self._message = f'Analysis failed: {e}'
            self._log(f'ERROR: {e}')
            self._log(traceback.format_exc())
        finally:
            self._emit()
