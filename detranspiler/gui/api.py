from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

import detranspiler
from detranspiler.gui.analyzer import AnalysisWorker
from detranspiler.gui.session import load_job
from detranspiler.gui.server import AnalysisFileServer
from detranspiler.gui.settings import load_settings, save_settings as persist_settings
from detranspiler.reporting.html_theme import RE_THEME_CSS


class DetranspilerApi:

    def __init__(self) -> None:
        self._worker = AnalysisWorker(on_update=self._on_worker_update)
        self._server = AnalysisFileServer()
        self._view_urls: Dict[str, Optional[str]] = {'report': None, 'map': None}
        self._session_paths: Dict[str, Optional[str]] = {
            'out_dir': None,
            'pseudocode_dir': None,
            'jar_sources_dir': None,
            'native_map_dir': None,
        }

    def _on_worker_update(self, snap: Dict[str, Any]) -> None:
        if snap.get('running'):
            return
        summary = snap.get('summary')
        if isinstance(summary, dict) and not snap.get('error'):
            self._activate_session(summary)

    def get_version(self) -> str:
        return detranspiler.__version__

    def get_theme_css(self) -> str:
        return RE_THEME_CSS

    def get_settings(self) -> Dict[str, Any]:
        return load_settings()

    def save_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        persist_settings(settings)
        return {'ok': True}

    def pick_file(self, kind: str) -> Optional[str]:
        try:
            import webview
        except ImportError as e:
            raise RuntimeError('pywebview is not installed. Run: pip install pywebview') from e
        windows = webview.windows
        if not windows:
            return None
        window = windows[0]
        kind = (kind or 'any').lower()
        if kind == 'folder':
            result = window.create_file_dialog(webview.FOLDER_DIALOG)
        elif kind == 'dll':
            result = window.create_file_dialog(
                webview.OPEN_DIALOG,
                file_types=('Native libraries (*.dll;*.so;*.dylib)', 'All files (*.*)'),
            )
        elif kind == 'jar':
            result = window.create_file_dialog(
                webview.OPEN_DIALOG,
                file_types=('Java archives (*.jar)', 'All files (*.*)'),
            )
        elif kind == 'ghidra':
            result = window.create_file_dialog(webview.FOLDER_DIALOG)
        elif kind == 'pseudo_c':
            result = window.create_file_dialog(
                webview.OPEN_DIALOG,
                file_types=('C source (*.c)', 'All files (*.*)'),
            )
        elif kind == 'json':
            result = window.create_file_dialog(
                webview.OPEN_DIALOG,
                file_types=('JSON (*.json)', 'All files (*.*)'),
            )
        else:
            result = window.create_file_dialog(webview.OPEN_DIALOG)
        if not result:
            return None
        if isinstance(result, (list, tuple)):
            return str(result[0]) if result else None
        return str(result)

    def extract_native(self, config: Dict[str, Any]) -> Dict[str, Any]:
        from detranspiler.extract import ExtractionError, extract_native_library

        jar = str(config.get("jar") or "").strip()
        out = str(config.get("out") or "").strip()
        mode = str(config.get("mode") or "").strip().lower()
        if not jar:
            return {"ok": False, "code": "JAR_REQUIRED", "error": "Select an input JAR."}
        if not out:
            return {"ok": False, "code": "OUTPUT_REQUIRED", "error": "Select an output directory."}
        try:
            result = extract_native_library(
                jar_path=Path(jar),
                out_dir=Path(out),
                mode=mode,
            )
        except ExtractionError as exc:
            return {"ok": False, "code": exc.code, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "code": "UNEXPECTED_ERROR", "error": str(exc)}
        return {"ok": True, "result": result}


    def run_doctor(self) -> Dict[str, Any]:
        from detranspiler.doctor import collect_diagnostics

        settings = load_settings()
        ghidra = settings.get('ghidra_install_dir')
        return collect_diagnostics(
            ghidra_install_dir=Path(str(ghidra)).expanduser() if ghidra else None,
        )

    def open_external(self, url: str) -> Dict[str, Any]:
        if url:
            webbrowser.open(url)
        return {'ok': True}

    def reveal_in_explorer(self, path: str) -> Dict[str, Any]:
        p = Path(path).expanduser()
        if not p.exists():
            return {'ok': False, 'error': 'Path not found'}
        if sys.platform == 'win32':
            os.startfile(p if p.is_dir() else p.parent)
        elif sys.platform == 'darwin':
            import subprocess

            subprocess.Popen(['open', str(p if p.is_dir() else p.parent)])
        else:
            import subprocess

            subprocess.Popen(['xdg-open', str(p if p.is_dir() else p.parent)])
        return {'ok': True}

    def get_progress(self) -> Dict[str, Any]:
        snap = self._worker.snapshot()
        if isinstance(snap.get('summary'), dict) and not snap.get('running') and not snap.get('error'):
            if not any(self._view_urls.values()):
                self._activate_session(snap['summary'])
        snap['view_urls'] = dict(self._view_urls)
        return snap

    def ensure_view_urls(self) -> Dict[str, Any]:
        snap = self._worker.snapshot()
        summary = snap.get('summary')
        if isinstance(summary, dict):
            self._activate_session(summary)
        return {'ok': bool(any(self._view_urls.values())), 'view_urls': dict(self._view_urls)}

    def _activate_session(self, summary: Dict[str, Any]) -> Dict[str, Optional[str]]:
        out_dir = summary.get('out_dir')
        if isinstance(out_dir, str):
            self._session_paths['out_dir'] = out_dir
        artifacts = summary.get('artifacts') if isinstance(summary.get('artifacts'), dict) else {}
        pseudo = artifacts.get('pseudocode_dir')
        if isinstance(pseudo, str):
            self._session_paths['pseudocode_dir'] = pseudo
        elif isinstance(out_dir, str):
            candidate = Path(out_dir) / 'pseudocode'
            if candidate.is_dir():
                self._session_paths['pseudocode_dir'] = str(candidate)
        if isinstance(out_dir, str):
            jar_src = Path(out_dir) / 'pseudocode' / 'jar_sources'
            if jar_src.is_dir():
                self._session_paths['jar_sources_dir'] = str(jar_src)
        native_map = artifacts.get('native_map_dir')
        if isinstance(native_map, str) and Path(native_map).is_dir():
            self._session_paths['native_map_dir'] = native_map
        elif isinstance(out_dir, str):
            candidate = Path(out_dir) / 'native_map'
            if candidate.is_dir():
                self._session_paths['native_map_dir'] = str(candidate)
        analysis_dir = summary.get('analysis_dir')
        if not isinstance(analysis_dir, str) or not analysis_dir.strip():
            self._view_urls = {'report': None, 'map': None}
            return dict(self._view_urls)
        try:
            base = self._server.serve(Path(analysis_dir))
        except Exception:
            self._view_urls = {'report': None, 'map': None}
            return dict(self._view_urls)
        self._view_urls = {
            'report': f'{base}report.html' if artifacts.get('report_html') else None,
            'map': f'{base}re_map.html' if artifacts.get('re_map_html') else None,
        }
        return dict(self._view_urls)

    def _refresh_session_reports(self, out_dir: Path) -> None:
        analysis_dir = out_dir / 'analysis'
        if not analysis_dir.is_dir():
            return
        try:
            job = load_job(out_dir)
            from detranspiler.reporting.report import write_html_report
            from detranspiler.reporting.re_map import write_re_map_from_job
            write_html_report(job=job, out_path=analysis_dir / 'report.html')
            write_re_map_from_job(job=job, analysis_dir=analysis_dir)
        except Exception:
            pass

    def load_session(self, out_dir: str) -> Dict[str, Any]:
        path = Path(out_dir).expanduser()
        if not path.is_dir():
            return {'ok': False, 'error': f'Directory not found: {path}'}
        try:
            self._refresh_session_reports(path)
            summary = self._worker.load_existing(path)
            view_urls = self._activate_session(summary)
            summary = dict(summary)
            summary['view_urls'] = view_urls
            return {'ok': True, 'summary': summary}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def start_analysis(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if self._worker.snapshot().get('running'):
            return {'ok': False, 'error': 'Analysis is already running'}
        persist_settings(config)
        self._server.stop()
        self._view_urls = {'report': None, 'map': None}
        self._session_paths = {
            'out_dir': None,
            'pseudocode_dir': None,
            'jar_sources_dir': None,
            'native_map_dir': None,
        }
        try:
            self._worker.start(config)
            return {'ok': True, 'view_urls': dict(self._view_urls)}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def shutdown(self) -> None:
        self._server.stop()

    def get_sources_tree(self) -> Dict[str, Any]:
        from detranspiler.gui.views.sources import build_sources_tree

        pseudo = self._session_paths.get('pseudocode_dir')
        if not isinstance(pseudo, str) or not Path(pseudo).is_dir():
            return {'status': 'SKIPPED', 'error': 'No active session with pseudocode output'}
        jar = self._session_paths.get('jar_sources_dir')
        jar_path = Path(jar) if isinstance(jar, str) else None
        return build_sources_tree(pseudocode_dir=Path(pseudo), jar_sources_dir=jar_path)

    def get_source_file(self, rel_path: str) -> Dict[str, Any]:
        from detranspiler.gui.views.sources import read_source_file

        pseudo = self._session_paths.get('pseudocode_dir')
        if not isinstance(pseudo, str):
            return {'status': 'ERROR', 'error': 'No active session'}
        doc = read_source_file(rel_path=rel_path, pseudocode_dir=Path(pseudo))
        doc['status'] = 'OK'
        return doc

    def get_native_map_tree(self) -> Dict[str, Any]:
        from detranspiler.gui.views.native_map import build_native_map_tree

        out_dir = self._session_paths.get('out_dir')
        if not isinstance(out_dir, str) or not Path(out_dir).is_dir():
            return {'status': 'SKIPPED', 'error': 'No active session'}
        return build_native_map_tree(out_dir=Path(out_dir))

    def get_native_map_method(self, method_id: str) -> Dict[str, Any]:
        from detranspiler.gui.views.native_map import read_native_map_method

        out_dir = self._session_paths.get('out_dir')
        if not isinstance(out_dir, str) or not Path(out_dir).is_dir():
            return {'status': 'ERROR', 'error': 'No active session'}
        return read_native_map_method(out_dir=Path(out_dir), method_id=method_id)

    def open_native_map_folder(self) -> Dict[str, Any]:
        path = self._session_paths.get('native_map_dir')
        if not isinstance(path, str):
            return {'ok': False, 'error': 'Native map not available'}
        return self.reveal_in_explorer(path)
