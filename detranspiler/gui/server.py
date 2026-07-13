from __future__ import annotations
import mimetypes
import threading
import time
import urllib.error
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

class _AnalysisHandler(SimpleHTTPRequestHandler):
    extensions_map = {**getattr(SimpleHTTPRequestHandler, 'extensions_map', {}), '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml'}

    def __init__(self, *args, directory: str, **kwargs):
        self._directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format: str, *args) -> None:
        return

    def end_headers(self) -> None:
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def translate_path(self, path: str) -> str:
        from urllib.parse import unquote
        path = unquote(path.split('?', 1)[0])
        rel = path.lstrip('/')
        if not rel or rel.endswith('/'):
            rel = 'report.html'
        target = Path(self._directory) / rel
        if target.is_dir():
            target = target / 'report.html'
        return str(target)

class AnalysisFileServer:

    def __init__(self) -> None:
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._analysis_dir: Optional[Path] = None
        self._port: Optional[int] = None
        self._lock = threading.Lock()
        self._probe_filename = 'report.html'

    @property
    def base_url(self) -> Optional[str]:
        if self._port is None:
            return None
        return f'http://127.0.0.1:{self._port}/'

    def _stop_unlocked(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        self._thread = None
        self._port = None
        self._analysis_dir = None
        self._probe_filename = 'report.html'

    def serve(self, analysis_dir: Path, *, probe_filename: str='report.html') -> str:
        analysis_dir = analysis_dir.expanduser().resolve()
        if not analysis_dir.is_dir():
            raise FileNotFoundError(str(analysis_dir))
        with self._lock:
            if self._analysis_dir == analysis_dir and self._port is not None and self._probe_filename == probe_filename:
                ready = self._probe_ready()
                if ready:
                    return self.base_url or ''
            self._stop_unlocked()
            self._probe_filename = probe_filename
            handler = partial(_AnalysisHandler, directory=str(analysis_dir))
            self._server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            self._port = self._server.server_address[1]
            self._analysis_dir = analysis_dir
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        if not self.wait_ready(timeout=5.0):
            self.stop()
            raise RuntimeError('Local report server failed to start')
        return self.base_url or ''

    def _probe_ready(self) -> bool:
        base = self.base_url
        if not base:
            return False
        try:
            with urllib.request.urlopen(f'{base}{self._probe_filename}', timeout=0.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def wait_ready(self, *, timeout: float=3.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._probe_ready():
                return True
            time.sleep(0.05)
        return False

    def stop(self) -> None:
        with self._lock:
            self._stop_unlocked()

    def artifact_url(self, filename: str) -> Optional[str]:
        if not self.base_url:
            return None
        return f"{self.base_url}{filename.lstrip('/')}"

def guess_mime(path: Path) -> str:
    mime, _ = mimetypes.guess_type(str(path))
    return mime or 'application/octet-stream'
