from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional

def assets_dir() -> Path:
    return Path(__file__).resolve().parent / 'assets'

def _enable_local_file_access() -> None:
    if sys.platform == 'win32':
        flag = '--allow-file-access-from-files'
        current = os.environ.get('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', '')
        if flag not in current:
            os.environ['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'] = f'{current} {flag}'.strip()

def launch_gui(*, width: Optional[int]=None, height: Optional[int]=None) -> int:
    try:
        import webview
    except ImportError:
        print('GUI requires pywebview. Install with:')
        print('  pip install pywebview')
        print('  pip install -e ".[gui]"')
        return 1
    from detranspiler.gui.api import DetranspilerApi
    from detranspiler.gui.settings import load_settings
    _enable_local_file_access()
    settings = load_settings()
    api = DetranspilerApi()
    index_html = assets_dir() / 'index.html'
    if not index_html.is_file():
        print(f'Missing GUI assets: {index_html}')
        return 1
    window = webview.create_window(title='Detranspiler · 0WhiteDev', url=str(index_html), js_api=api, width=int(width or settings.get('window_width') or 1280), height=int(height or settings.get('window_height') or 860), min_size=(960, 640), background_color='#0d1117')

    def on_closed() -> None:
        api.shutdown()
    window.events.closed += on_closed
    webview.start(debug=False)
    return 0
