from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
DEFAULT_SETTINGS: Dict[str, Any] = {'ghidra_install_dir': '', 'use_ghidra': True, 'input_dll': '', 'jar_path': '', 'use_jar': False, 'decompile_jar': True, 'validate_java': True, 'compile_java': False, 'out_dir': '', 'mode': 'AUTO', 'force': False, 'pseudo_c': '', 'functions_json': '', 'strings_json': '', 'diff_old': '', 'diff_new': '', 'diff_out': '', 'diff_old_jar': '', 'diff_new_jar': '', 'diff_mode': 'AUTO', 'diff_force': False, 'diff_use_ghidra': True, 'window_width': 1280, 'window_height': 860}

def settings_path() -> Path:
    base = os.environ.get('APPDATA') or os.environ.get('LOCALAPPDATA')
    if base:
        root = Path(base) / 'Detranspiler'
    else:
        root = Path.home() / '.detranspiler'
    root.mkdir(parents=True, exist_ok=True)
    return root / 'settings.json'

def load_settings() -> Dict[str, Any]:
    path = settings_path()
    if not path.is_file():
        merged = dict(DEFAULT_SETTINGS)
        env_ghidra = os.environ.get('GHIDRA_INSTALL_DIR')
        if env_ghidra:
            merged['ghidra_install_dir'] = env_ghidra
        return merged
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return dict(DEFAULT_SETTINGS)
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(raw, dict):
        merged.update(raw)
    return merged

def save_settings(data: Dict[str, Any]) -> None:
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        merged.update(data)
    settings_path().write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding='utf-8')
