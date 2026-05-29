import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

def _pkg_version(mod: Any) -> Optional[str]:
    for attr in ('__version__', 'VERSION'):
        try:
            v = getattr(mod, attr)
        except Exception:
            v = None
        if v:
            return str(v)
    return None

def collect_diagnostics(*, ghidra_install_dir: Optional[Path]=None) -> Dict[str, Any]:
    py = {'version': sys.version.split()[0], 'executable': sys.executable, 'ok': sys.version_info >= (3, 10)}
    deps: Dict[str, Any] = {}
    for name in ('lief', 'pefile', 'tqdm', 'angr'):
        try:
            mod = importlib.import_module(name)
            deps[name] = {'status': 'OK', 'version': _pkg_version(mod)}
        except Exception as e:
            deps[name] = {'status': 'MISSING', 'error': repr(e)}
    java: Dict[str, Any]
    try:
        p = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=10)
        out = (p.stderr or '') + ('\n' + p.stdout if p.stdout else '')
        java = {'status': 'OK' if p.returncode == 0 else 'ERROR', 'returncode': p.returncode, 'output': out.strip()}
    except Exception as e:
        java = {'status': 'MISSING', 'error': repr(e)}
    ghidra_dir_raw = str(ghidra_install_dir) if ghidra_install_dir else os.environ.get('GHIDRA_INSTALL_DIR')
    ghidra: Dict[str, Any] = {'install_dir': ghidra_dir_raw, 'analyze_headless': None, 'status': 'SKIPPED_NO_INSTALL_DIR' if not ghidra_dir_raw else 'UNKNOWN'}
    if ghidra_dir_raw:
        try:
            from detranspiler.ghidra.headless import _resolve_analyze_headless
            ah = _resolve_analyze_headless(Path(ghidra_dir_raw))
            ghidra['analyze_headless'] = str(ah.resolve())
            ghidra['status'] = 'OK'
        except Exception as e:
            ghidra['status'] = 'ERROR'
            ghidra['error'] = repr(e)
    return {'python': py, 'deps': deps, 'java': java, 'ghidra': ghidra}

def format_diagnostics_text(diag: Dict[str, Any]) -> str:
    lines = []
    py = diag.get('python', {})
    lines.append('Python')
    lines.append(f"  version: {py.get('version')}")
    lines.append(f"  exe: {py.get('executable')}")
    lines.append(f"  ok: {py.get('ok')}")
    lines.append('')
    lines.append('Dependencies')
    deps = diag.get('deps', {})
    for name in ('lief', 'pefile', 'tqdm', 'angr'):
        d = deps.get(name, {})
        status = d.get('status')
        ver = d.get('version')
        suffix = f' ({ver})' if ver else ''
        lines.append(f'  {name}: {status}{suffix}')
    lines.append('')
    java = diag.get('java', {})
    lines.append('Java')
    lines.append(f"  status: {java.get('status')}")
    if java.get('status') != 'OK':
        if java.get('error'):
            lines.append(f"  error: {java.get('error')}")
    else:
        out = str(java.get('output') or '')
        if out:
            first = out.splitlines()[0]
            lines.append(f'  output: {first}')
    lines.append('')
    ghidra = diag.get('ghidra', {})
    lines.append('Ghidra')
    lines.append(f"  install_dir: {ghidra.get('install_dir')}")
    lines.append(f"  status: {ghidra.get('status')}")
    if ghidra.get('analyze_headless'):
        lines.append(f"  analyzeHeadless: {ghidra.get('analyze_headless')}")
    if ghidra.get('error'):
        lines.append(f"  error: {ghidra.get('error')}")
    return '\n'.join(lines) + '\n'

def run_doctor(*, ghidra_install_dir: Optional[Path], as_json: bool=False) -> int:
    diag = collect_diagnostics(ghidra_install_dir=ghidra_install_dir)
    if as_json:
        print(json.dumps(diag, ensure_ascii=False, indent=2))
    else:
        print(format_diagnostics_text(diag))
    py_ok = bool(diag.get('python', {}).get('ok'))
    deps = diag.get('deps', {})
    base_ok = all((deps.get(n, {}).get('status') == 'OK' for n in ('lief', 'pefile', 'tqdm')))
    ghidra_status = diag.get('ghidra', {}).get('status')
    java_status = diag.get('java', {}).get('status')
    ok = py_ok and base_ok and (java_status in ('OK', 'MISSING')) and (ghidra_status in ('OK', 'SKIPPED_NO_INSTALL_DIR', 'ERROR'))
    return 0 if ok else 1
