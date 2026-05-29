import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
CFR_URL = 'https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar'

def _find_java() -> Optional[str]:
    return shutil.which('java')

def _find_cfr_jar(*, cache_dir: Path) -> Optional[Path]:
    candidates = [cache_dir / 'cfr.jar', cache_dir / 'cfr-0.152.jar']
    for c in candidates:
        if c.is_file():
            return c
    env_cfr = shutil.which('cfr')
    if env_cfr:
        return Path(env_cfr)
    return None

def _download_cfr(*, cache_dir: Path) -> Optional[Path]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / 'cfr-0.152.jar'
    if target.is_file():
        return target
    try:
        urllib.request.urlretrieve(CFR_URL, target)
    except Exception:
        return None
    return target if target.is_file() else None

def decompile_jar_with_cfr(*, jar_path: Path, out_dir: Path, cache_dir: Optional[Path]=None, download_if_missing: bool=True, timeout_sec: int=600) -> Dict[str, Any]:
    jar_path = jar_path.expanduser().resolve()
    if not jar_path.is_file():
        return {'status': 'ERROR', 'error': 'jar_not_found', 'path': str(jar_path)}
    java_bin = _find_java()
    if not java_bin:
        return {'status': 'SKIPPED_NO_JAVA'}
    cache = cache_dir or out_dir / '.tools'
    cfr_jar = _find_cfr_jar(cache_dir=cache)
    if cfr_jar is None and download_if_missing:
        cfr_jar = _download_cfr(cache_dir=cache)
    if cfr_jar is None:
        return {'status': 'SKIPPED_NO_CFR'}
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [java_bin, '-jar', str(cfr_jar), str(jar_path), '--outputdir', str(out_dir), '--silent', 'true']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'cfr_jar': str(cfr_jar)}
    except Exception as e:
        return {'status': 'EXCEPTION', 'error': repr(e), 'cfr_jar': str(cfr_jar)}
    java_files = sorted(out_dir.rglob('*.java'))
    return {'status': 'OK' if proc.returncode == 0 else 'CFR_ERROR', 'returncode': proc.returncode, 'cfr_jar': str(cfr_jar.resolve()), 'output_dir': str(out_dir), 'java_files_written': len(java_files), 'stdout_tail': (proc.stdout or '')[-4000:], 'stderr_tail': (proc.stderr or '')[-4000:]}
