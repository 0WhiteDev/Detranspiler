import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

def _resolve_analyze_headless(ghidra_install_dir: Path) -> Path:
    candidates = [ghidra_install_dir / 'support' / 'analyzeHeadless.bat', ghidra_install_dir / 'support' / 'analyzeHeadless', ghidra_install_dir / 'analyzeHeadless.bat', ghidra_install_dir / 'analyzeHeadless']
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(f'analyzeHeadless not found under: {ghidra_install_dir}')

def run_headless_decompile(*, ghidra_install_dir: Path, binary_path: Path, project_dir: Path, project_name: str, output_c_path: Path, output_functions_json_path: Optional[Path]=None, output_strings_json_path: Optional[Path]=None, logs_dir: Optional[Path]=None, timeout_seconds: int=60 * 60) -> Dict[str, Any]:
    analyze_headless = _resolve_analyze_headless(ghidra_install_dir)
    script_dir = Path(__file__).resolve().parent / 'scripts'
    script_file = script_dir / 'ExportPseudoC.java'
    if not script_file.is_file():
        raise FileNotFoundError(str(script_file))
    functions_script_file = script_dir / 'ExportFunctionsJson.java'
    if output_functions_json_path is not None and (not functions_script_file.is_file()):
        raise FileNotFoundError(str(functions_script_file))
    strings_script_file = script_dir / 'ExportStringsJson.java'
    if output_strings_json_path is not None and (not strings_script_file.is_file()):
        raise FileNotFoundError(str(strings_script_file))
    project_dir.mkdir(parents=True, exist_ok=True)
    output_c_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(analyze_headless), str(project_dir), project_name, '-import', str(binary_path), '-scriptPath', str(script_dir), '-postScript', 'ExportPseudoC.java', str(output_c_path)]
    if output_functions_json_path is not None:
        output_functions_json_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.extend(['-postScript', 'ExportFunctionsJson.java', str(output_functions_json_path)])
    if output_strings_json_path is not None:
        output_strings_json_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.extend(['-postScript', 'ExportStringsJson.java', str(output_strings_json_path)])
    if analyze_headless.suffix.lower() in {'.bat', '.cmd'}:
        cmd = ['cmd.exe', '/c', *cmd]
    env = os.environ.copy()
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout_seconds)
    stdout_path = None
    stderr_path = None
    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = logs_dir / 'ghidra_stdout.txt'
        stderr_path = logs_dir / 'ghidra_stderr.txt'
        stdout_path.write_text(p.stdout or '', encoding='utf-8', errors='replace')
        stderr_path.write_text(p.stderr or '', encoding='utf-8', errors='replace')
    output_c_ok = output_c_path.is_file()
    output_functions_ok = output_functions_json_path.is_file() if output_functions_json_path is not None else None
    output_strings_ok = output_strings_json_path.is_file() if output_strings_json_path is not None else None
    ok = p.returncode == 0 and (output_c_ok or bool(output_functions_ok) or bool(output_strings_ok))
    return {'status': 'OK' if ok else 'ERROR', 'returncode': p.returncode, 'stdout_path': str(stdout_path.resolve()) if stdout_path else None, 'stderr_path': str(stderr_path.resolve()) if stderr_path else None, 'output_c_path': str(output_c_path.resolve()) if output_c_path.is_file() else None, 'output_functions_json_path': str(output_functions_json_path.resolve()) if output_functions_json_path is not None and output_functions_json_path.is_file() else None, 'output_strings_json_path': str(output_strings_json_path.resolve()) if output_strings_json_path is not None and output_strings_json_path.is_file() else None, 'project_dir': str(project_dir.resolve())}
