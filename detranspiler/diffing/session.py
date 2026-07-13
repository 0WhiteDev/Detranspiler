from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from detranspiler.diffing.compare import compare_snapshots
from detranspiler.diffing.report import write_reports
from detranspiler.diffing.snapshot import build_snapshot
from detranspiler.pipeline.runner import run_pipeline


class DiffError(RuntimeError):
    pass


def _analysis_root(path: Path) -> Optional[Path]:
    path = path.expanduser().resolve()
    if path.is_file() and path.name.lower() == 'job.json':
        return path.parent
    if path.is_dir() and (path / 'job.json').is_file():
        return path
    if path.is_dir() and path.name.lower() == 'analysis' and (path.parent / 'job.json').is_file():
        return path.parent
    return None


def _prepare_input(path: Path, target: Path, *, jar_path: Optional[Path], mode: str, use_ghidra: bool, ghidra_install_dir: Optional[Path], decompile_jar: bool, validate_java: bool) -> Path:
    existing = _analysis_root(path)
    if existing is not None:
        return existing
    source = path.expanduser().resolve()
    if not source.is_file():
        raise DiffError(f'Input is neither a native binary nor an analysis directory: {path}')
    run_pipeline(
        input_path=source,
        out_dir=target,
        requested_mode=mode,
        use_ghidra=use_ghidra,
        ghidra_install_dir=ghidra_install_dir,
        jar_path=jar_path,
        force=False,
        decompile_jar=decompile_jar,
        validate_java=validate_java,
        compile_java=False,
    )
    return target


def _validate_output(output: Path, inputs: tuple[Path, Path]) -> None:
    for value in inputs:
        source = value.expanduser().resolve()
        if output == source or output in source.parents:
            raise DiffError(f'Output directory would replace an input: {output}')


def _remove_output(path: Path) -> None:
    resolved = path.resolve()
    cwd = Path.cwd().resolve()
    if resolved == cwd or resolved.parent == resolved:
        raise DiffError(f'Refusing to replace unsafe output directory: {resolved}')
    shutil.rmtree(resolved)


def run_diff(*, old_path: Path, new_path: Path, out_dir: Path, old_jar: Optional[Path]=None, new_jar: Optional[Path]=None, mode: str='AUTO', use_ghidra: bool=True, ghidra_install_dir: Optional[Path]=None, decompile_jar: bool=True, validate_java: bool=True, force: bool=False) -> Dict[str, Any]:
    output = out_dir.expanduser().resolve()
    _validate_output(output, (old_path, new_path))
    if output.exists():
        if not force:
            raise DiffError(f'Output directory already exists: {output}')
        _remove_output(output)
    output.mkdir(parents=True)
    try:
        old_root = _prepare_input(old_path, output / 'old_analysis', jar_path=old_jar, mode=mode, use_ghidra=use_ghidra, ghidra_install_dir=ghidra_install_dir, decompile_jar=decompile_jar, validate_java=validate_java)
        new_root = _prepare_input(new_path, output / 'new_analysis', jar_path=new_jar, mode=mode, use_ghidra=use_ghidra, ghidra_install_dir=ghidra_install_dir, decompile_jar=decompile_jar, validate_java=validate_java)
        old_snapshot = build_snapshot(old_root)
        new_snapshot = build_snapshot(new_root)
        result = compare_snapshots(old_snapshot, new_snapshot)
        result['inputs'] = {'old': str(old_root), 'new': str(new_root)}
        paths = write_reports(result, output)
        result['artifacts'] = paths
        (output / 'diff.json').write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
        return result
    except Exception:
        if not any(output.iterdir()):
            output.rmdir()
        raise
