from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from typing import List

@lru_cache(maxsize=2)
def _read_lines(path: str, modified_ns: int, size: int) -> tuple[str, ...]:
    del modified_ns, size
    return tuple(Path(path).read_text(encoding='utf-8', errors='replace').splitlines())

def read_line_window(path: Path, start_line: int, end_line: int) -> List[str]:
    stat = path.stat()
    lines = _read_lines(str(path), stat.st_mtime_ns, stat.st_size)
    start = max(1, int(start_line))
    end = max(start, min(len(lines), int(end_line)))
    return list(lines[start - 1:end])

def line_count(path: Path) -> int:
    stat = path.stat()
    return len(_read_lines(str(path), stat.st_mtime_ns, stat.st_size))
