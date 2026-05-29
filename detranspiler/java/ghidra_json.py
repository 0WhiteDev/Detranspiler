import json
from pathlib import Path
from typing import Any, Dict, List

def _load_ghidra_functions_json(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return None
