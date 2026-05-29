from typing import Any, Callable, Dict, Optional
ProgressCallback = Callable[[Dict[str, Any]], None]

def emit_progress(callback: Optional[ProgressCallback], *, phase: str, percent: int, message: str='') -> None:
    if callback is None:
        return
    try:
        callback({'phase': phase, 'percent': max(0, min(100, int(percent))), 'message': message or phase})
    except Exception:
        pass
