from typing import Any

def _java_comment_escape(value: Any) -> str:
    s = str(value if value is not None else '')
    s = s.replace('\r', ' ').replace('\n', ' ')
    return s[:240]
