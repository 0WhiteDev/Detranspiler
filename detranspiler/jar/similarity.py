import difflib
import re
from typing import List, Optional

def _normalize_body_text(lines: List[str]) -> str:
    parts: List[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        s = re.sub('//.*?$', '', s)
        s = re.sub('\\s+', ' ', s).strip()
        if s:
            parts.append(s)
    return ' '.join(parts)

def similarity_between_bodies(recovered: Optional[List[str]], reference: Optional[List[str]]) -> float:
    if not isinstance(recovered, list) or not isinstance(reference, list):
        return 0.0
    a = _normalize_body_text(recovered)
    b = _normalize_body_text(reference)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()

def jar_similarity_bonus(recovered: Optional[List[str]], reference: Optional[List[str]]) -> int:
    ratio = similarity_between_bodies(recovered, reference)
    if ratio >= 0.85:
        return 35
    if ratio >= 0.55:
        return 20
    if ratio >= 0.35:
        return 10
    return 0
