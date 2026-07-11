from __future__ import annotations
import json
import re
from pathlib import Path
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

_LAYER_LABELS = {
    'jar_sources': 'CFR',
    'jni': 'JNI synthesis',
    'jni_exports': 'JNI export',
    'jnic': 'JNIC reconstruction',
    'radioegor_sources': 'Radioegor reconstruction',
}

_SOURCE_LABELS = {
    'bytecode': 'JVM bytecode',
    'jar': 'CFR',
    'jar_metadata': 'JAR metadata',
    'jar_repair': 'JAR repair',
    'jar_sources': 'CFR',
    'jni': 'JNI trace',
    'jni_synthesis': 'JNI synthesis',
    'jnic': 'JNIC reconstruction',
    'pseudoc': 'Ghidra pseudo-C',
    'pseudo_c': 'Ghidra pseudo-C',
    'register_natives': 'RegisterNatives',
    'simple': 'Simple recovery heuristic',
}

@lru_cache(maxsize=32)
def _read_json_document(path: str, modified_ns: int, size: int) -> Dict[str, Any]:
    del modified_ns, size
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}

def read_json(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
    except OSError:
        return {}
    return _read_json_document(str(path.resolve()), stat.st_mtime_ns, stat.st_size)

def resolve_beneath(root: Path, rel_path: str) -> Optional[Path]:
    root = root.expanduser().resolve()
    normalized = str(rel_path or '').replace('\\', '/').lstrip('/')
    candidate = (root / normalized).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate

def layer_label(layer: Optional[str]) -> str:
    if not isinstance(layer, str) or not layer:
        return 'Unknown source'
    return _LAYER_LABELS.get(layer, layer.replace('_', ' ').title())

def source_labels(values: Iterable[Any]) -> List[str]:
    labels: List[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        label = _SOURCE_LABELS.get(value, value.replace('_', ' ').title())
        if label not in labels:
            labels.append(label)
    return labels

def normalize_type(value: Any) -> str:
    text = str(value or '').strip().replace('...', '[]')
    text = re.sub(r'<[^<>]*>', '', text)
    dimensions = ''
    while text.endswith('[]'):
        dimensions += '[]'
        text = text[:-2]
    simple = re.split(r'[.$/]', text)[-1]
    return simple + dimensions

def normalize_shape(values: Iterable[Any]) -> Tuple[str, ...]:
    return tuple(normalize_type(value) for value in values)

def line_at(text: str, offset: Any) -> int:
    if not isinstance(offset, int):
        return 1
    return text.count('\n', 0, max(0, min(len(text), offset))) + 1

def method_candidate(items: Iterable[Dict[str, Any]], *, class_internal: str, name: str, shape: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
    named = [item for item in items if item.get('class_internal', item.get('class')) == class_internal and item.get('method') == name]
    exact = [item for item in named if normalize_shape(item.get('java_params') or item.get('parameter_shape') or []) == shape]
    if len(exact) == 1:
        return exact[0]
    return named[0] if len(named) == 1 else None

def compress_ranges(evidence_ids: List[str], roles: List[str]) -> List[Dict[str, Any]]:
    if not evidence_ids:
        return []
    ranges: List[Dict[str, Any]] = []
    start = 1
    current_evidence = evidence_ids[0]
    current_role = roles[0]
    for index in range(1, len(evidence_ids)):
        if evidence_ids[index] == current_evidence and roles[index] == current_role:
            continue
        ranges.append({'start_line': start, 'end_line': index, 'evidence_id': current_evidence, 'role': current_role})
        start = index + 1
        current_evidence = evidence_ids[index]
        current_role = roles[index]
    ranges.append({'start_line': start, 'end_line': len(evidence_ids), 'evidence_id': current_evidence, 'role': current_role})
    return ranges
