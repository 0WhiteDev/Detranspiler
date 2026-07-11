from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.provenance.model import read_json, resolve_beneath
from detranspiler.provenance.pseudo import line_count, read_line_window

_LINE_HINTS = {
    'throw': ('Throw', 'Exception'),
    'new ': ('NewObject', 'NewString', 'NewObjectArray', 'NewPrimitiveArray', 'AllocObject', 'CallNonvirtualVoidMethod'),
    '.tochararray': ('CallObjectMethod', 'StringChars'),
    '.intern': ('CallObjectMethod',),
    '.length': ('GetArrayLength', 'GetStringLength'),
    'string': ('String', 'UTF'),
    'class': ('FindClass', 'GetObjectClass', 'IsInstanceOf'),
    'field': ('Field',),
    '[': ('Array',),
}

def _rank_calls(java_line: str, calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lowered = java_line.lower()
    positioned = [call for call in calls if isinstance(call.get('line'), int) and int(call.get('line')) > 0]
    pool = positioned or calls
    for marker, names in _LINE_HINTS.items():
        if marker not in lowered:
            continue
        selected = [call for call in pool if any(name.lower() in str(call.get('jni_name') or '').lower() for name in names)]
        if selected:
            return selected[:40]
    return pool[:40]

def _pseudo_fragment(out_dir: Path, evidence: Dict[str, Any], calls: List[Dict[str, Any]], max_lines: int=120) -> Optional[Dict[str, Any]]:
    native = evidence.get('native') if isinstance(evidence.get('native'), dict) else {}
    pseudo = native.get('pseudo_c') if isinstance(native.get('pseudo_c'), dict) else {}
    rel_path = pseudo.get('path')
    if not isinstance(rel_path, str):
        return None
    path = resolve_beneath(out_dir, rel_path)
    if path is None or not path.is_file():
        return None
    total_lines = line_count(path)
    span = pseudo.get('lines') if isinstance(pseudo.get('lines'), list) else []
    start = int(span[0]) if len(span) == 2 and isinstance(span[0], int) else 1
    end = int(span[1]) if len(span) == 2 and isinstance(span[1], int) else min(total_lines, start + max_lines - 1)
    call_lines = [int(call.get('line')) for call in calls if isinstance(call.get('line'), int) and start <= int(call.get('line')) <= end]
    if call_lines:
        center = min(call_lines)
        start = max(start, center - 12)
        end = min(end, start + max_lines - 1)
    else:
        end = min(end, start + max_lines - 1)
    if start < 1 or start > total_lines:
        return None
    end = min(end, total_lines)
    return {'path': rel_path, 'start_line': start, 'end_line': end, 'content': '\n'.join(read_line_window(path, start, end))}

def read_line_provenance(*, out_dir: Path, rel_path: str, line: int) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    document = read_json(out_dir / 'analysis' / 'source_provenance.json')
    files = document.get('files') if isinstance(document.get('files'), dict) else {}
    file_entry = files.get(rel_path.replace('\\', '/').lstrip('/'))
    if not isinstance(file_entry, dict):
        return {'status': 'NOT_FOUND', 'path': rel_path, 'line': line}
    selected_range = None
    for item in file_entry.get('ranges') or []:
        if isinstance(item, dict) and int(item.get('start_line') or 0) <= line <= int(item.get('end_line') or 0):
            selected_range = item
            break
    if not isinstance(selected_range, dict):
        return {'status': 'NOT_FOUND', 'path': rel_path, 'line': line}
    evidence_map = document.get('evidence') if isinstance(document.get('evidence'), dict) else {}
    evidence = evidence_map.get(str(selected_range.get('evidence_id')))
    if not isinstance(evidence, dict):
        return {'status': 'NOT_FOUND', 'path': rel_path, 'line': line}
    source_path = resolve_beneath(out_dir / 'pseudocode' / 'sources', rel_path)
    source_lines = source_path.read_text(encoding='utf-8', errors='replace').splitlines() if source_path is not None and source_path.is_file() else []
    java_line = source_lines[line - 1] if 0 < line <= len(source_lines) else ''
    calls = evidence.get('jni_calls') if isinstance(evidence.get('jni_calls'), list) else []
    selected_calls = _rank_calls(java_line, calls)
    pseudo = _pseudo_fragment(out_dir, evidence, selected_calls)
    return {'status': 'OK', 'path': rel_path, 'line': line, 'java_line': java_line, 'range': selected_range, 'evidence': evidence, 'pseudo_c': pseudo, 'jni_calls': selected_calls}
