import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from detranspiler.java.body.recovery import is_invalid_java_body_lines, is_stub_body_lines

def _path_to_internal(rel: str) -> str:
    s = rel.replace('\\', '/')
    if s.endswith('.java'):
        s = s[:-5]
    if s.startswith('jni/'):
        s = s[4:]
    if s.startswith('jni_exports/'):
        s = s[len('jni_exports/'):]
    return s

def _extract_methods_with_bodies(text: str) -> List[Tuple[str, int, int, List[str]]]:
    results: List[Tuple[str, int, int, List[str]]] = []
    pat = re.compile('(?:public|private|protected|static|final|native|synchronized|abstract|\s)+[\w\[\]<>,\s\.]+\s+(?P<name>\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,.]+)?\s*\{')
    skip = {'class', 'interface', 'enum', 'if', 'for', 'while', 'switch', 'catch'}
    for m in pat.finditer(text):
        name = m.group('name')
        if name in skip:
            continue
        start = m.end() - 1
        depth = 0
        end = start
        for i, ch in enumerate(text[start:], start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        body_text = text[start + 1:end]
        body_lines = body_text.splitlines()
        results.append((name, start + 1, end, body_lines))
    return results

def _method_key(class_internal: str, method: str, descriptor: Optional[str]) -> str:
    return f"{class_internal}::{method}::{descriptor or '?'}"

def build_recovered_body_index(*, pseudocode_dir: Path, max_files: int=2000) -> Dict[str, List[str]]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    if not pseudocode_dir.is_dir():
        return {}
    index: Dict[str, List[str]] = {}
    java_files: List[Path] = []
    for sub in ('jni', 'jni_exports'):
        d = pseudocode_dir / sub
        if d.is_dir():
            java_files.extend(sorted(d.rglob('*.java')))
    for java_file in java_files[:max_files]:
        try:
            rel = str(java_file.relative_to(pseudocode_dir)).replace('\\', '/')
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        class_internal = _path_to_internal(rel)
        descriptor_by_method = _scan_method_descriptors(text)
        for method_name, _start, _end, body_lines in _extract_methods_with_bodies(text):
            if is_stub_body_lines(body_lines) or is_invalid_java_body_lines(body_lines):
                continue
            normalized = [ln if ln.startswith('    ') else f'    {ln.strip()}' for ln in body_lines if isinstance(ln, str) and ln.strip()]
            if not normalized:
                continue
            desc = descriptor_by_method.get(method_name)
            key = _method_key(class_internal, method_name, desc)
            if key not in index or len(normalized) > len(index[key]):
                index[key] = normalized
    return index

def _scan_method_descriptors(text: str) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    from detranspiler.jar.radioegor.util import _NATIVE_DECL_RE
    from detranspiler.jar.radioegor.context import _descriptor_from_decl
    for m in _NATIVE_DECL_RE.finditer(text):
        name = m.group('name')
        if name in {'class', 'interface', 'enum', 'if', 'for', 'while', 'switch', 'catch'}:
            continue
        out[name] = _descriptor_from_decl(m.group('ret'), m.group('params'))
    return out

def lookup_recovered_body(index: Dict[str, List[str]], *, class_internal: str, method: str, descriptor: Optional[str]=None) -> Optional[List[str]]:
    if not index:
        return None
    if descriptor:
        hit = index.get(_method_key(class_internal, method, descriptor))
        if hit:
            return list(hit)
    for key, body in index.items():
        if key.startswith(f'{class_internal}::{method}::'):
            return list(body)
    fallback: Optional[List[str]] = None
    for key, body in index.items():
        if f'::{method}::' not in key:
            continue
        if fallback is None or len(body) > len(fallback):
            fallback = list(body)
    return fallback
