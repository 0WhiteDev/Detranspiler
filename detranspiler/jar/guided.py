import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.jni_descriptors import _jni_method_sig_to_java

def _descriptor_arg_count(desc: str) -> int:
    if not isinstance(desc, str) or not desc.startswith('('):
        return 0
    i = 1
    count = 0
    while i < len(desc):
        ch = desc[i]
        if ch == ')':
            return count
        if ch in 'BCDFIJSZ':
            count += 1
            i += 1
            continue
        if ch == 'L':
            j = desc.find(';', i)
            if j == -1:
                return count
            count += 1
            i = j + 1
            continue
        if ch == '[':
            while i < len(desc) and desc[i] == '[':
                i += 1
            if i < len(desc) and desc[i] == 'L':
                j = desc.find(';', i)
                if j == -1:
                    return count
                i = j + 1
            else:
                i += 1
            count += 1
            continue
        break
    return count

def _internal_to_rel_path(internal: str) -> str:
    parts = [p for p in internal.split('/') if p]
    return '/'.join(parts) + '.java' if parts else ''

def _parse_cfr_param_names(params_raw: str) -> List[str]:
    names: List[str] = []
    if not params_raw.strip():
        return names
    depth = 0
    buf = ''
    for ch in params_raw + ',':
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            part = buf.strip()
            buf = ''
            if part:
                toks = part.split()
                if toks:
                    names.append(toks[-1].strip())
            continue
        buf += ch
    return names

def _parse_cfr_param_types(params_raw: str) -> List[str]:
    types: List[str] = []
    if not params_raw.strip():
        return types
    depth = 0
    buf = ''
    for ch in params_raw + ',':
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            part = buf.strip()
            buf = ''
            if part:
                toks = part.split()
                if len(toks) >= 2:
                    types.append(' '.join(toks[:-1]))
                elif toks:
                    types.append(toks[0])
            continue
        buf += ch
    return types

def _normalize_java_type_name(t: str) -> str:
    s = re.sub('\\s+', ' ', (t or '').strip())
    if '<' in s:
        s = s.split('<', 1)[0].strip()
    if s.endswith('...'):
        s = s[:-3] + '[]'
    return s.replace('java.lang.', '')

def _pick_jar_method_candidate(candidates: List[Any], *, descriptor: Optional[str]=None) -> Optional[Dict[str, Any]]:
    if not isinstance(candidates, list) or not candidates:
        return None
    dicts = [c for c in candidates if isinstance(c, dict)]
    if not dicts:
        return None
    if not isinstance(descriptor, str) or not descriptor:
        return dicts[0]
    parsed = _jni_method_sig_to_java(descriptor)
    if parsed is None:
        target_count = _descriptor_arg_count(descriptor)
        for c in dicts:
            if c.get('param_count') == target_count:
                return c
        return dicts[0]
    ret_java, param_types = parsed
    norm_params = [_normalize_java_type_name(t) for t in param_types]
    best: Optional[Dict[str, Any]] = None
    best_score = -1
    for c in dicts:
        score = 0
        c_ret = _normalize_java_type_name(str(c.get('return_type') or ''))
        if c_ret == ret_java or c_ret.split('.')[-1] == ret_java.split('.')[-1]:
            score += 24
        if c.get('param_count') == len(param_types):
            score += 12
        c_types = c.get('param_java_types')
        if isinstance(c_types, list) and len(c_types) == len(norm_params):
            matches = sum((1 for a, b in zip(c_types, norm_params) if _normalize_java_type_name(str(a)) == b or _normalize_java_type_name(str(a)).split('.')[-1] == b.split('.')[-1]))
            score += matches * 8
        if score > best_score:
            best_score = score
            best = c
    return best if best is not None else dicts[0]

def _extract_method_bodies(text: str) -> List[Dict[str, Any]]:
    methods: List[Dict[str, Any]] = []
    pattern = re.compile('(?:public|private|protected|static|final|native|synchronized|abstract|\s)+(?P<ret>[\w\[\]<>,\s.]+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?:throws\s+[\w\s,.]+)?\s*\{')
    skip = {'class', 'interface', 'enum', 'if', 'for', 'while', 'switch', 'catch'}
    for m in pattern.finditer(text):
        name = m.group('name')
        if name in skip:
            continue
        start = m.end() - 1
        depth = 0
        body_chars: List[str] = []
        for ch in text[start:]:
            body_chars.append(ch)
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    break
        body = ''.join(body_chars)
        params_raw = m.group('params').strip()
        param_count = 0 if not params_raw else len([p for p in params_raw.split(',') if p.strip()])
        param_names = _parse_cfr_param_names(params_raw)
        param_java_types = _parse_cfr_param_types(params_raw)
        methods.append({'name': name, 'return_type': m.group('ret').strip(), 'param_count': param_count, 'param_names': param_names, 'param_java_types': param_java_types, 'body': body})
    return methods

def build_jar_method_index(*, jar_sources_dir: Path, max_files: int=2000) -> Dict[str, Any]:
    jar_sources_dir = jar_sources_dir.expanduser().resolve()
    if not jar_sources_dir.is_dir():
        return {'status': 'SKIPPED_NO_JAR_SOURCES'}
    by_class: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    files_scanned = 0
    for java_file in sorted(jar_sources_dir.rglob('*.java'))[:max_files]:
        files_scanned += 1
        rel = str(java_file.relative_to(jar_sources_dir)).replace('\\', '/')
        internal = rel[:-5].replace('/', '/') if rel.endswith('.java') else rel.replace('/', '/')
        try:
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        for m in _extract_method_bodies(text):
            name = m.get('name')
            if not isinstance(name, str):
                continue
            by_class.setdefault(internal, {}).setdefault(name, []).append(m)
    return {'status': 'OK', 'jar_sources_dir': str(jar_sources_dir), 'files_scanned': files_scanned, 'classes_total': len(by_class), 'methods_total': sum((len(v) for cls in by_class.values() for v in cls.values())), 'by_class': by_class}

def _body_to_java_lines(body: str, *, indent: str='    ') -> List[str]:
    inner = body.strip()
    if inner.startswith('{'):
        inner = inner[1:]
    if inner.endswith('}'):
        inner = inner[:-1]
    lines: List[str] = []
    for line in inner.splitlines():
        s = line.rstrip()
        if not s.strip():
            continue
        if s.lstrip().startswith('//'):
            lines.append(f'{indent}{s.lstrip()}')
        else:
            lines.append(f'{indent}{s.lstrip()}')
    return lines[:500]

def get_jar_return_expr(*, jar_index: Optional[Dict[str, Any]], class_internal: str, method: str, descriptor: Optional[str]=None) -> Optional[str]:
    lines = get_jar_reference_body(jar_index=jar_index, class_internal=class_internal, method=method, descriptor=descriptor)
    if not isinstance(lines, list):
        return None
    for line in reversed(lines):
        s = line.strip()
        if s.startswith('return '):
            return s[len('return '):].rstrip(';').strip()
    return None

def get_jar_reference_body(*, jar_index: Optional[Dict[str, Any]], class_internal: str, method: str, descriptor: Optional[str]=None) -> Optional[List[str]]:
    lines = get_jar_fallback_body(jar_index=jar_index, class_internal=class_internal, method=method, descriptor=descriptor)
    if not isinstance(lines, list):
        return None
    ref = [ln for ln in lines if not ln.strip().startswith('// [jar-guided]')]
    return ref if ref else None

def get_jar_fallback_body(*, jar_index: Optional[Dict[str, Any]], class_internal: str, method: str, descriptor: Optional[str]=None) -> Optional[List[str]]:
    if not isinstance(jar_index, dict) or jar_index.get('status') != 'OK':
        return None
    by_class = jar_index.get('by_class')
    if not isinstance(by_class, dict):
        return None
    candidates = None
    cls_methods = by_class.get(class_internal)
    if isinstance(cls_methods, dict):
        candidates = cls_methods.get(method)
    if candidates is None:
        alt = class_internal.replace('jni/', '').replace('jni_exports/', '')
        cls_methods = by_class.get(alt)
        if isinstance(cls_methods, dict):
            candidates = cls_methods.get(method)
    if not isinstance(candidates, list) or not candidates:
        return None
    chosen = _pick_jar_method_candidate(candidates, descriptor=descriptor)
    if not isinstance(chosen, dict):
        return None
    body = chosen.get('body')
    if not isinstance(body, str) or not body.strip():
        return None
    lines = _body_to_java_lines(body)
    if not lines:
        return None
    return lines

def get_jar_param_names(*, jar_index: Optional[Dict[str, Any]], class_internal: str, method: str, descriptor: Optional[str]=None) -> Optional[List[str]]:
    if not isinstance(jar_index, dict) or jar_index.get('status') != 'OK':
        return None
    by_class = jar_index.get('by_class')
    if not isinstance(by_class, dict):
        return None
    candidates = None
    cls_methods = by_class.get(class_internal)
    if isinstance(cls_methods, dict):
        candidates = cls_methods.get(method)
    if candidates is None:
        alt = class_internal.replace('jni/', '').replace('jni_exports/', '')
        cls_methods = by_class.get(alt)
        if isinstance(cls_methods, dict):
            candidates = cls_methods.get(method)
    if not isinstance(candidates, list) or not candidates:
        return None
    chosen = _pick_jar_method_candidate(candidates, descriptor=descriptor)
    if not isinstance(chosen, dict):
        return None
    names = chosen.get('param_names')
    if isinstance(names, list) and names and all((isinstance(n, str) for n in names)):
        return list(names)
    return None
