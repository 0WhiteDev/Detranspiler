from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

_CLASS_RE = re.compile(r'\b(?:class|record|enum)\s+([A-Za-z_$][\w$]*)')
_TEMP_ASSIGN_RE = re.compile(r'(?m)^\s*(?P<name>(?:local_|temp_|tmp)[A-Za-z0-9_$]*)\s*=\s*(?P<value>[^;]+);')
_DECL_RE = re.compile(r'\b[A-Za-z_$][\w$<>.?\[\]]*\s+([A-Za-z_$][\w$]*)\s*(?:=|;|,|\))')
_METHOD_RE = re.compile(r'(?m)^[ \t]*(?:@[\w.$]+(?:\([^\r\n]*\))?[ \t]*)*(?P<mods>(?:(?:(?:public|private|protected|static|final|synchronized|strictfp|abstract|native|default)\s+)|(?:/\*[^\r\n]*?\*/\s*))*)(?P<ret>[A-Za-z_$][\w$.[\]<>?, \t]*)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)(?:\s+throws\s+[\w$., <>?\[\]]+)?\s*(?P<end>[{;])')
_NON_TYPE_PREFIXES = {'assert', 'break', 'case', 'catch', 'continue', 'do', 'else', 'for', 'if', 'new', 'return', 'switch', 'throw', 'try', 'while', 'yield'}

def _split_parameters(params: str) -> Tuple[str, ...]:
    values: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in params:
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            values.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        values.append(''.join(current))
    shape: List[str] = []
    for value in values:
        cleaned = re.sub(r'@[\w.$]+(?:\([^)]*\))?\s*', '', value).strip()
        cleaned = re.sub(r'\bfinal\s+', '', cleaned)
        match = re.match(r'(.+?)\s+[A-Za-z_$][\w$]*$', cleaned)
        java_type = match.group(1).strip() if match else cleaned
        shape.append(re.sub(r'\s+', '', java_type).replace('...', '[]'))
    return tuple(shape)

def _matching_brace(text: str, start: int) -> int:
    depth = 0
    quote = ''
    escaped = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ''
        if line_comment:
            if ch in '\r\n':
                line_comment = False
        elif block_comment:
            if ch == '*' and nxt == '/':
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ''
        elif ch == '/' and nxt == '/':
            line_comment = True
            i += 1
        elif ch == '/' and nxt == '*':
            block_comment = True
            i += 1
        elif ch in {'\'', '"'}:
            quote = ch
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)

def find_methods(text: str) -> List[Dict[str, Any]]:
    methods: List[Dict[str, Any]] = []
    for match in _METHOD_RE.finditer(text):
        return_type = match.group('ret').strip()
        if return_type.split()[0] in _NON_TYPE_PREFIXES:
            continue
        body_text = None
        body_start = match.end()
        end = match.end()
        if match.group('end') == '{':
            opening = match.end() - 1
            end = _matching_brace(text, opening)
            body_text = text[opening + 1:max(opening + 1, end - 1)]
            body_start = opening + 1
        methods.append({'name': match.group('name'), 'return_type': return_type, 'parameter_shape': _split_parameters(match.group('params')), 'body_text': body_text, 'body_start': body_start, 'params_text': match.group('params'), 'start': match.start(), 'end': end, 'native': 'native' in match.group('mods').split()})
    return methods

def _brace_state(text: str) -> Tuple[int, int]:
    depth = 0
    minimum = 0
    quote = ''
    escaped = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ''
        if line_comment:
            if ch in '\r\n':
                line_comment = False
        elif block_comment:
            if ch == '*' and nxt == '/':
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = ''
        elif ch == '/' and nxt == '/':
            line_comment = True
            i += 1
        elif ch == '/' and nxt == '*':
            block_comment = True
            i += 1
        elif ch in {'\'', '"'}:
            quote = ch
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            minimum = min(minimum, depth)
        i += 1
    return depth, minimum

def _method_diagnostics(method: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = method.get('body_text')
    if not isinstance(body, str):
        return []
    name = method.get('name')
    return_type = str(method.get('return_type') or '').strip()
    diagnostics: List[Dict[str, Any]] = []
    if return_type == 'void' and re.search(r'\breturn\s+[^;]+;', body):
        diagnostics.append({'code': 'return_type_mismatch', 'severity': 'ERROR', 'method': name, 'detail': 'void method returns a value'})
    if return_type in {'boolean', 'byte', 'short', 'int', 'long', 'float', 'double', 'char'} and re.search(r'\breturn\s+null\s*;', body):
        diagnostics.append({'code': 'return_type_mismatch', 'severity': 'ERROR', 'method': name, 'detail': f'{return_type} method returns null'})
    invalid_casts = [
        (r'\((?:byte|short|int|long|float|double|char|boolean)\)\s*null\b', 'primitive cast from null'),
        (r'\(boolean\)\s*-?(?:0x[0-9A-Fa-f]+|\d+)\b', 'boolean cast from numeric literal'),
        (r'\((?:byte|short|int|long|float|double|char)\)\s*"(?:\\.|[^"\\])*"', 'numeric cast from string literal'),
    ]
    for pattern, detail in invalid_casts:
        if re.search(pattern, body):
            diagnostics.append({'code': 'invalid_cast', 'severity': 'ERROR', 'method': name, 'detail': detail})
    depth = 0
    terminated: set[int] = set()
    for line_number, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        leading_closes = len(stripped) - len(stripped.lstrip('}'))
        depth = max(0, depth - leading_closes)
        terminated = {value for value in terminated if value <= depth}
        statement = stripped.lstrip('}').strip()
        if statement and depth in terminated and statement not in {';', '}'} and not statement.startswith(('case ', 'default:')):
            diagnostics.append({'code': 'unreachable_code', 'severity': 'ERROR', 'method': name, 'line_in_method': line_number})
            terminated.remove(depth)
        if re.match(r'^(?:return(?:\s+[^;]+)?|throw\s+[^;]+);$', statement):
            terminated.add(depth)
        opens = statement.count('{')
        closes = max(0, statement.count('}') - leading_closes)
        depth = max(0, depth + opens - closes)
    return diagnostics

def parse_java_source(text: str, *, path: Path) -> Dict[str, Any]:
    methods = find_methods(text)
    class_match = _CLASS_RE.search(text)
    class_name = class_match.group(1) if class_match else path.stem
    diagnostics: List[Dict[str, Any]] = []
    depth, minimum = _brace_state(text)
    if depth != 0 or minimum < 0:
        diagnostics.append({'code': 'unbalanced_braces', 'severity': 'ERROR', 'detail': f'brace depth={depth}, minimum={minimum}'})
    signatures: Dict[Tuple[str, Any], List[Dict[str, Any]]] = {}
    for method in methods:
        key = (str(method.get('name') or ''), method.get('parameter_shape'))
        signatures.setdefault(key, []).append(method)
        diagnostics.extend(_method_diagnostics(method))
    for key, duplicates in signatures.items():
        if len(duplicates) > 1:
            bodies = {' '.join(str(item.get('body_text') or '').split()) for item in duplicates}
            diagnostics.append({'code': 'duplicate_method', 'severity': 'ERROR', 'method': key[0], 'detail': 'identical implementations' if len(bodies) == 1 else 'conflicting implementations', 'safe_repair': len(bodies) == 1})
    for method in methods:
        body = method.get('body_text')
        if not isinstance(body, str):
            continue
        declared = set(_DECL_RE.findall(body))
        declared.update(re.findall(r'(?:^|,)\s*(?:final\s+)?[A-Za-z_$][\w$<>.?\[\]]*\s+([A-Za-z_$][\w$]*)', str(method.get('params_text') or '')))
        for match in _TEMP_ASSIGN_RE.finditer(body):
            name = match.group('name')
            if name not in declared:
                diagnostics.append({'code': 'undeclared_temporary', 'severity': 'ERROR', 'method': method.get('name'), 'name': name, 'offset': int(method.get('body_start') or 0) + match.start(), 'value': match.group('value').strip()})
    return {'status': 'OK' if not any(item.get('severity') == 'ERROR' for item in diagnostics) else 'INVALID', 'path': str(path), 'class_name': class_name, 'methods_total': len(methods), 'methods': methods, 'diagnostics': diagnostics}
