from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.validation.java_ast import parse_java_source

_ASSIGNMENT_RE = re.compile(r'^(?:[A-Za-z_$][\w$.[\]]*\s*)?(?:\+\+|--)?[A-Za-z_$][\w$.[\]]*\s*(?:=|\+=|-=|\*=|/=|%=)\s*.+$')
_INVOCATION_RE = re.compile(r'^(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*\s*\(.*\)$')
_TEMP_LINE_RE = re.compile(r'^(?P<indent>\s*)(?P<name>(?:local_|temp_|tmp)[A-Za-z0-9_$]*)\s*=\s*(?P<value>[^;]+);\s*$')
_JAVA_IMPORTS = {
    'ArrayList': 'java.util.ArrayList',
    'Arrays': 'java.util.Arrays',
    'CallSite': 'java.lang.invoke.CallSite',
    'Collection': 'java.util.Collection',
    'Collections': 'java.util.Collections',
    'Comparator': 'java.util.Comparator',
    'Constructor': 'java.lang.reflect.Constructor',
    'Field': 'java.lang.reflect.Field',
    'File': 'java.io.File',
    'HashMap': 'java.util.HashMap',
    'HashSet': 'java.util.HashSet',
    'IOException': 'java.io.IOException',
    'InputStream': 'java.io.InputStream',
    'List': 'java.util.List',
    'Map': 'java.util.Map',
    'Method': 'java.lang.reflect.Method',
    'MethodHandle': 'java.lang.invoke.MethodHandle',
    'MethodHandles': 'java.lang.invoke.MethodHandles',
    'MethodType': 'java.lang.invoke.MethodType',
    'MutableCallSite': 'java.lang.invoke.MutableCallSite',
    'Objects': 'java.util.Objects',
    'Optional': 'java.util.Optional',
    'OutputStream': 'java.io.OutputStream',
    'Set': 'java.util.Set',
}

def _balanced_inline(value: str) -> bool:
    return value.count('(') == value.count(')') and value.count('[') == value.count(']')

def _repair_imports(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    if re.search(r'(?m)^\s*import\s+[\w.]+\.\*\s*;', text):
        return text, []
    existing = set(re.findall(r'(?m)^\s*import\s+([\w.]+)\s*;', text))
    declared = set(re.findall(r'\b(?:class|record|enum|interface)\s+([A-Za-z_$][\w$]*)', text))
    additions = []
    for simple, qualified in sorted(_JAVA_IMPORTS.items()):
        if simple in declared or qualified in existing or not re.search(rf'\b{re.escape(simple)}\b', text):
            continue
        additions.append(qualified)
    if not additions:
        return text, []
    newline = '\r\n' if '\r\n' in text else '\n'
    imports = ''.join(f'import {qualified};{newline}' for qualified in additions)
    import_matches = list(re.finditer(r'(?m)^\s*import\s+[\w.]+\s*;\s*\r?\n?', text))
    if import_matches:
        offset = import_matches[-1].end()
    else:
        package_match = re.search(r'(?m)^\s*package\s+[\w.]+\s*;\s*\r?\n?', text)
        offset = package_match.end() if package_match else 0
    repaired = text[:offset] + imports + text[offset:]
    return repaired, [{'code': 'missing_import', 'import': qualified} for qualified in additions]

def _repair_semicolons(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    lines = text.splitlines()
    repairs: List[Dict[str, Any]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.endswith((';', '{', '}', ':', ',')):
            continue
        control_statement = bool(re.match(r'^(?:if|for|while|switch|catch|synchronized|try)\b', stripped))
        candidate = not control_statement and (stripped.startswith(('return ', 'throw new ', 'break ', 'continue ')) or stripped in {'return', 'break', 'continue'} or bool(_ASSIGNMENT_RE.match(stripped)) or bool(_INVOCATION_RE.match(stripped)))
        if candidate and _balanced_inline(stripped) and not stripped.endswith(('.', '+', '-', '*', '/', '&&', '||', '?')):
            lines[index] = line + ';'
            repairs.append({'code': 'missing_semicolon', 'line': index + 1})
    newline = '\r\n' if '\r\n' in text else '\n'
    suffix = newline if text.endswith(('\n', '\r')) else ''
    return newline.join(lines) + suffix, repairs

def _infer_type(value: str) -> Optional[str]:
    value = value.strip()
    if re.fullmatch(r'"(?:\\.|[^"\\])*"', value):
        return 'String'
    if value in {'true', 'false'} or re.search(r'(?:==|!=|<=|>=|<|>|&&|\|\|)', value):
        return 'boolean'
    if re.fullmatch(r'-?(?:0x[0-9A-Fa-f]+|\d+)[lL]', value):
        return 'long'
    if re.fullmatch(r'-?(?:0x[0-9A-Fa-f]+|\d+)', value):
        return 'int'
    if re.fullmatch(r'-?(?:\d+\.\d*|\d*\.\d+)(?:[dD])?', value):
        return 'double'
    if re.fullmatch(r'-?(?:\d+\.\d*|\d*\.\d+)[fF]', value):
        return 'float'
    new_match = re.match(r'new\s+([A-Za-z_$][\w$<>.?\[\]]*)\s*[({[]', value)
    if new_match:
        return new_match.group(1)
    cast_match = re.match(r'\(([A-Za-z_$][\w$<>.?\[\]]*)\)\s*.+', value)
    if cast_match:
        return cast_match.group(1)
    return None

def _repair_temporaries(text: str, ast: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    diagnostics = [item for item in ast.get('diagnostics') or [] if item.get('code') == 'undeclared_temporary' and isinstance(item.get('offset'), int)]
    repairs: List[Dict[str, Any]] = []
    for diagnostic in sorted(diagnostics, key=lambda item: int(item.get('offset')), reverse=True):
        offset = int(diagnostic.get('offset'))
        line_start = text.rfind('\n', 0, offset) + 1
        line_end = text.find('\n', offset)
        if line_end < 0:
            line_end = len(text)
        raw_line = text[line_start:line_end].rstrip('\r')
        match = _TEMP_LINE_RE.match(raw_line)
        if not match or match.group('name') != diagnostic.get('name'):
            continue
        inferred = _infer_type(match.group('value'))
        if inferred is None:
            continue
        replacement = f"{match.group('indent')}{inferred} {match.group('name')} = {match.group('value')};"
        text = text[:line_start] + replacement + text[line_start + len(raw_line):]
        repairs.append({'code': 'undeclared_temporary', 'line': text.count('\n', 0, line_start) + 1, 'name': match.group('name'), 'type': inferred})
    repairs.reverse()
    return text, repairs

def _repair_return_literals(text: str, ast: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    defaults = {'boolean': 'false', 'byte': '0', 'short': '0', 'int': '0', 'long': '0L', 'float': '0.0f', 'double': '0.0d', 'char': "'\\0'"}
    repairs: List[Dict[str, Any]] = []
    for method in sorted(ast.get('methods') or [], key=lambda item: int(item.get('body_start') or 0), reverse=True):
        start = method.get('body_start')
        end = method.get('end')
        return_type = str(method.get('return_type') or '').strip()
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            continue
        body_end = max(start, end - 1)
        body = text[start:body_end]
        if return_type in defaults:
            replacement = f"return {defaults[return_type]};"
            body, count = re.subn(r'\breturn\s+null\s*;', replacement, body)
        elif return_type == 'void':
            body, count = re.subn(r'\breturn\s+(?:null|true|false|-?(?:0x[0-9A-Fa-f]+|\d+)(?:[lLfFdD])?|"(?:\\.|[^"\\])*")\s*;', 'return;', body)
        else:
            count = 0
        if count:
            text = text[:start] + body + text[body_end:]
            repairs.append({'code': 'return_type_literal', 'method': method.get('name'), 'count': count, 'return_type': return_type})
    repairs.reverse()
    return text, repairs

def _repair_identical_duplicates(text: str, ast: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    groups: Dict[Tuple[str, Any], List[Dict[str, Any]]] = {}
    for method in ast.get('methods') or []:
        groups.setdefault((str(method.get('name') or ''), method.get('parameter_shape')), []).append(method)
    removals: List[Tuple[int, int, str]] = []
    for key, methods in groups.items():
        if len(methods) < 2:
            continue
        normalized = [' '.join(str(item.get('body_text') or '').split()) for item in methods]
        if len(set(normalized)) != 1:
            continue
        for method in methods[1:]:
            start = method.get('start')
            end = method.get('end')
            if isinstance(start, int) and isinstance(end, int) and end > start:
                removals.append((start, end, key[0]))
    repairs: List[Dict[str, Any]] = []
    for start, end, name in sorted(removals, reverse=True):
        text = text[:start] + text[end:]
        repairs.append({'code': 'duplicate_method', 'method': name, 'offset': start})
    repairs.reverse()
    return text, repairs

def apply_safe_repairs(text: str, *, path: Path) -> Tuple[str, List[Dict[str, Any]]]:
    repaired, imports = _repair_imports(text)
    repaired, semicolons = _repair_semicolons(repaired)
    ast = parse_java_source(repaired, path=path)
    repaired, returns = _repair_return_literals(repaired, ast)
    ast = parse_java_source(repaired, path=path)
    repaired, temporaries = _repair_temporaries(repaired, ast)
    ast = parse_java_source(repaired, path=path)
    repaired, duplicates = _repair_identical_duplicates(repaired, ast)
    return repaired, imports + semicolons + returns + temporaries + duplicates
