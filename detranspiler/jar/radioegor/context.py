import json
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detranspiler.java.jni_descriptors import _jni_method_sig_to_java
from detranspiler.jni.register import _infer_dat_pointer_values, _load_strings_json, _pe_read_c_string, _resolve_string_expr
from detranspiler.jar.radioegor.util import _METHOD_BODY_RE, _param_names
from detranspiler.jar.radioegor.validate import _radioegor_body_is_usable

def _extract_recovered_bodies(pseudocode_dir: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for sub in ('jni', 'jni_exports'):
        root = pseudocode_dir / sub
        if not root.is_dir():
            continue
        for java_file in sorted(root.rglob('*.java')):
            rel = str(java_file.relative_to(root)).replace('\\', '/')
            class_internal = rel[:-5] if rel.endswith('.java') else rel
            try:
                text = java_file.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            for m in _METHOD_BODY_RE.finditer(text):
                name = m.group('name')
                if name in {'class', 'interface', 'enum', 'if', 'for', 'while', 'switch', 'catch'}:
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
                body = text[start + 1:end].splitlines()
                if not _radioegor_body_is_usable(body):
                    continue
                key = f'{class_internal}::{name}'
                item = {'body': [ln for ln in body if isinstance(ln, str) and ln.strip()], 'params': _param_names(m.group('params'))}
                old = out.get(key)
                if old is None or len(item['body']) > len(old.get('body') or []):
                    out[key] = item
    return out

def _extract_pseudoc_blocks(pseudocode_dir: Path) -> Dict[str, str]:
    pseudo_c = pseudocode_dir.parent / 'pseudo_c' / 'decompiled.c'
    if not pseudo_c.is_file():
        return {}
    try:
        text = pseudo_c.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for m in re.finditer('/\\*\\s*FUNCTION\\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\\b.*?(?=/\\*\\s*FUNCTION\\s+|\\Z)', text, flags=re.DOTALL):
        name = m.group('name')
        if isinstance(name, str) and name:
            out[name] = m.group(0)
    return out

def _pe_image_base_and_sections(data: bytes) -> tuple[Optional[int], List[tuple[int, int, int]]]:
    if len(data) < 256 or data[:2] != b'MZ':
        return (None, [])
    try:
        e_lfanew = struct.unpack_from('<I', data, 60)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return (None, [])
        file_hdr_off = e_lfanew + 4
        number_of_sections = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
        size_of_optional_header = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
        opt_off = file_hdr_off + 20
        magic = struct.unpack_from('<H', data, opt_off)[0]
        image_base_off = opt_off + (28 if magic == 267 else 24)
        image_base = struct.unpack_from('<I' if magic == 267 else '<Q', data, image_base_off)[0]
        sect_off = opt_off + size_of_optional_header
        sections: List[tuple[int, int, int]] = []
        for i in range(number_of_sections):
            sh = sect_off + i * 40
            if sh + 40 > len(data):
                break
            virtual_size = struct.unpack_from('<I', data, sh + 8)[0]
            virtual_address = struct.unpack_from('<I', data, sh + 12)[0]
            size_of_raw_data = struct.unpack_from('<I', data, sh + 16)[0]
            pointer_to_raw_data = struct.unpack_from('<I', data, sh + 20)[0]
            span = max(virtual_size, size_of_raw_data)
            if span and size_of_raw_data and (pointer_to_raw_data < len(data)):
                sections.append((virtual_address, pointer_to_raw_data, min(size_of_raw_data, len(data) - pointer_to_raw_data)))
        return (image_base, sections)
    except Exception:
        return (None, [])

def _augment_short_strings_from_binary(pseudocode_dir: Path, strings_by_addr: Dict[int, str]) -> None:
    job_path = pseudocode_dir.parent / 'job.json'
    try:
        job = json.loads(job_path.read_text(encoding='utf-8', errors='replace'))
        binary_path = Path(str((job.get('input') or {}).get('path') or ''))
    except Exception:
        return
    if not binary_path.is_file():
        return
    try:
        data = binary_path.read_bytes()
    except Exception:
        return
    image_base, sections = _pe_image_base_and_sections(data)
    if not isinstance(image_base, int) or not sections:
        return
    for rva, raw_off, raw_size in sections:
        chunk = data[raw_off:raw_off + raw_size]
        for m in re.finditer(b'[\\x20-\\x7e]{2,240}\\x00', chunk):
            raw = m.group(0)[:-1]
            if not raw:
                continue
            try:
                value = raw.decode('ascii')
            except Exception:
                continue
            va = image_base + rva + m.start()
            strings_by_addr.setdefault(va, value)
        for m in re.finditer(b'[\\x01\\x02\\x20-\\x7e]{2,240}\\x00', chunk):
            raw = m.group(0)[:-1]
            if b'\x01' not in raw and b'\x02' not in raw:
                continue
            cleaned = raw.replace(b'\x01', b'').replace(b'\x02', b'')
            if len(cleaned) < 2:
                continue
            try:
                value = cleaned.decode('ascii')
            except Exception:
                continue
            if not value or not any((ch.isalnum() for ch in value)):
                continue
            va = image_base + rva + m.start()
            strings_by_addr.setdefault(va, value)

def _expr_string_address(expr: str, dat_ptr_values: Dict[str, int]) -> Optional[int]:
    m = re.fullmatch('\\s*(DAT_[0-9A-Fa-f]+)(?:\\s*\\+\\s*(0x[0-9A-Fa-f]+|\\d+))?\\s*', str(expr))
    if m is None:
        return None
    base = dat_ptr_values.get(m.group(1))
    if not isinstance(base, int):
        return None
    off = _int_literal(m.group(2) or '0')
    if off is None:
        return None
    return base + off

def _infer_global_string_values(lines: List[str], dat_ptr_values: Dict[str, int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    recent_exprs: List[str] = []
    new_string_re = re.compile('\\(\\*\\*\\(code \\*\\*\\)\\(\\*param_1 \\+\\s*0x538\\)\\)\\s*\\(\\s*param_1\\s*,\\s*(?P<expr>DAT_[0-9A-Fa-f]+(?:\\s*\\+\\s*(?:0x[0-9A-Fa-f]+|\\d+))?)\\s*\\)')
    assign_re = re.compile('\\b(?P<dat>DAT_[0-9A-Fa-f]+)\\s*=\\s*\\(\\*\\*\\(code \\*\\*\\)\\(\\*param_1 \\+\\s*0xa8\\)\\)')
    for line in lines:
        m = new_string_re.search(line)
        if m is not None:
            recent_exprs.append(m.group('expr'))
            recent_exprs = recent_exprs[-4:]
            continue
        a = assign_re.search(line)
        if a is None or not recent_exprs:
            continue
        va = _expr_string_address(recent_exprs[-1], dat_ptr_values)
        if isinstance(va, int):
            out[a.group('dat')] = va
    return out

def _string_context(pseudocode_dir: Path) -> tuple[Dict[int, str], Dict[str, int]]:
    strings_path = pseudocode_dir.parent / 'ghidra' / 'strings.json'
    strings_by_addr: Dict[int, str] = {}
    if strings_path.is_file():
        try:
            strings_by_addr = _load_strings_json(strings_path)
        except Exception:
            strings_by_addr = {}
    _augment_short_strings_from_binary(pseudocode_dir, strings_by_addr)
    pseudo_c = pseudocode_dir.parent / 'pseudo_c' / 'decompiled.c'
    dat_ptr_values: Dict[str, int] = {}
    if pseudo_c.is_file():
        try:
            lines = pseudo_c.read_text(encoding='utf-8', errors='replace').splitlines()
            dat_ptr_values = _infer_dat_pointer_values(lines)
            dat_ptr_values.update(_infer_global_string_values(lines, dat_ptr_values))
        except Exception:
            dat_ptr_values = {}
    return (strings_by_addr, dat_ptr_values)

def _native_methods(native_index: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(native_index, dict):
        return []
    methods = native_index.get('methods')
    if not isinstance(methods, list):
        return []
    return [m for m in methods if isinstance(m, dict)]

def _jni_register_methods(pseudocode_dir: Path) -> List[Dict[str, Any]]:
    path = pseudocode_dir.parent / 'analysis' / 'jni_register.json'
    if not path.is_file():
        return []
    try:
        data = __import__('json').loads(path.read_text(encoding='utf-8'))
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for call in data.get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        cls = call.get('class')
        if not isinstance(cls, str) or not cls:
            cls = None
        for m in call.get('methods') or []:
            if not isinstance(m, dict):
                continue
            sig = m.get('signature')
            fn = m.get('fn_symbol')
            if not isinstance(sig, str) or not isinstance(fn, str):
                continue
            out.append({'class': cls, 'method': m.get('name'), 'descriptor': sig, 'fn_symbol': fn, 'sources': ['register_natives'], 'confidence': 70})
    return out

def _java_type_to_desc(java_type: str) -> Optional[str]:
    s = re.sub('\\s+', ' ', java_type.strip())
    if not s:
        return None
    array_dim = 0
    while s.endswith('[]'):
        array_dim += 1
        s = s[:-2].strip()
    s = re.sub('<.*>', '', s).strip()
    prim = {'void': 'V', 'boolean': 'Z', 'byte': 'B', 'char': 'C', 'short': 'S', 'int': 'I', 'long': 'J', 'float': 'F', 'double': 'D'}
    if s in prim:
        base = prim[s]
    elif s in {'String', 'java.lang.String'}:
        base = 'Ljava/lang/String;'
    elif s in {'Object', 'java.lang.Object'}:
        base = 'Ljava/lang/Object;'
    elif s in {'Class', 'java.lang.Class'}:
        base = 'Ljava/lang/Class;'
    else:
        base = 'L' + s.replace('.', '/') + ';'
    return '[' * array_dim + base

def _descriptor_from_decl(ret_raw: str, params_raw: str) -> Optional[str]:
    ret_desc = _java_type_to_desc(ret_raw)
    if not ret_desc:
        return None
    param_descs: List[str] = []
    if params_raw.strip():
        for part in params_raw.split(','):
            p = part.strip()
            if not p:
                continue
            toks = p.rsplit(' ', 1)
            typ = toks[0].strip() if len(toks) == 2 else p
            desc = _java_type_to_desc(typ)
            if not desc:
                return None
            param_descs.append(desc)
    return '(' + ''.join(param_descs) + ')' + ret_desc

def _java_sig(method: Dict[str, Any]) -> tuple[Optional[str], List[str]]:
    desc = method.get('descriptor')
    if not isinstance(desc, str) or not desc:
        return (None, [])
    parsed = _jni_method_sig_to_java(desc)
    if parsed is None:
        return (None, [])
    return parsed

def _int_literal(expr: str) -> Optional[int]:
    s = str(expr).strip().rstrip('uUlL')
    try:
        if s.lower().startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None

def _class_decl_name(text: str) -> Optional[str]:
    m = re.search('\\b(?:class|interface|enum)\\s+([A-Za-z_$][\\w$]*)\\b', text)
    return m.group(1) if m else None

def build_native_method_lookup(*, pseudocode_dir: Path, native_index: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    from detranspiler.native.index import resolve_native_index
    job_path = pseudocode_dir.parent / 'job.json'
    job = None
    if job_path.is_file():
        try:
            job = json.loads(job_path.read_text(encoding='utf-8', errors='replace'))
        except Exception:
            job = None
    analysis_dir = pseudocode_dir.parent / 'analysis'
    resolved_index = resolve_native_index(job=job if isinstance(job, dict) else None, analysis_dir=analysis_dir if analysis_dir.is_dir() else None, native_index=native_index if isinstance(native_index, dict) else None)
    native_methods = _native_methods(resolved_index)
    known_method_keys = {(m.get('class'), m.get('method'), m.get('descriptor'), m.get('fn_symbol')) for m in native_methods if isinstance(m, dict)}
    for m in _jni_register_methods(pseudocode_dir):
        key = (m.get('class'), m.get('method'), m.get('descriptor'), m.get('fn_symbol'))
        if key not in known_method_keys:
            native_methods.append(m)
            known_method_keys.add(key)
    native_by_class_method: Dict[tuple[str, str], Dict[str, Any]] = {}
    native_by_class_descriptor: Dict[tuple[str, str], Dict[str, Any]] = {}
    native_by_method_descriptor: Dict[tuple[str, str], Dict[str, Any]] = {}
    native_by_method_name: Dict[str, Dict[str, Any]] = {}
    descriptor_counts: Dict[tuple[str, str], int] = {}
    method_descriptor_counts: Dict[tuple[str, str], int] = {}
    method_name_counts: Dict[str, int] = {}
    for native_method in native_methods:
        cls = native_method.get('class')
        method_name = native_method.get('method')
        if isinstance(cls, str) and isinstance(method_name, str) and cls and method_name:
            existing = native_by_class_method.get((cls, method_name))
            if existing is None or (not existing.get('fn_symbol') and native_method.get('fn_symbol')):
                native_by_class_method[cls, method_name] = native_method
        desc = native_method.get('descriptor')
        if isinstance(cls, str) and isinstance(desc, str) and cls and desc:
            key = (cls, desc)
            descriptor_counts[key] = descriptor_counts.get(key, 0) + 1
            native_by_class_descriptor[key] = native_method
        if isinstance(method_name, str) and isinstance(desc, str) and method_name and desc:
            key2 = (method_name, desc)
            method_descriptor_counts[key2] = method_descriptor_counts.get(key2, 0) + 1
            native_by_method_descriptor[key2] = native_method
        if isinstance(method_name, str) and method_name:
            method_name_counts[method_name] = method_name_counts.get(method_name, 0) + 1
            native_by_method_name[method_name] = native_method
    strings_by_addr, dat_ptr_values = _string_context(pseudocode_dir)
    return {'native_index': resolved_index, 'recovered_body_index': _extract_recovered_bodies(pseudocode_dir), 'native_methods': native_methods, 'native_by_class_method': native_by_class_method, 'native_by_class_descriptor': {key: val for key, val in native_by_class_descriptor.items() if descriptor_counts.get(key) == 1}, 'native_by_method_descriptor': {key: val for key, val in native_by_method_descriptor.items() if method_descriptor_counts.get(key) == 1}, 'native_by_method_name': {key: val for key, val in native_by_method_name.items() if method_name_counts.get(key) == 1}, 'pseudoc_blocks': _extract_pseudoc_blocks(pseudocode_dir), 'strings_by_addr': strings_by_addr, 'dat_ptr_values': dat_ptr_values}
