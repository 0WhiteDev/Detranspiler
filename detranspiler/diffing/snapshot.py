from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional


_HEX = re.compile(r'0x[0-9a-fA-F]{7,}|\bFUN_[0-9a-fA-F]+\b')
_SPACE = re.compile(r'\s+')


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def _artifact_path(job: Dict[str, Any], key: str, fallback: Path) -> Path:
    if fallback.is_file():
        return fallback
    artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
    value = artifacts.get(key)
    if isinstance(value, str):
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate
    return fallback


def _method_key(class_name: Any, method: Any, descriptor: Any) -> str:
    return f'{class_name or "?"}#{method or "?"}{descriptor or ""}'


def _function_fingerprint(function: Dict[str, Any]) -> str:
    instructions = []
    for item in function.get('instructions') or []:
        if not isinstance(item, dict):
            continue
        text = _HEX.sub('<addr>', str(item.get('text') or '')).lower()
        instructions.append([str(item.get('mnemonic') or '').upper(), _SPACE.sub(' ', text).strip()])
    params = [str(item.get('data_type') or '') for item in function.get('parameters') or [] if isinstance(item, dict)]
    payload = [str(function.get('return_type') or ''), params, instructions]
    return hashlib.sha256(json.dumps(payload, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()


def _source_methods(root: Path, provenance: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    if not isinstance(provenance, dict):
        return result
    sources_dir = Path(str(provenance.get('sources_dir') or root / 'pseudocode' / 'sources'))
    if not sources_dir.is_dir():
        sources_dir = root / 'pseudocode' / 'sources'
    for relative, file_info in (provenance.get('files') or {}).items():
        if not isinstance(file_info, dict):
            continue
        source_path = sources_dir / str(relative)
        try:
            lines = source_path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            continue
        class_name = file_info.get('class_internal') or str(relative).removesuffix('.java')
        for index, method in enumerate(file_info.get('methods') or []):
            if not isinstance(method, dict):
                continue
            start = max(1, int(method.get('start_line') or 1))
            end = min(len(lines), int(method.get('end_line') or start))
            text = '\n'.join(lines[start - 1:end]).strip()
            descriptor = method.get('descriptor')
            shape = ','.join(str(value) for value in method.get('parameter_shape') or [])
            key = _method_key(class_name, method.get('method'), descriptor or f'({shape})')
            if key in result:
                key = f'{key}@{index}'
            result[key] = {'key': key, 'class': class_name, 'method': method.get('method'), 'descriptor': descriptor, 'parameter_shape': method.get('parameter_shape') or [], 'path': str(relative), 'start_line': start, 'end_line': end, 'text': text}
    return result


def build_snapshot(root: Path) -> Dict[str, Any]:
    root = root.resolve()
    job = _read_json(root / 'job.json')
    if not isinstance(job, dict):
        raise ValueError(f'Invalid analysis job: {root / "job.json"}')
    analysis = root / 'analysis'
    native_doc = _read_json(_artifact_path(job, 'native_index_json', analysis / 'native_index.json'))
    register_doc = _read_json(_artifact_path(job, 'jni_register_json', analysis / 'jni_register.json'))
    confidence_doc = _read_json(_artifact_path(job, 'method_confidence_json', analysis / 'method_confidence.json'))
    provenance_doc = _read_json(_artifact_path(job, 'source_provenance_json', analysis / 'source_provenance.json'))
    function_doc = _read_json(_artifact_path(job, 'ghidra_functions_json', root / 'ghidra' / 'functions.json'))
    ghidra_strings_doc = _read_json(_artifact_path(job, 'ghidra_strings_json', root / 'ghidra' / 'strings.json'))
    raw_strings_doc = _read_json(root / 'metadata' / 'strings.json')
    decrypted_doc = _read_json(_artifact_path(job, 'string_decrypt_json', analysis / 'string_decrypt.json'))
    functions: Dict[str, Dict[str, Any]] = {}
    for function in (function_doc or {}).get('functions') or []:
        if not isinstance(function, dict):
            continue
        name = str(function.get('name') or function.get('entry') or '')
        entry = str(function.get('entry') or '')
        data = {'name': name, 'entry': entry, 'fingerprint': _function_fingerprint(function)}
        functions[name] = data
        if entry:
            functions[entry] = data
    methods: Dict[str, Dict[str, Any]] = {}
    for method in (native_doc or {}).get('methods') or []:
        if isinstance(method, dict):
            key = _method_key(method.get('class'), method.get('method'), method.get('descriptor'))
            fn = functions.get(str(method.get('fn_symbol') or ''))
            methods[key] = {**method, 'key': key, 'function_fingerprint': fn.get('fingerprint') if fn else None}
    registrations: Dict[str, Dict[str, Any]] = {}
    for call in (register_doc or {}).get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        for method in call.get('methods') or []:
            if not isinstance(method, dict):
                continue
            key = _method_key(call.get('class'), method.get('name'), method.get('signature'))
            fn = functions.get(str(method.get('fn_symbol') or '')) or functions.get(str(method.get('fn_address') or ''))
            registrations[key] = {'key': key, 'class': call.get('class'), 'method': method.get('name'), 'descriptor': method.get('signature'), 'registrar': call.get('function'), 'fn_symbol': method.get('fn_symbol'), 'mapping_source': method.get('mapping_source'), 'function_fingerprint': fn.get('fingerprint') if fn else None}
    confidence: Dict[str, Dict[str, Any]] = {}
    for method in (confidence_doc or {}).get('methods') or []:
        if isinstance(method, dict):
            key = _method_key(method.get('class'), method.get('method'), method.get('descriptor'))
            confidence[key] = {**method, 'key': key}
    named_methods = {str(value.get('fn_symbol')): key for key, value in methods.items() if value.get('fn_symbol')}
    fingerprint_counts = Counter(value['fingerprint'] for name, value in functions.items() if name == value['name'])
    def canonical(name: Any, address: Any) -> Optional[str]:
        raw = str(name or address or '')
        if raw in named_methods:
            return named_methods[raw]
        fn = functions.get(raw) or functions.get(str(address or ''))
        if fn and fingerprint_counts[fn['fingerprint']] == 1:
            return f'fn:{fn["fingerprint"]}'
        if raw and not raw.startswith('FUN_'):
            return f'symbol:{raw}'
        return None
    edges = set()
    omitted_edges = 0
    for edge in (function_doc or {}).get('callgraph_edges') or []:
        if not isinstance(edge, dict):
            continue
        source = canonical(edge.get('from_name'), edge.get('from'))
        target = canonical(edge.get('to_name'), edge.get('to'))
        if source and target:
            edges.add((source, target))
        else:
            omitted_edges += 1
    ghidra_strings = [{'address': str(item.get('address') or ''), 'value': str(item.get('value') or '')} for item in (ghidra_strings_doc or {}).get('strings') or [] if isinstance(item, dict)]
    raw_strings = [str(value) for value in (raw_strings_doc or {}).get('strings') or []]
    decrypted = []
    for item in (decrypted_doc or {}).get('strings') or (decrypted_doc or {}).get('recovered_strings') or []:
        decrypted.append(str(item.get('value') or item.get('text') or '') if isinstance(item, dict) else str(item))
    pseudocode = _source_methods(root, provenance_doc)
    availability = {
        'jni_methods': isinstance(native_doc, dict) and isinstance(native_doc.get('methods'), list),
        'registrations': isinstance(register_doc, dict) and isinstance(register_doc.get('register_calls'), list),
        'confidence': isinstance(confidence_doc, dict) and isinstance(confidence_doc.get('methods'), list),
        'call_graph': isinstance(function_doc, dict) and isinstance(function_doc.get('functions'), list) and isinstance(function_doc.get('callgraph_edges'), list),
        'ghidra_strings': isinstance(ghidra_strings_doc, dict) and isinstance(ghidra_strings_doc.get('strings'), list),
        'raw_strings': isinstance(raw_strings_doc, dict) and isinstance(raw_strings_doc.get('strings'), list),
        'decrypted_strings': isinstance(decrypted_doc, dict) and (isinstance(decrypted_doc.get('strings'), list) or isinstance(decrypted_doc.get('recovered_strings'), list)),
        'pseudocode': isinstance(provenance_doc, dict) and isinstance(provenance_doc.get('files'), dict) and (bool(pseudocode) or not provenance_doc.get('files')),
    }
    return {'root': str(root), 'input': job.get('input') or {}, 'methods': methods, 'registrations': registrations, 'confidence': confidence, 'edges': sorted(edges), 'omitted_edges': omitted_edges, 'strings': {'ghidra': ghidra_strings, 'raw': raw_strings, 'decrypted': decrypted}, 'pseudocode': pseudocode, 'availability': availability}
