from __future__ import annotations
import difflib
from collections import Counter
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from detranspiler.java.jni_descriptors import _jni_method_sig_to_java
from detranspiler.provenance.model import compress_ranges, layer_label, line_at, method_candidate, normalize_shape, read_json, source_labels
from detranspiler.validation.java_ast import find_methods

def _descriptor_params(descriptor: Any) -> List[str]:
    parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
    return parsed[1] if parsed is not None else []

def _with_java_params(items: Iterable[Any], class_key: str='class') -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for value in items:
        if not isinstance(value, dict):
            continue
        item = dict(value)
        if class_key in item and 'class_internal' not in item:
            item['class_internal'] = item.get(class_key)
        if not isinstance(item.get('java_params'), list):
            item['java_params'] = _descriptor_params(item.get('descriptor'))
        output.append(item)
    return output

def _confidence(value: Any) -> Optional[float]:
    if not isinstance(value, (int, float)):
        return None
    score = float(value)
    if score > 1:
        score /= 100.0
    return round(max(0.0, min(1.0, score)), 3)

def _method_key(item: Dict[str, Any]) -> Tuple[str, str, str]:
    return str(item.get('class_internal', item.get('class')) or ''), str(item.get('method') or ''), str(item.get('descriptor') or '')

def _jni_index(document: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    for call in document.get('calls') or []:
        if not isinstance(call, dict) or not isinstance(call.get('function'), str):
            continue
        result.setdefault(call['function'], []).append({'line': call.get('line'), 'jni_name': call.get('jni_name'), 'category': call.get('category'), 'source_line': call.get('source_line'), 'resolved': call.get('resolved'), 'resolved_classes': call.get('resolved_classes')})
    return result

def _jni_summary(calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    names: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    for call in calls:
        name = str(call.get('jni_name') or 'unknown')
        category = str(call.get('category') or 'other')
        names[name] = names.get(name, 0) + 1
        categories[category] = categories.get(category, 0) + 1
    return {'calls_total': len(calls), 'names': dict(sorted(names.items(), key=lambda item: (-item[1], item[0]))[:30]), 'categories': dict(sorted(categories.items()))}

def _bounded_calls(calls: List[Dict[str, Any]], limit: int=160) -> List[Dict[str, Any]]:
    if len(calls) <= limit:
        return calls
    indices = set(range(limit // 2))
    names = {str(calls[index].get('jni_name') or '') for index in indices}
    for index, call in enumerate(calls[limit // 2:], start=limit // 2):
        name = str(call.get('jni_name') or '')
        if name not in names:
            indices.add(index)
            names.add(name)
    remaining = limit - len(indices)
    if remaining > 0:
        stride = max(1, len(calls) // remaining)
        for index in range(0, len(calls), stride):
            indices.add(index)
            if len(indices) >= limit:
                break
    return [calls[index] for index in sorted(indices)[:limit]]


def _baseline_matches(final_lines: List[str], baseline_lines: List[str]) -> set[int]:
    matches: set[int] = set()
    matcher = difflib.SequenceMatcher(None, baseline_lines, final_lines, autojunk=False)
    for tag, _, _, final_start, final_end in matcher.get_opcodes():
        if tag == 'equal':
            matches.update(range(final_start + 1, final_end + 1))
    return matches

def _validation_repairs(document: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    for item in document.get('files') or []:
        if isinstance(item, dict) and isinstance(item.get('relative_path'), str):
            result[item['relative_path']] = [repair for repair in item.get('repairs') or [] if isinstance(repair, dict)]
    return result

def _parsed_method_candidate(items: Iterable[Dict[str, Any]], name: str, shape: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
    matches = [item for item in items if item.get('name') == name and normalize_shape(item.get('parameter_shape') or []) == shape]
    return matches[0] if len(matches) == 1 else None


def build_source_provenance(*, out_dir: Path, output_path: Optional[Path]=None, max_files: Optional[int]=None) -> Dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    pseudocode_dir = out_dir / 'pseudocode'
    sources_root = pseudocode_dir / 'sources'
    analysis_dir = out_dir / 'analysis'
    if not sources_root.is_dir():
        return {'status': 'SKIPPED_NO_SOURCES'}
    manifest = read_json(pseudocode_dir / 'sources_manifest.json')
    layers = {str(item.get('path')): str(item.get('source_layer')) for item in manifest.get('files') or [] if isinstance(item, dict) and item.get('path')}
    native_map = read_json(analysis_dir / 'native_map.json')
    native_methods = _with_java_params(native_map.get('methods') or [], class_key='class_internal')
    recovery = read_json(analysis_dir / 'method_recovery.json')
    recovery_methods = _with_java_params(recovery.get('methods') or [])
    confidence_doc = read_json(analysis_dir / 'method_confidence.json')
    confidence_methods = _with_java_params(confidence_doc.get('methods') or [])
    confidence_by_key = {_method_key(item): item for item in confidence_methods}
    recovery_by_key = {_method_key(item): item for item in recovery_methods}
    jni_by_function = _jni_index(read_json(analysis_dir / 'jni_calls.json'))
    repairs_by_file = _validation_repairs(read_json(analysis_dir / 'java_validation.json'))
    files: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}
    evidence_counter = 0

    def add_evidence(value: Dict[str, Any]) -> str:
        nonlocal evidence_counter
        evidence_counter += 1
        evidence_id = f'e{evidence_counter:06d}'
        evidence[evidence_id] = value
        return evidence_id

    methods_total = 0
    native_methods_linked = 0
    lines_total = 0
    methods_with_body_evidence = 0
    methods_with_generated_body_evidence = 0
    line_roles: Counter[str] = Counter()
    source_line_counts: Counter[str] = Counter()
    source_paths = sorted(sources_root.rglob('*.java'))
    files_available = len(source_paths)
    if max_files is not None:
        source_paths = source_paths[:max(0, int(max_files))]
    truncated = len(source_paths) < files_available
    status = 'OK_TRUNCATED' if truncated else 'OK'
    for path in source_paths:
        rel = path.relative_to(sources_root).as_posix()
        text = path.read_text(encoding='utf-8', errors='replace')
        source_lines = text.splitlines()
        lines_total += len(source_lines)
        class_internal = rel[:-5] if rel.endswith('.java') else rel
        layer = layers.get(rel, 'unknown')
        file_source = layer_label(layer)
        file_evidence = add_evidence({'kind': 'file', 'path': rel, 'class_internal': class_internal, 'sources': [file_source], 'confidence': {'semantic': 0.95 if file_source == 'CFR' else 0.6, 'mapping': None}})
        evidence_ids = [file_evidence for _ in source_lines]
        roles = ['file' for _ in source_lines]
        baseline_path = pseudocode_dir / 'jar_sources' / rel
        baseline_text = baseline_path.read_text(encoding='utf-8', errors='replace') if baseline_path.is_file() else ''
        baseline_lines = baseline_text.splitlines()
        cfr_lines = _baseline_matches(source_lines, baseline_lines) if baseline_lines else set()
        cfr_evidence = file_evidence
        if baseline_lines and file_source != 'CFR':
            cfr_evidence = add_evidence({'kind': 'file', 'path': rel, 'class_internal': class_internal, 'sources': ['CFR'], 'confidence': {'semantic': 0.95, 'mapping': None}})
            for line in cfr_lines:
                if 0 < line <= len(evidence_ids):
                    evidence_ids[line - 1] = cfr_evidence
        parsed_methods = find_methods(text)
        baseline_methods = find_methods(baseline_text) if baseline_text else []
        method_records: List[Dict[str, Any]] = []
        for method in parsed_methods:
            methods_total += 1
            name = str(method.get('name') or '')
            shape = normalize_shape(method.get('parameter_shape') or [])
            native = method_candidate(native_methods, class_internal=class_internal, name=name, shape=shape)
            baseline = _parsed_method_candidate(baseline_methods, name, shape)
            descriptor = str(native.get('descriptor') or '') if isinstance(native, dict) else ''
            key = (class_internal, name, descriptor)
            recovered = recovery_by_key.get(key) if descriptor else method_candidate(recovery_methods, class_internal=class_internal, name=name, shape=shape)
            scored = confidence_by_key.get(key) if descriptor else method_candidate(confidence_methods, class_internal=class_internal, name=name, shape=shape)
            symbol = native.get('fn_symbol') if isinstance(native, dict) else recovered.get('fn_symbol') if isinstance(recovered, dict) else None
            calls = jni_by_function.get(str(symbol), []) if isinstance(symbol, str) else []
            mapping_confidence = _confidence(native.get('confidence')) if isinstance(native, dict) else None
            evidence_calls = _bounded_calls(calls)
            semantic_confidence = _confidence(scored.get('score')) if isinstance(scored, dict) else _confidence(recovered.get('score')) if isinstance(recovered, dict) else None
            start_line = line_at(text, method.get('start'))
            end_line = line_at(text, max(int(method.get('start') or 0), int(method.get('end') or 1) - 1))
            body_line = line_at(text, method.get('body_start')) if isinstance(method.get('body_text'), str) else None
            base_sources = ['CFR'] if baseline is not None else [file_source]
            native_sources = source_labels(native.get('sources') or []) if isinstance(native, dict) else []
            recovery_sources = source_labels(recovered.get('sources') or []) if isinstance(recovered, dict) else []
            native_payload = None
            if isinstance(native, dict):
                native_methods_linked += 1
                c_span = native.get('decompiled_c_lines') if isinstance(native.get('decompiled_c_lines'), list) else None
                native_payload = {'symbol': native.get('fn_symbol'), 'address': native.get('address'), 'descriptor': native.get('descriptor'), 'java_signature': native.get('java_signature'), 'c_signature': native.get('c_signature'), 'calling_convention': native.get('calling_convention'), 'callees': native.get('callees') or [], 'c_file': f"native_map/{native.get('c_file')}" if native.get('c_file') else None, 'pseudo_c': {'path': 'pseudo_c/decompiled.c', 'lines': c_span} if c_span else None}
            declaration_sources = base_sources + [value for value in native_sources if value not in base_sources]
            declaration_evidence = add_evidence({'kind': 'method_declaration', 'path': rel, 'class_internal': class_internal, 'method': name, 'descriptor': descriptor or None, 'parameter_shape': list(shape), 'sources': declaration_sources, 'confidence': {'semantic': 0.95 if baseline is not None else semantic_confidence, 'mapping': mapping_confidence}, 'native': native_payload, 'jni_summary': _jni_summary(calls), 'jni_calls': evidence_calls})
            for line in range(start_line, min(end_line, len(evidence_ids)) + 1):
                evidence_ids[line - 1] = declaration_evidence
                roles[line - 1] = 'declaration'
            generated_evidence = None
            baseline_body_evidence = None
            baseline_has_body = isinstance(baseline, dict) and isinstance(baseline.get('body_text'), str)
            if baseline_has_body:
                baseline_body_evidence = add_evidence({'kind': 'method_body', 'path': rel, 'class_internal': class_internal, 'method': name, 'descriptor': descriptor or None, 'parameter_shape': list(shape), 'sources': ['CFR'], 'confidence': {'semantic': 0.95, 'mapping': mapping_confidence}, 'native': native_payload, 'jni_summary': _jni_summary(calls), 'jni_calls': evidence_calls})
            if isinstance(method.get('body_text'), str) and (native is not None or recovered is not None or file_source != 'CFR' and baseline is None):
                generated_sources = [file_source] + [value for value in native_sources if value not in {'CFR', 'JAR metadata'}] + recovery_sources
                if isinstance(native, dict) and native.get('body_found') and 'Ghidra pseudo-C' not in generated_sources:
                    generated_sources.append('Ghidra pseudo-C')
                if calls and 'JNI trace' not in generated_sources:
                    generated_sources.append('JNI trace')
                generated_sources = list(dict.fromkeys(generated_sources))
                generated_evidence = add_evidence({'kind': 'method_body', 'path': rel, 'class_internal': class_internal, 'method': name, 'descriptor': descriptor or None, 'parameter_shape': list(shape), 'sources': generated_sources, 'confidence': {'semantic': semantic_confidence if semantic_confidence is not None else 0.35, 'mapping': mapping_confidence}, 'native': native_payload, 'jni_summary': _jni_summary(calls), 'jni_calls': evidence_calls})
                methods_with_generated_body_evidence += 1
            body_evidence_ids = [value for value in (baseline_body_evidence, generated_evidence) if isinstance(value, str)]
            if isinstance(method.get('body_text'), str) and body_evidence_ids:
                methods_with_body_evidence += 1
                first_body_line = max(start_line + 1, body_line or start_line + 1)
                for line in range(first_body_line, min(end_line, len(evidence_ids)) + 1):
                    if baseline_body_evidence is not None and line in cfr_lines:
                        evidence_ids[line - 1] = baseline_body_evidence
                        roles[line - 1] = 'body'
                    elif generated_evidence is not None:
                        evidence_ids[line - 1] = generated_evidence
                        roles[line - 1] = 'body'
                    elif baseline_body_evidence is not None:
                        evidence_ids[line - 1] = baseline_body_evidence
                        roles[line - 1] = 'body'
            method_records.append({'method': name, 'descriptor': descriptor or None, 'parameter_shape': list(shape), 'start_line': start_line, 'end_line': end_line, 'body_start_line': body_line, 'native': bool(method.get('native')), 'original_native': bool(baseline.get('native')) if isinstance(baseline, dict) else None, 'recovered': bool(native is not None and not method.get('native') and generated_evidence is not None), 'declaration_evidence_id': declaration_evidence, 'body_evidence_id': generated_evidence or baseline_body_evidence, 'body_evidence_ids': body_evidence_ids})
        for repair in repairs_by_file.get(rel, []):
            affected_lines: List[int] = []
            if isinstance(repair.get('line'), int):
                affected_lines.append(int(repair['line']))
            elif repair.get('code') == 'missing_import' and isinstance(repair.get('import'), str):
                target = f"import {repair['import']};"
                affected_lines.extend(index + 1 for index, value in enumerate(source_lines) if value.strip() == target)
            for line in affected_lines:
                if not (0 < line <= len(evidence_ids)):
                    continue
                parent = evidence.get(evidence_ids[line - 1], {})
                repair_evidence = dict(parent)
                repair_evidence['kind'] = 'safe_repair'
                repair_evidence['sources'] = list(dict.fromkeys(['Java validation'] + list(parent.get('sources') or [])))
                repair_evidence['repair'] = repair
                repair_evidence['confidence'] = {'semantic': 0.9, 'mapping': (parent.get('confidence') or {}).get('mapping') if isinstance(parent.get('confidence'), dict) else None}
                evidence_ids[line - 1] = add_evidence(repair_evidence)
                roles[line - 1] = 'repair'
        file_role_counts = Counter(roles)
        line_roles.update(file_role_counts)
        for evidence_id in evidence_ids:
            item = evidence.get(evidence_id)
            if not isinstance(item, dict):
                continue
            source_line_counts.update(set(item.get('sources') or []))
        files[rel] = {'path': rel, 'class_internal': class_internal, 'source_layer': layer, 'lines_total': len(source_lines), 'role_counts': dict(sorted(file_role_counts.items())), 'ranges': compress_ranges(evidence_ids, roles), 'methods': method_records}
    native_mapping_coverage = round(native_methods_linked / len(native_methods), 3) if native_methods else None
    result = {'status': status, 'schema_version': 1, 'sources_dir': str(sources_root), 'files_available': files_available, 'files_total': len(files), 'truncated': truncated, 'lines_total': lines_total, 'methods_total': methods_total, 'methods_with_body_evidence': methods_with_body_evidence, 'methods_with_generated_body_evidence': methods_with_generated_body_evidence, 'native_methods_total': len(native_methods), 'native_methods_linked': native_methods_linked, 'native_mapping_coverage': native_mapping_coverage, 'line_role_counts': dict(sorted(line_roles.items())), 'source_line_counts': dict(sorted(source_line_counts.items())), 'evidence_total': len(evidence), 'files': files, 'evidence': evidence}
    target = output_path.expanduser().resolve() if output_path is not None else analysis_dir / 'source_provenance.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'status': status, 'output_path': str(target), 'files_available': files_available, 'files_total': len(files), 'truncated': truncated, 'lines_total': lines_total, 'methods_total': methods_total, 'methods_with_body_evidence': methods_with_body_evidence, 'methods_with_generated_body_evidence': methods_with_generated_body_evidence, 'native_methods_total': len(native_methods), 'native_methods_linked': native_methods_linked, 'native_mapping_coverage': native_mapping_coverage, 'line_role_counts': dict(sorted(line_roles.items())), 'source_line_counts': dict(sorted(source_line_counts.items())), 'evidence_total': len(evidence)}
