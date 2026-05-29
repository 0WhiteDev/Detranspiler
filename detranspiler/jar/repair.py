from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.body.recovery import is_low_quality_body_lines, is_stub_body_lines
from detranspiler.jar.guided import build_jar_method_index, get_jar_fallback_body
from detranspiler.jar.similarity import similarity_between_bodies
from detranspiler.jar.body_index import _extract_methods_with_bodies, _path_to_internal, build_recovered_body_index, lookup_recovered_body
from detranspiler.jar.native_repair import build_repair_state_from_job, recover_stub_via_pipeline

def _descriptor_for_method(native_index: Optional[Dict[str, Any]], class_internal: str, method: str) -> Optional[str]:
    if not isinstance(native_index, dict):
        return None
    for item in native_index.get('methods') or []:
        if not isinstance(item, dict):
            continue
        if item.get('class') == class_internal and item.get('method') == method:
            desc = item.get('descriptor')
            if isinstance(desc, str):
                return desc
    return None

def _body_is_worth_keeping(body_lines: List[str], *, jar_index: Optional[Dict[str, Any]]=None, class_internal: Optional[str]=None, method_name: Optional[str]=None, descriptor: Optional[str]=None) -> bool:
    if is_stub_body_lines(body_lines):
        return False
    jar_body = None
    if isinstance(jar_index, dict) and class_internal and method_name:
        jar_body = get_jar_fallback_body(jar_index=jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
    if isinstance(jar_body, list) and jar_body:
        if is_low_quality_body_lines(body_lines, jar_reference=jar_body):
            return False
        if similarity_between_bodies(body_lines, jar_body) < 0.35:
            return False
    return True

def _format_repair_lines(repair_body: List[str]) -> List[str]:
    repair_lines: List[str] = []
    for line in repair_body:
        s = line.strip()
        if s.startswith('//'):
            continue
        repair_lines.append(line if line.startswith('    ') else f'    {s}')
    return repair_lines

def _repair_pass(*, pseudocode_dir: Path, native_index: Optional[Dict[str, Any]], jar_index: Optional[Dict[str, Any]], recovered_body_index: Dict[str, List[str]], repair_state: Any, max_files: int) -> Tuple[List[Dict[str, Any]], int, int, int, int, int]:
    repaired: List[Dict[str, Any]] = []
    files_scanned = 0
    methods_repaired = 0
    methods_repaired_from_jar = 0
    methods_repaired_from_native = 0
    methods_repaired_from_pipeline = 0
    java_files: List[Path] = []
    for sub in ('jni', 'jni_exports'):
        d = pseudocode_dir / sub
        if d.is_dir():
            java_files.extend(sorted(d.rglob('*.java')))
    aggregate = pseudocode_dir / 'NativeDecompiled.java'
    if aggregate.is_file():
        java_files.append(aggregate)
    for java_file in java_files[:max_files]:
        files_scanned += 1
        try:
            rel = str(java_file.relative_to(pseudocode_dir)).replace('\\', '/')
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        class_internal = _path_to_internal(rel)
        methods = _extract_methods_with_bodies(text)
        if not methods:
            continue
        new_text = text
        offset = 0
        file_repaired = False
        for method_name, body_start, body_end, body_lines in methods:
            descriptor = _descriptor_for_method(native_index, class_internal, method_name)
            if _body_is_worth_keeping(body_lines, jar_index=jar_index, class_internal=class_internal, method_name=method_name, descriptor=descriptor):
                continue
            jar_body = None
            if isinstance(jar_index, dict):
                jar_body = get_jar_fallback_body(jar_index=jar_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
            native_body = lookup_recovered_body(recovered_body_index, class_internal=class_internal, method=method_name, descriptor=descriptor)
            source = None
            repair_body: Optional[List[str]] = None
            if isinstance(jar_body, list) and jar_body:
                repair_body = jar_body
                source = 'jar'
            elif isinstance(native_body, list) and native_body:
                repair_body = native_body
                source = 'native'
            elif repair_state is not None:
                pipeline_body = recover_stub_via_pipeline(repair_state, native_index, class_internal=class_internal, method_name=method_name, descriptor=descriptor)
                if isinstance(pipeline_body, list) and pipeline_body:
                    repair_body = pipeline_body
                    source = 'pipeline'
            if not isinstance(repair_body, list) or not repair_body or source is None:
                continue
            repair_lines = _format_repair_lines(repair_body)
            replacement = '\n' + '\n'.join(repair_lines) + '\n  '
            adj_start = body_start + offset
            adj_end = body_end + offset
            new_text = new_text[:adj_start] + replacement + new_text[adj_end:]
            offset += len(replacement) - (body_end - body_start)
            methods_repaired += 1
            if source == 'jar':
                methods_repaired_from_jar += 1
            elif source == 'native':
                methods_repaired_from_native += 1
            else:
                methods_repaired_from_pipeline += 1
            file_repaired = True
            repaired.append({'file': rel, 'class': class_internal, 'method': method_name, 'descriptor': descriptor, 'source': source})
        if file_repaired:
            java_file.write_text(new_text, encoding='utf-8')
    return repaired, files_scanned, methods_repaired, methods_repaired_from_jar, methods_repaired_from_native, methods_repaired_from_pipeline

def repair_stub_methods(*, pseudocode_dir: Path, jar_sources_dir: Optional[Path]=None, native_index: Optional[Dict[str, Any]]=None, jar_index: Optional[Dict[str, Any]]=None, recovered_body_index: Optional[Dict[str, List[str]]]=None, job: Optional[Dict[str, Any]]=None, max_files: int=2000, passes: int=2) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    if not pseudocode_dir.is_dir():
        return {'status': 'SKIPPED_NO_PSEUDOCODE_DIR'}
    if jar_sources_dir is not None:
        jar_sources_dir = jar_sources_dir.expanduser().resolve()
    if jar_index is None and jar_sources_dir is not None and jar_sources_dir.is_dir():
        jar_index = build_jar_method_index(jar_sources_dir=jar_sources_dir)
    if recovered_body_index is None:
        recovered_body_index = build_recovered_body_index(pseudocode_dir=pseudocode_dir, max_files=max_files)
    repair_state = build_repair_state_from_job(job, pseudocode_dir=pseudocode_dir) if job else None
    all_repaired: List[Dict[str, Any]] = []
    files_scanned = 0
    methods_repaired = 0
    methods_repaired_from_jar = 0
    methods_repaired_from_native = 0
    methods_repaired_from_pipeline = 0
    pass_count = max(1, int(passes))
    for pass_idx in range(pass_count):
        if pass_idx > 0:
            recovered_body_index = build_recovered_body_index(pseudocode_dir=pseudocode_dir, max_files=max_files)
        pass_repaired, pass_files, pass_methods, pass_jar, pass_native, pass_pipeline = _repair_pass(pseudocode_dir=pseudocode_dir,
                                                                                                     native_index=native_index, jar_index=jar_index, recovered_body_index=recovered_body_index, repair_state=repair_state, max_files=max_files)
        files_scanned = max(files_scanned, pass_files)
        methods_repaired += pass_methods
        methods_repaired_from_jar += pass_jar
        methods_repaired_from_native += pass_native
        methods_repaired_from_pipeline += pass_pipeline
        all_repaired.extend(pass_repaired)
        if pass_methods == 0 and pass_idx > 0:
            break
    return {'status': 'OK', 'passes': pass_count, 'files_scanned': files_scanned, 'methods_repaired': methods_repaired, 'methods_repaired_from_jar': methods_repaired_from_jar, 'methods_repaired_from_native': methods_repaired_from_native, 'methods_repaired_from_pipeline': methods_repaired_from_pipeline, 'repairs': all_repaired[:500]}

def repair_jar_native_declarations(*, pseudocode_dir: Path, native_index: Optional[Dict[str, Any]]=None, job: Optional[Dict[str, Any]]=None, source_subdirs: Tuple[str, ...]=('jar_sources',), max_files: int=2000, in_place: bool=False) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    if not pseudocode_dir.is_dir():
        return {'status': 'SKIPPED_NO_PSEUDOCODE_DIR'}
    from detranspiler.jar.radioegor.context import build_native_method_lookup
    from detranspiler.jar.radioegor.overlay import _replace_native_declarations
    from detranspiler.jar.native_repair import build_repair_state_from_job
    if job is None:
        job_path = pseudocode_dir.parent / 'job.json'
        if job_path.is_file():
            try:
                import json
                job = json.loads(job_path.read_text(encoding='utf-8', errors='replace'))
            except Exception:
                job = None
    lookup = build_native_method_lookup(pseudocode_dir=pseudocode_dir, native_index=native_index)
    recovered_body_index = lookup['recovered_body_index']
    native_by_class_method = lookup['native_by_class_method']
    native_by_class_descriptor = lookup['native_by_class_descriptor']
    native_by_method_descriptor = lookup['native_by_method_descriptor']
    native_by_method_name = lookup['native_by_method_name']
    pseudoc_blocks = lookup['pseudoc_blocks']
    strings_by_addr = lookup['strings_by_addr']
    dat_ptr_values = lookup['dat_ptr_values']
    repair_state = build_repair_state_from_job(job, pseudocode_dir=pseudocode_dir) if isinstance(job, dict) else None
    files_scanned = 0
    methods_repaired = 0
    repairs: List[Dict[str, Any]] = []
    for subdir in source_subdirs:
        source_root = pseudocode_dir / subdir
        if not source_root.is_dir():
            continue
        for java_file in sorted(source_root.rglob('*.java'))[:max_files]:
            rel = java_file.relative_to(source_root)
            rel_posix = str(rel).replace('\\', '/')
            if rel_posix.startswith('native0/'):
                continue
            files_scanned += 1
            try:
                text = java_file.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            class_internal = rel_posix[:-5] if rel_posix.endswith('.java') else rel_posix
            new_text, replaced = _replace_native_declarations(text, class_internal=class_internal, recovered_body_index=recovered_body_index, native_by_class_method=native_by_class_method, native_by_class_descriptor=native_by_class_descriptor, native_by_method_descriptor=native_by_method_descriptor, native_by_method_name=native_by_method_name, pseudoc_blocks=pseudoc_blocks, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, repair_state=repair_state)
            if replaced <= 0:
                continue
            methods_repaired += replaced
            if in_place:
                java_file.write_text(new_text, encoding='utf-8')
            repairs.append({'file': f'{subdir}/{rel_posix}', 'class': class_internal, 'methods_repaired': replaced})
    return {'status': 'OK', 'files_scanned': files_scanned, 'methods_repaired': methods_repaired, 'repairs': repairs[:500]}
