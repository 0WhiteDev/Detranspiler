from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.java.jni_descriptors import _internal_class_to_package_and_class, _jni_parameter_shape
from detranspiler.jar.radioegor.context import _descriptor_from_decl
from detranspiler.jar.radioegor.util import _NATIVE_DECL_RE
_SCaffold_PREFIX = 'native0/'

def _is_application_class(class_internal: str) -> bool:
    if class_internal == 'NativeDecompiled':
        return False
    return not class_internal.startswith(_SCaffold_PREFIX)
_NATIVE_METHOD_RE = re.compile('(?m)(?:^[ \\t]*(?:@[\\w.]+\\s*)*)?(?:(?:public|private|protected|static|final|synchronized|strictfp|abstract)\\s+)*native\\s+(?:/\\*[^*]*\\*/\\s*)?[\\w<>\\[\\],\\s.?/*]+?(?<![\\w$]){name}\\s*\\(')

def _sources_root(job: Dict[str, Any]) -> Optional[Path]:
    artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
    sources_dir = artifacts.get('sources_dir')
    if isinstance(sources_dir, str):
        root = Path(sources_dir).expanduser()
        if root.is_dir():
            return root
    pseudocode_dir = artifacts.get('pseudocode_dir')
    if isinstance(pseudocode_dir, str):
        root = Path(pseudocode_dir).expanduser() / 'sources'
        if root.is_dir():
            return root
    return None

def _native_index_methods(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    from detranspiler.native.index import resolve_native_index
    from detranspiler.reporting.re_map import get_analysis_dir_from_job

    analysis_dir = get_analysis_dir_from_job(job)
    analysis = job.get('analysis') if isinstance(job.get('analysis'), dict) else {}
    native_index = resolve_native_index(job=job, analysis_dir=analysis_dir, native_index=analysis.get('native_index') if isinstance(analysis.get('native_index'), dict) else None)
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for item in native_index.get('methods') or []:
        if not isinstance(item, dict):
            continue
        cls = item.get('class')
        method = item.get('method')
        desc = item.get('descriptor')
        if not (isinstance(cls, str) and isinstance(method, str) and isinstance(desc, str)):
            continue
        if method.startswith('$jnic'):
            continue
        key = (cls, method, desc)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

def _class_source_path(sources_root: Path, class_internal: str) -> Path:
    rel = class_internal.replace('\\', '/').strip('/') + '.java'
    return sources_root / rel

def _method_still_native(source_text: str, method_name: str, descriptor: Optional[str]) -> bool:
    if not source_text or not method_name:
        return False
    if method_name in {'<init>', '<clinit>'}:
        return False
    target_shape = _jni_parameter_shape(descriptor) if isinstance(descriptor, str) else None
    for match in _NATIVE_DECL_RE.finditer(source_text):
        if match.group('name') != method_name:
            continue
        if target_shape is None:
            return True
        declared = _descriptor_from_decl(match.group('ret'), match.group('params'))
        if isinstance(declared, str) and _jni_parameter_shape(declared) == target_shape:
            return True
    return False

def _scan_class_native_recovery(*, class_internal: str, native_methods: List[Dict[str, Any]], sources_root: Path) -> Dict[str, Any]:
    source_path = _class_source_path(sources_root, class_internal)
    source_text = ''
    has_source = source_path.is_file()
    if has_source:
        try:
            source_text = source_path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            source_text = ''
    pkg, cls_simple = _internal_class_to_package_and_class(class_internal)
    fqcn = f'{pkg}.{cls_simple}' if pkg else cls_simple
    recovered: List[str] = []
    remaining: List[str] = []
    details: List[Dict[str, Any]] = []
    for item in native_methods:
        name = str(item.get('method') or '')
        if not name:
            continue
        still_native = True if not has_source else _method_still_native(source_text, name, item.get('descriptor'))
        if still_native:
            remaining.append(name)
        else:
            recovered.append(name)
        details.append({'method': name, 'descriptor': item.get('descriptor'), 'fn_symbol': item.get('fn_symbol'), 'still_native': still_native, 'recovered': not still_native})
    total = len(native_methods)
    rec_count = len(recovered)
    rem_count = len(remaining)
    rate = round(rec_count / total, 3) if total else 0.0
    return {'class': class_internal, 'class_fqcn': fqcn, 'class_simple': cls_simple, 'source_path': str(source_path.resolve()) if has_source else None, 'source_missing': not has_source, 'native_total': total, 'native_recovered': rec_count, 'native_remaining': rem_count, 'methods_total': total, 'methods_recovered': rec_count, 'methods_stub': rem_count, 'recovery_rate': rate, 'recovered_methods': recovered, 'remaining_methods': remaining, 'methods': details}

def build_recovery_summary(*, job: Dict[str, Any]) -> Dict[str, Any]:
    sources_root = _sources_root(job)
    if sources_root is None:
        return {'status': 'SKIPPED_NO_SOURCES_DIR'}
    indexed = _native_index_methods(job)
    if not indexed:
        return {'status': 'SKIPPED_NO_NATIVE_INDEX'}
    by_class: Dict[str, List[Dict[str, Any]]] = {}
    for item in indexed:
        cls = str(item.get('class') or '')
        by_class.setdefault(cls, []).append(item)
    per_class: List[Dict[str, Any]] = []
    native_total = 0
    native_recovered = 0
    native_remaining = 0
    app_total = 0
    app_recovered = 0
    app_remaining = 0
    for class_internal in sorted(by_class):
        scan = _scan_class_native_recovery(class_internal=class_internal, native_methods=by_class[class_internal], sources_root=sources_root)
        scan['is_application_class'] = _is_application_class(class_internal)
        per_class.append(scan)
        total = int(scan.get('native_total') or 0)
        rec = int(scan.get('native_recovered') or 0)
        rem = int(scan.get('native_remaining') or 0)
        native_total += total
        native_recovered += rec
        native_remaining += rem
        if scan['is_application_class']:
            app_total += total
            app_recovered += rec
            app_remaining += rem
    headline_total = app_total if app_total else native_total
    headline_recovered = app_recovered if app_total else native_recovered
    headline_remaining = app_remaining if app_total else native_remaining
    overall_rate = round(headline_recovered / headline_total, 3) if headline_total else 0.0
    all_rate = round(native_recovered / native_total, 3) if native_total else 0.0
    analysis = job.get('analysis') if isinstance(job.get('analysis'), dict) else {}
    java_like = analysis.get('java_like') if isinstance(analysis, dict) else {}
    jni_register = analysis.get('jni_register') if isinstance(analysis, dict) else {}
    jni_calls = analysis.get('jni_calls') if isinstance(analysis, dict) else {}
    deobfuscation = analysis.get('deobfuscation') if isinstance(analysis, dict) else {}
    return {'status': 'OK', 'sources_dir': str(sources_root.resolve()), 'classes_total': len(per_class), 'application_classes_total': sum((1 for c in per_class if c.get('is_application_class'))), 'native_methods_total': headline_total, 'native_methods_recovered': headline_recovered, 'native_methods_remaining': headline_remaining, 'methods_total': headline_total, 'methods_recovered': headline_recovered, 'methods_stub': headline_remaining, 'methods_with_body': headline_recovered, 'overall_recovery_rate': overall_rate, 'recovery_rate': overall_rate, 'all_native_methods_total': native_total, 'all_native_methods_recovered': native_recovered, 'all_native_methods_remaining': native_remaining, 'all_recovery_rate': all_rate, 'confidence': _recovery_confidence(overall_rate, job), 'sources': {'jni_register_methods': jni_register.get('methods_total') if isinstance(jni_register, dict) else 0, 'jni_calls_total': jni_calls.get('calls_total') if isinstance(jni_calls, dict) else 0, 'jni_export_methods': java_like.get('jni_export_methods') if isinstance(java_like, dict) else 0, 'jni_sources_written': java_like.get('jni_sources_written') if isinstance(java_like, dict) else 0, 'had_pseudo_c': java_like.get('had_pseudo_c') if isinstance(java_like, dict) else False, 'had_functions_json': java_like.get('had_functions_json') if isinstance(java_like, dict) else False}, 'deobfuscation_level': deobfuscation.get('risk_level') if isinstance(deobfuscation, dict) else None, 'classes': per_class, 'files': per_class}

def _recovery_confidence(rate: float, job: Dict[str, Any]) -> str:
    ghidra = job.get('ghidra') if isinstance(job.get('ghidra'), dict) else {}
    run = ghidra.get('run') if isinstance(ghidra.get('run'), dict) else {}
    ghidra_ok = run.get('status') == 'OK'
    if rate >= 0.7 and ghidra_ok:
        return 'HIGH'
    if rate >= 0.4 and ghidra_ok:
        return 'MEDIUM'
    if rate >= 0.15 or ghidra_ok:
        return 'LOW'
    return 'MINIMAL'
