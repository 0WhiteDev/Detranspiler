import json
from pathlib import Path
from typing import Any, Dict, List, Optional

def summarize_job_dict(job: Dict[str, Any]) -> str:
    lines: List[str] = []
    job_id = job.get('job_id', '?')
    lines.append(f'Detranspiler job: {job_id}')
    inp = job.get('input') if isinstance(job.get('input'), dict) else {}
    lines.append(f"  Input: {inp.get('name')} ({inp.get('format')})")
    if inp.get('sha256'):
        lines.append(f"  SHA256: {inp.get('sha256')}")
    analysis = job.get('analysis') if isinstance(job.get('analysis'), dict) else {}
    recovery = analysis.get('recovery') if isinstance(analysis.get('recovery'), dict) else {}
    if recovery:
        rate = recovery.get('overall_recovery_rate') or recovery.get('recovery_rate')
        if rate is not None:
            rec = recovery.get('native_methods_recovered', recovery.get('methods_recovered'))
            total = recovery.get('native_methods_total', recovery.get('methods_total'))
            lines.append(f'  Recovery rate: {int(float(rate) * 100)}% ({rec}/{total} native methods)')
    jni_reg = analysis.get('jni_register') if isinstance(analysis.get('jni_register'), dict) else {}
    if jni_reg.get('methods_total'):
        lines.append(f"  JNI methods mapped: {jni_reg.get('methods_total')}")
    jar_repair = analysis.get('jar_repair') if isinstance(analysis.get('jar_repair'), dict) else {}
    if jar_repair.get('methods_repaired'):
        lines.append(f"  JAR repair: {jar_repair.get('methods_repaired')} stub(s) patched")
    final_sources = analysis.get('final_sources') if isinstance(analysis.get('final_sources'), dict) else {}
    if final_sources.get('files_total'):
        lines.append(f"  Java sources: {final_sources.get('files_total')} file(s)")
    deob = analysis.get('deobfuscation') if isinstance(analysis.get('deobfuscation'), dict) else {}
    if deob.get('risk_level'):
        lines.append(f"  Obfuscation risk: {deob.get('risk_level')} (score {deob.get('risk_score', '?')})")
    flat = analysis.get('flattening') if isinstance(analysis.get('flattening'), dict) else {}
    if flat.get('flatten_level') and flat.get('flatten_level') != 'NONE':
        lines.append(f"  CFG flattening: {flat.get('flatten_level')} ({flat.get('flattened_functions_total', 0)} functions)")
    strat = analysis.get('recovery_strategy') if isinstance(analysis.get('recovery_strategy'), dict) else {}
    if strat.get('fallback_order'):
        lines.append(f"  Recovery strategy: {' → '.join(strat.get('fallback_order') or [])}")
    java_like = analysis.get('java_like') if isinstance(analysis.get('java_like'), dict) else {}
    mr = java_like.get('method_recovery') if isinstance(java_like.get('method_recovery'), list) else None
    if not mr:
        mr_doc = analysis.get('method_recovery') if isinstance(analysis.get('method_recovery'), dict) else {}
        mr = mr_doc.get('methods') if isinstance(mr_doc.get('methods'), list) else None
    if mr:
        with_jni = sum((1 for m in mr if isinstance(m, dict) and any((s == 'jni' for s in m.get('sources') or []))))
        with_jar = sum((1 for m in mr if isinstance(m, dict) and any((s == 'jar' for s in m.get('sources') or []))))
        lines.append(f'  Method recovery map: {len(mr)} methods ({with_jni} JNI, {with_jar} CFR-guided)')
    validation = analysis.get('java_validation') if isinstance(analysis.get('java_validation'), dict) else {}
    if validation:
        lines.append(f"  Java AST: {validation.get('files_ast_valid', 0)}/{validation.get('files_total', 0)} valid, {validation.get('repairs_total', 0)} safe repair(s)")
        javac = validation.get('javac') if isinstance(validation.get('javac'), dict) else {}
        if javac.get('compilation_rate') is not None:
            lines.append(f"  javac: {int(float(javac.get('compilation_rate')) * 100)}% files compilable")
        elif javac.get('status'):
            lines.append(f"  javac: {javac.get('status')}")
    artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
    if artifacts.get('report_html'):
        lines.append(f"  Report: {artifacts.get('report_html')}")
    if artifacts.get('recovered_project_dir'):
        lines.append(f"  Project: {artifacts.get('recovered_project_dir')}")
    return '\n'.join(lines)

def summarize_job_file(job_path: Path) -> str:
    job_path = job_path.expanduser().resolve()
    if not job_path.is_file():
        return f'job.json not found: {job_path}'
    try:
        job = json.loads(job_path.read_text(encoding='utf-8', errors='replace'))
    except Exception as e:
        return f'Failed to read job.json: {e!r}'
    if not isinstance(job, dict):
        return 'Invalid job.json'
    return summarize_job_dict(job)
