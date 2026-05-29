import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from detranspiler.reporting.html_theme import artifact_links_from_job, badge, confidence_badge, escape_html, file_link, json_pre, kv_table, panel, render_page, risk_badge, side_nav, stat_card

def _get(d: Dict[str, Any], path: str, default: Any=None) -> Any:
    cur: Any = d
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return default
        if part not in cur:
            return default
        cur = cur[part]
    return cur

def _render_method_recovery(methods: Any) -> str:
    if not isinstance(methods, list) or not methods:
        return '<p class="empty">No recovered methods recorded.</p>'
    rows: List[str] = []
    for m in methods[:200]:
        if not isinstance(m, dict):
            continue
        cls = m.get('class', '')
        method = m.get('method', '')
        sources = '+'.join((str(s) for s in m.get('sources') or [] if s))
        score = m.get('score', '')
        row_key = f'{cls} {method} {sources}'.lower()
        rows.append(f'<tr data-search="{escape_html(row_key)}"><td><code>{escape_html(str(cls))}#{escape_html(str(method))}</code></td><td>{escape_html(sources)}</td><td>{escape_html(str(score))}</td></tr>')
    if not rows:
        return '<p class="empty">No recovered methods recorded.</p>'
    return f'<div class="toolbar"><input type="search" id="methodSearch" placeholder="Filter methods, classes, sources…"><span class="muted">{len(rows)} shown (max 200)</span></div><table class="data-table" id="methodRecoveryTable"><tr><th>Method</th><th>Sources</th><th>Score</th></tr>' + ''.join(rows) + '</table>'

def _render_pattern_categories(categories: Any) -> str:
    if not isinstance(categories, dict):
        return '<p class="empty">n/a</p>'
    rows: List[str] = []
    for name, data in sorted(categories.items()):
        if not isinstance(data, dict):
            continue
        count = int(data.get('count') or 0)
        kind = 'ok' if count else 'neutral'
        rows.append(f'<tr><td><strong>{escape_html(name)}</strong></td><td>{badge(str(count), kind)}</td></tr>')
    if not rows:
        return '<p class="empty">No patterns detected.</p>'
    return "<table class='data-table'><tr><th>Category</th><th>Hits</th></tr>" + ''.join(rows) + '</table>'

def _render_jni_calls_summary(functions: Any, counts_by_name: Any) -> str:
    parts: List[str] = []
    if isinstance(counts_by_name, dict) and counts_by_name:
        top = sorted(counts_by_name.items(), key=lambda x: -x[1])[:16]
        parts.append("<h3>Top JNI API calls</h3><ul class='list-compact'>")
        for name, cnt in top:
            parts.append(f'<li><code>{escape_html(name)}</code> {cnt}</li>')
        parts.append('</ul>')
    if isinstance(functions, list) and functions:
        parts.append('<h3>Functions with JNI activity</h3>')
        parts.append("<table class='data-table'><tr><th>Native fn</th><th>Calls</th><th>Classes</th><th>Methods</th></tr>")
        for fn in functions[:50]:
            if not isinstance(fn, dict):
                continue
            classes = fn.get('classes') or []
            methods = fn.get('methods') or []
            cls_preview = ', '.join((str(c) for c in classes[:3]))
            meth_preview = ', '.join((f"{m.get('class', '')}.{m.get('method', '')}" for m in methods[:2] if isinstance(m, dict)))
            parts.append(f"<tr><td><code>{escape_html(str(fn.get('function') or ''))}</code></td><td>{fn.get('calls_total', 0)}</td><td><small>{escape_html(cls_preview)}</small></td><td><small>{escape_html(meth_preview)}</small></td></tr>")
        parts.append('</table>')
    return '\n'.join(parts) if parts else '<p class="empty">No JNI call data.</p>'

def _render_recovery_files(files: Any) -> str:
    if not isinstance(files, list) or not files:
        return '<p class="empty">No native method recovery data.</p>'
    rows: List[str] = []
    app_only = [f for f in files if isinstance(f, dict) and f.get('is_application_class', True)]
    for f in (app_only if app_only else files)[:60]:
        if not isinstance(f, dict):
            continue
        rate = float(f.get('recovery_rate') or 0)
        kind = 'ok' if rate >= 0.5 else 'warn' if rate >= 0.2 else 'bad'
        label = f.get('class_fqcn') or f.get('class_simple') or Path(str(f.get('path', ''))).name
        native_total = f.get('native_total', f.get('methods_total', 0))
        recovered = f.get('native_recovered', f.get('methods_recovered', 0))
        remaining = f.get('native_remaining', f.get('methods_stub', 0))
        rows.append(f"<tr><td><code>{escape_html(str(label))}</code></td><td>{native_total}</td><td>{recovered}</td><td>{remaining}</td><td>{badge(f'{int(rate * 100)}%', kind)}</td></tr>")
    return "<table class='data-table'><tr><th>Class</th><th>Native</th><th>Recovered</th><th>Still native</th><th>Rate</th></tr>" + ''.join(rows) + '</table>'

def _render_deobfuscation(deob: Any) -> str:
    if not isinstance(deob, dict):
        return '<p class="empty">n/a</p>'
    indicators = deob.get('indicator_list') or deob.get('indicators')
    recs = deob.get('recommendations')
    parts = [f"<p>Score: <strong>{escape_html(str(deob.get('risk_score', '?')))}</strong> / 100 {risk_badge(str(deob.get('risk_level')))}</p>"]
    if isinstance(indicators, list) and indicators:
        parts.append("<ul class='list-compact'>")
        for ind in indicators[:16]:
            if isinstance(ind, dict):
                parts.append(f"<li><strong>{escape_html(str(ind.get('name', '')))}</strong>: {escape_html(str(ind.get('detail', '')))}</li>")
            else:
                parts.append(f'<li>{escape_html(str(ind))}</li>')
        parts.append('</ul>')
    if isinstance(recs, list) and recs:
        parts.append("<h3>Recommendations</h3><ul class='list-compact'>")
        for r in recs[:10]:
            parts.append(f'<li>{escape_html(str(r))}</li>')
        parts.append('</ul>')
    return '\n'.join(parts)

def _render_anti_analysis(data: Any) -> str:
    if not isinstance(data, dict):
        return '<p class="empty">n/a</p>'
    parts = [f"<p>Risk: {risk_badge(str(data.get('risk_level')))} suspicious functions: <strong>{data.get('suspicious_functions_total', 0)}</strong></p>"]
    low = data.get('low_trust_symbols') or []
    if low:
        parts.append("<h3>Low-trust symbols</h3><ul class='list-compact'>")
        for sym in low[:30]:
            parts.append(f'<li><code>{escape_html(str(sym))}</code></li>')
        parts.append('</ul>')
    recs = data.get('recommendations')
    if isinstance(recs, list) and recs:
        parts.append("<ul class='list-compact'>")
        for r in recs[:8]:
            parts.append(f'<li>{escape_html(str(r))}</li>')
        parts.append('</ul>')
    return '\n'.join(parts)

def _render_method_confidence(data: Any) -> str:
    if not isinstance(data, dict):
        return '<p class="empty">n/a</p>'
    parts = [f"<p>Total: <strong>{data.get('methods_total', 0)}</strong> HIGH: {data.get('high_confidence', 0)}, MEDIUM: {data.get('medium_confidence', 0)}</p>"]
    methods = data.get('methods') or []
    if methods:
        parts.append("<table class='data-table'><tr><th>Class</th><th>Method</th><th>Score</th><th>Level</th><th>Sources</th></tr>")
        for m in methods[:60]:
            if not isinstance(m, dict):
                continue
            src = ', '.join((str(s) for s in (m.get('sources') or [])[:4]))
            parts.append(f"<tr><td><code>{escape_html(str(m.get('class') or ''))}</code></td><td><code>{escape_html(str(m.get('method') or ''))}</code></td><td>{m.get('score', 0)}</td><td>{confidence_badge(str(m.get('level')))}</td><td><small>{escape_html(src)}</small></td></tr>")
        parts.append('</table>')
    return '\n'.join(parts)

def _render_jnic_patterns(data: Any) -> str:
    if not isinstance(data, dict):
        return '<p class="empty">n/a</p>'
    parts = [f"<p>Transpiler guess: <strong>{escape_html(str(data.get('transpiler_guess', 'unknown')))}</strong> confidence: {confidence_badge(str(data.get('confidence')))}</p>"]
    exports = data.get('java_exports_detected') or []
    if exports:
        parts.append("<h3>Java_* exports</h3><ul class='list-compact'>")
        for ex in exports[:20]:
            parts.append(f'<li><code>{escape_html(str(ex))}</code></li>')
        parts.append('</ul>')
    obf = data.get('obfuscation_hints') or []
    if obf:
        parts.append(f'<p>Obfuscation hints: <strong>{len(obf)}</strong> pattern(s) matched</p>')
    return '\n'.join(parts)

def _render_callgraph_list(callgraph: Any) -> str:
    if not isinstance(callgraph, dict):
        return '<p class="empty">No callgraph data.</p>'
    items = callgraph.get('jni_onload_reachable') or []
    parts = [f"<p>JNI_OnLoad reachable: <strong>{len(items)}</strong> functions · edges: <strong>{callgraph.get('callgraph_edges_total', 0)}</strong></p>"]
    if items:
        parts.append("<ul class='list-compact'>")
        for c in items[:25]:
            parts.append(f'<li><code>{escape_html(str(c))}</code></li>')
        parts.append('</ul>')
    exports = callgraph.get('java_exports') or []
    if exports:
        parts.append("<h3>Java exports</h3><ul class='list-compact'>")
        for ex in exports[:15]:
            if isinstance(ex, dict):
                parts.append(f"<li><code>{escape_html(str(ex.get('name', '')))}</code></li>")
        parts.append('</ul>')
    return '\n'.join(parts)

def write_html_report(*, job: Dict[str, Any], out_path: Path) -> Dict[str, Any]:
    out_path = out_path.expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from detranspiler.recovery.metrics import build_recovery_summary
        recovery = build_recovery_summary(job=job)
        if isinstance(recovery, dict) and recovery.get('status') == 'OK':
            analysis = job.get('analysis')
            if isinstance(analysis, dict):
                analysis = dict(analysis)
                analysis['recovery'] = recovery
                job = dict(job)
                job['analysis'] = analysis
    except Exception:
        pass
    analysis_dir = out_path.parent
    title = f"Analysis Report {job.get('job_id', 'Detranspiler')}".strip()
    subtitle = escape_html(str(_get(job, 'input.path', '')))
    artifacts = job.get('artifacts', {}) if isinstance(job.get('artifacts'), dict) else {}
    report_href, map_href = artifact_links_from_job(job, analysis_dir)
    recovery = _get(job, 'analysis.recovery', {})
    patterns = _get(job, 'analysis.patterns', {})
    jni_register = _get(job, 'analysis.jni_register', {})
    jni_calls = _get(job, 'analysis.jni_calls', {})
    deobfuscation = _get(job, 'analysis.deobfuscation', {})
    java_like = _get(job, 'analysis.java_like', {})
    jar_decompile = _get(job, 'analysis.jar_decompile', {})
    string_decrypt = _get(job, 'analysis.string_decrypt', {})
    callgraph = _get(job, 'analysis.callgraph', {})
    jar_repair = _get(job, 'analysis.jar_repair', {})
    flattening = _get(job, 'analysis.flattening', {})
    native_index = _get(job, 'analysis.native_index', {})
    from detranspiler.native.index import resolve_native_index
    native_index = resolve_native_index(job=job, analysis_dir=analysis_dir, native_index=native_index if isinstance(native_index, dict) else None)
    method_confidence = _get(job, 'analysis.method_confidence', {})
    anti_analysis = _get(job, 'analysis.anti_analysis', {})
    export_project = _get(job, 'analysis.export_project', {})
    jnic_patterns = _get(job, 'analysis.jnic_patterns', {})
    final_sources = _get(job, 'analysis.final_sources', {})
    recovery_rate = int((recovery.get('overall_recovery_rate') or 0) * 100) if isinstance(recovery, dict) else 0
    jni_methods = jni_register.get('methods_total', 0) if isinstance(jni_register, dict) else 0
    decrypted_count = string_decrypt.get('strings_total', 0) if isinstance(string_decrypt, dict) else 0
    sources_total = final_sources.get('files_total', 0) if isinstance(final_sources, dict) else 0
    flat_level = flattening.get('flatten_level') if isinstance(flattening, dict) else 'NONE'
    native_methods = native_index.get('methods_total', 0) if isinstance(native_index, dict) else 0
    high_conf = method_confidence.get('high_confidence', 0) if isinstance(method_confidence, dict) else 0
    repaired = jar_repair.get('methods_repaired', 0) if isinstance(jar_repair, dict) else 0
    repaired_native = jar_repair.get('methods_repaired_from_native', 0) if isinstance(jar_repair, dict) else 0
    stats = '<div class="stats">' + stat_card(f'{recovery_rate}%', 'Recovery rate', extra=confidence_badge(recovery.get('confidence') if isinstance(recovery, dict) else None)) + stat_card(str(jni_methods), 'JNI methods') + stat_card(str(decrypted_count), 'Decrypted strings') + stat_card(str(native_methods), 'Native index') + stat_card(str(high_conf), 'High confidence') + stat_card(str(sources_total), 'Java sources') + '</div>'
    main = stats
    main += f"""<section class="section" id="overview">{panel('Run info', kv_table([('Created', escape_html(str(job.get('created_at', '')))), ('Input', f"<code>{escape_html(str(_get(job, 'input.path', '')))}</code>"), ('SHA256', f"<code>{escape_html(str(_get(job, 'input.sha256', '')))}</code>"), ('Mode', f"{escape_html(str(_get(job, 'mode.requested', '')))} → {escape_html(str(_get(job, 'mode.resolved', '')))}"), ('JNI detected', badge('YES', 'ok') if _get(job, 'jni.detected') else badge('NO', 'neutral')), ('Flattening', badge(str(flat_level), 'warn' if flat_level not in (None, 'NONE') else 'neutral')), ('Anti-analysis', risk_badge(str(anti_analysis.get('risk_level') if isinstance(anti_analysis, dict) else 'NONE')))]))}</section>"""
    main += f"""<section class="section" id="recovery">{panel('Recovery summary', kv_table([('Overall rate', f'{recovery_rate}%'), ('Native methods', recovery.get('native_methods_total') if isinstance(recovery, dict) else recovery.get('methods_total') if isinstance(recovery, dict) else None), ('Recovered', recovery.get('native_methods_recovered') if isinstance(recovery, dict) else recovery.get('methods_recovered') if isinstance(recovery, dict) else None), ('Still native', recovery.get('native_methods_remaining') if isinstance(recovery, dict) else recovery.get('methods_stub') if isinstance(recovery, dict) else None), ('Classes', recovery.get('classes_total') if isinstance(recovery, dict) else None), ('Stubs patched', repaired), ('Native repair', repaired_native)]) + _render_recovery_files(recovery.get('classes') or recovery.get('files') if isinstance(recovery, dict) else None))}</section>"""
    method_recovery_html = _render_method_recovery(_get(job, 'analysis.java_like.method_recovery') or _get(job, 'analysis.method_recovery.methods'))
    main += f"""<section class="section" id="methods">{panel('Method recovery map', method_recovery_html)}</section>"""
    main += f"""<section class="section" id="artifacts">{panel('Artifacts & outputs', kv_table([('Pseudo-C', file_link(artifacts.get('pseudo_c_file'), base_dir=analysis_dir)), ('Ghidra functions', file_link(artifacts.get('ghidra_functions_json'), base_dir=analysis_dir)), ('JNI register', file_link(artifacts.get('jni_register_json'), base_dir=analysis_dir)), ('JNI calls', file_link(artifacts.get('jni_calls_json'), base_dir=analysis_dir)), ('Java aggregate', file_link(artifacts.get('java_like_file'), base_dir=analysis_dir)), ('Method recovery JSON', file_link(artifacts.get('method_recovery_json'), base_dir=analysis_dir)), ('JNI sources', file_link(java_like.get('jni_sources_dir') if isinstance(java_like, dict) else None, base_dir=analysis_dir)), ('JNI exports', file_link(artifacts.get('jni_export_sources_dir'), base_dir=analysis_dir)), ('Java sources', file_link(artifacts.get('sources_dir') or (final_sources.get('output_dir') if isinstance(final_sources, dict) else None), base_dir=analysis_dir)), ('Recovered project', file_link(export_project.get('output_dir') if isinstance(export_project, dict) else None, base_dir=analysis_dir)), ('RE map', file_link(map_href or artifacts.get('re_map_html'), base_dir=analysis_dir, label='re_map.html'))]))}</section>"""
    main += f"""<section class="section" id="analysis">{panel('Pipeline analysis', kv_table([('Ghidra state', escape_html(str(_get(job, 'ghidra.state', '')))), ('Ghidra run', escape_html(str(_get(job, 'ghidra.run.status', '')))), ('RegisterNatives', jni_register.get('register_calls_total') if isinstance(jni_register, dict) else None), ('Static JNI tables', jni_register.get('static_method_tables_total') if isinstance(jni_register, dict) else None), ('JNI API calls', jni_calls.get('calls_total') if isinstance(jni_calls, dict) else None), ('JAR decompile', jar_decompile.get('status') if isinstance(jar_decompile, dict) else 'SKIPPED'), ('Java sources', sources_total if sources_total else None)]))}</section>"""
    strings_list = ''.join((f"<li><code>{escape_html(str(s.get('value', '')))}</code> <span class='muted'>({escape_html(str(s.get('method', '')))})</span></li>" for s in (string_decrypt.get('strings') or [])[:24] if isinstance(s, dict)))
    strings_body = f"""<p>Recovered strings: <strong>{decrypted_count}</strong> · XOR loops: <strong>{(string_decrypt.get('xor_loops_detected', 0) if isinstance(string_decrypt, dict) else 0)}</strong></p><ul class='list-compact'>{strings_list or '<li class="empty">none</li>'}</ul>"""
    main += f"""<section class="section" id="strings">{panel('String decryption', strings_body)}</section>"""
    main += f"""<section class="section" id="callgraph">{panel('Call graph', _render_callgraph_list(callgraph))}</section>"""
    main += f"""<section class="section" id="patterns">{panel('Pattern detection', _render_pattern_categories(patterns.get('categories') if isinstance(patterns, dict) else None))}</section>"""
    main += f"""<section class="section" id="jni">{panel('JNI call analysis', _render_jni_calls_summary(jni_calls.get('functions') if isinstance(jni_calls, dict) else None, jni_calls.get('counts_by_name') if isinstance(jni_calls, dict) else None))}</section>"""
    main += f"""<section class="section" id="deobfuscation">{panel('Deobfuscation', _render_deobfuscation(deobfuscation))}</section>"""
    main += f"""<section class="section" id="anti">{panel('Anti-analysis', _render_anti_analysis(anti_analysis))}</section>"""
    main += f"""<section class="section" id="confidence">{panel('Method confidence', _render_method_confidence(method_confidence))}</section>"""
    main += f"""<section class="section" id="jnic">{panel('JNIC / transpiler', _render_jnic_patterns(jnic_patterns))}</section>"""
    main += '<section class="section" id="job"><details class="collapsible panel"><summary>Full job.json</summary>' + json_pre(job) + '</details></section>'
    sidebar = side_nav([('Overview', '#overview'), ('Recovery', '#recovery'), ('Methods', '#methods'), ('Artifacts', '#artifacts'), ('Analysis', '#analysis'), ('Strings', '#strings'), ('Call graph', '#callgraph'), ('Patterns', '#patterns'), ('JNI', '#jni'), ('Deobfuscation', '#deobfuscation'), ('Anti-analysis', '#anti'), ('Confidence', '#confidence'), ('JNIC', '#jnic'), ('job.json', '#job')])
    script = "\n<script>\n(() => {\n  const input = document.getElementById('methodSearch');\n  const table = document.getElementById('methodRecoveryTable');\n  if (input && table) {\n    input.addEventListener('input', () => {\n      const q = input.value.trim().toLowerCase();\n      for (const row of table.querySelectorAll('tr[data-search]')) {\n        row.classList.toggle('hidden', q && !row.dataset.search.includes(q));\n      }\n    });\n  }\n})();\n</script>\n"
    page = render_page(title=title, subtitle=subtitle, current_nav='report', sidebar_html=sidebar, main_html=main, extra_script=script, report_href=report_href, map_href=map_href)
    out_path.write_text(page, encoding='utf-8')
    return {'status': 'OK', 'output_path': str(out_path)}
