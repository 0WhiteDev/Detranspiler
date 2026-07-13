from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

from detranspiler.reporting.html_theme import escape_html, panel, render_page, side_nav, stat_card


def _count_line(label: str, section: Dict[str, Any]) -> str:
    return f'{label}: +{len(section.get("added") or [])} -{len(section.get("removed") or [])} ~{len(section.get("changed") or [])}'


def _text_report(result: Dict[str, Any]) -> str:
    lines = [
        'Detranspiler differential analysis',
        f'Old: {result["old"]["root"]}',
        f'New: {result["new"]["root"]}',
        '',
        _count_line('JNI methods', result['jni_methods']),
        _count_line('Registrations', result['registrations']),
        f'Ghidra strings: +{len(result["strings"]["ghidra"]["added"])} -{len(result["strings"]["ghidra"]["removed"])} modified={len(result["strings"]["ghidra"]["modified_at_address"])} relocated={len(result["strings"]["ghidra"]["relocated"])} count changes={len(result["strings"]["ghidra"].get("count_changed") or [])}',
        f'Raw strings: +{len(result["strings"]["raw"]["added"])} -{len(result["strings"]["raw"]["removed"])} count changes={len(result["strings"]["raw"].get("count_changed") or [])}',
        f'Decrypted strings: +{len(result["strings"]["decrypted"]["added"])} -{len(result["strings"]["decrypted"]["removed"])} count changes={len(result["strings"]["decrypted"].get("count_changed") or [])}',
        f'Call graph edges: +{len(result["call_graph"]["added"])} -{len(result["call_graph"]["removed"])}',
        f'Unstable call edges omitted: old={result["call_graph"]["old_omitted_unstable"]} new={result["call_graph"]["new_omitted_unstable"]}',
        _count_line('Confidence', result['confidence']),
        _count_line('Recovered pseudocode', result['pseudocode']),
        '',
        'Evidence availability:',
    ]
    for name, state in result['availability'].items():
        status = 'comparable' if state['comparable'] else f'unavailable (old={state["old"]}, new={state["new"]})'
        lines.append(f'  {name}: {status}')
    for section_name in ('jni_methods', 'registrations', 'confidence'):
        section = result[section_name]
        if section.get('added') or section.get('removed') or section.get('changed'):
            lines.extend(['', section_name.replace('_', ' ').title() + ':'])
            lines.extend(f'  + {item.get("key")}' for item in section.get('added') or [])
            lines.extend(f'  - {item.get("key")}' for item in section.get('removed') or [])
            lines.extend(f'  ~ {item.get("key")}' + (f' [{item.get("classification")}]' if item.get('classification') else '') for item in section.get('changed') or [])
    return '\n'.join(lines) + '\n'


def _table(headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    head = ''.join(f'<th>{escape_html(value)}</th>' for value in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{escape_html(value)}</td>' for value in row) + '</tr>' for row in rows)
    return f'<table class="data-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>' if body else '<div class="empty">No differences</div>'


def _mapping_panel(title: str, section: Dict[str, Any]) -> str:
    rows: List[List[str]] = []
    rows.extend(['Added', item.get('key', ''), ''] for item in section.get('added') or [])
    rows.extend(['Removed', item.get('key', ''), ''] for item in section.get('removed') or [])
    for item in section.get('changed') or []:
        details = ', '.join(f'{key}: {value.get("old")} -> {value.get("new")}' for key, value in item.get('changes', {}).items())
        details = f'{item.get("classification")}: {details}' if item.get('classification') else details
        rows.append(['Changed', item.get('key', ''), details])
    return panel(title, _table(('Change', 'Identity', 'Details'), rows))


def _string_panel(result: Dict[str, Any]) -> str:
    rows = []
    for source, section in result['strings'].items():
        rows.extend([source, 'Added', value] for value in section.get('added') or [])
        rows.extend([source, 'Removed', value] for value in section.get('removed') or [])
        rows.extend([source, 'Count changed', f'{item["value"]}: {item["old_count"]} -> {item["new_count"]}'] for item in section.get('count_changed') or [])
        rows.extend([source, 'Modified', f'{item["address"]}: {item["old"]} -> {item["new"]}'] for item in section.get('modified_at_address') or [])
        rows.extend([source, 'Relocated', f'{item["value"]}: {item["old_addresses"]} -> {item["new_addresses"]}'] for item in section.get('relocated') or [])
    return panel('Strings', _table(('Source', 'Change', 'Value'), rows))


def _pseudocode_panel(section: Dict[str, Any]) -> str:
    cards = []
    for change, values in (('Added', section.get('added') or []), ('Removed', section.get('removed') or [])):
        for item in values:
            cards.append(f'<details class="method-card"><summary><span>{change}</span><code>{escape_html(item.get("key") or item.get("path"))}</code></summary><div class="body"><pre class="pre-block">{escape_html(item.get("text") or "")}</pre></div></details>')
    for item in section.get('changed') or []:
        diff_lines = []
        for line in item.get('diff') or []:
            kind = 'hdr' if line.startswith(('@@', '---', '+++')) else 'add' if line.startswith('+') else 'rem' if line.startswith('-') else 'ctx'
            diff_lines.append(f'<div class="line {kind}">{escape_html(line)}</div>')
        truncated = f'<div class="muted">Showing 240 of {item["diff_lines_total"]} diff lines.</div>' if item.get('diff_truncated') else ''
        cards.append(f'<details class="method-card"><summary><code>{escape_html(item["key"])}</code><span class="muted">similarity {item["similarity"]:.1%}</span></summary><div class="body"><div class="diff-wrap">{"".join(diff_lines)}</div>{truncated}</div></details>')
    added_removed = _table(('Change', 'Identity'), ([kind, item.get('path', '') + ':' + str(item.get('start_line', ''))] for kind, values in (('Added', section.get('added') or []), ('Removed', section.get('removed') or [])) for item in values))
    return panel('Recovered pseudocode', added_removed + ''.join(cards) if cards else added_removed)


def _html_report(result: Dict[str, Any]) -> str:
    summary = result['summary']
    stats = ''.join([
        stat_card(str(summary['jni_methods_added'] + summary['jni_methods_removed'] + summary['jni_methods_changed']), 'JNI method changes'),
        stat_card(str(summary['registrations_changed']), 'Registration changes'),
        stat_card(str(summary['strings_added'] + summary['strings_removed'] + summary['string_counts_changed']), 'String changes'),
        stat_card(str(summary['call_edges_added'] + summary['call_edges_removed']), 'Call edge changes'),
        stat_card(str(summary['pseudocode_added'] + summary['pseudocode_removed'] + summary['pseudocode_changed']), 'Pseudocode changes'),
    ])
    availability_rows = ([name, 'yes' if state['old'] else 'no', 'yes' if state['new'] else 'no', 'yes' if state['comparable'] else 'no'] for name, state in result['availability'].items())
    graph_rows = [['Added', f'{edge[0]} -> {edge[1]}'] for edge in result['call_graph']['added']] + [['Removed', f'{edge[0]} -> {edge[1]}'] for edge in result['call_graph']['removed']]
    main = f'<div class="stats">{stats}</div>'
    main += f'<section id="jni">{_mapping_panel("JNI methods", result["jni_methods"])}</section>'
    main += f'<section id="registrations">{_mapping_panel("Registrations", result["registrations"])}</section>'
    main += f'<section id="strings">{_string_panel(result)}</section>'
    graph_note = f'<div class="muted">Ambiguous or unstable edges omitted: old {result["call_graph"]["old_omitted_unstable"]}, new {result["call_graph"]["new_omitted_unstable"]}</div>'
    main += f'<section id="graph">{panel("Call graph", graph_note + _table(("Change", "Edge"), graph_rows))}</section>'
    main += f'<section id="confidence">{_mapping_panel("Confidence", result["confidence"])}</section>'
    main += f'<section id="pseudocode">{_pseudocode_panel(result["pseudocode"])}</section>'
    main += f'<section id="availability">{panel("Evidence availability", _table(("Artifact", "Old", "New", "Comparable"), availability_rows))}</section>'
    nav = side_nav((('JNI methods', '#jni'), ('Registrations', '#registrations'), ('Strings', '#strings'), ('Call graph', '#graph'), ('Confidence', '#confidence'), ('Pseudocode', '#pseudocode'), ('Availability', '#availability')))
    subtitle = f'<code>{escape_html(result["old"]["root"])}</code> compared with <code>{escape_html(result["new"]["root"])}</code>'
    return render_page(title='Differential analysis', subtitle=subtitle, current_nav='diff', main_html=main, sidebar_html=nav, report_href='diff.html', map_href=None)


def write_reports(result: Dict[str, Any], out_dir: Path) -> Dict[str, str]:
    text_path = out_dir / 'diff.txt'
    html_path = out_dir / 'diff.html'
    json_path = out_dir / 'diff.json'
    text_path.write_text(_text_report(result), encoding='utf-8')
    html_path.write_text(_html_report(result), encoding='utf-8')
    return {'json': str(json_path), 'text': str(text_path), 'html': str(html_path)}
