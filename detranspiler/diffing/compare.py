from __future__ import annotations

import difflib
from collections import Counter
from typing import Any, Dict, Iterable, List, Set


def _availability(old: Dict[str, Any], new: Dict[str, Any], key: str) -> Dict[str, Any]:
    old_available = bool(old.get('availability', {}).get(key))
    new_available = bool(new.get('availability', {}).get(key))
    return {'old': old_available, 'new': new_available, 'comparable': old_available and new_available}


def _mapping_diff(old: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]], fields: Iterable[str]) -> Dict[str, Any]:
    old_keys = set(old)
    new_keys = set(new)
    changed = []
    for key in sorted(old_keys & new_keys):
        changes = {}
        for field in fields:
            old_value = old[key].get(field)
            new_value = new[key].get(field)
            if field == 'sources':
                old_value = sorted({str(value) for value in old_value or []})
                new_value = sorted({str(value) for value in new_value or []})
            if old_value != new_value:
                changes[field] = {'old': old_value, 'new': new_value}
        if changes:
            changed.append({'key': key, 'changes': changes})
    return {'added': [new[key] for key in sorted(new_keys - old_keys)], 'removed': [old[key] for key in sorted(old_keys - new_keys)], 'changed': changed}


def _string_diff(old_values: Iterable[str], new_values: Iterable[str]) -> Dict[str, Any]:
    old_counts = Counter(value for value in old_values if value)
    new_counts = Counter(value for value in new_values if value)
    old_set = set(old_counts)
    new_set = set(new_counts)
    count_changed = [{'value': value, 'old_count': old_counts[value], 'new_count': new_counts[value]} for value in sorted(old_set & new_set) if old_counts[value] != new_counts[value]]
    return {'added': sorted(new_set - old_set), 'removed': sorted(old_set - new_set), 'count_changed': count_changed, 'unchanged': len(old_set & new_set)}


def _ghidra_string_diff(old_items: List[Dict[str, Any]], new_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    old_by_address = {item['address']: item['value'] for item in old_items if item.get('address')}
    new_by_address = {item['address']: item['value'] for item in new_items if item.get('address')}
    values = _string_diff(old_by_address.values(), new_by_address.values())
    modified = []
    for address in sorted(set(old_by_address) & set(new_by_address)):
        if old_by_address[address] != new_by_address[address]:
            modified.append({'address': address, 'old': old_by_address[address], 'new': new_by_address[address]})
    old_addresses: Dict[str, Set[str]] = {}
    new_addresses: Dict[str, Set[str]] = {}
    for address, value in old_by_address.items():
        old_addresses.setdefault(value, set()).add(address)
    for address, value in new_by_address.items():
        new_addresses.setdefault(value, set()).add(address)
    relocated = []
    for value in sorted(set(old_addresses) & set(new_addresses)):
        if old_addresses[value] != new_addresses[value]:
            relocated.append({'value': value, 'old_addresses': sorted(old_addresses[value]), 'new_addresses': sorted(new_addresses[value])})
    return {**values, 'modified_at_address': modified, 'relocated': relocated}


def _pseudocode_diff(old: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    old_keys = set(old)
    new_keys = set(new)
    changed = []
    for key in sorted(old_keys & new_keys):
        old_text = old[key].get('text') or ''
        new_text = new[key].get('text') or ''
        if old_text == new_text:
            continue
        old_lines = old_text.splitlines()
        new_lines = new_text.splitlines()
        all_lines = list(difflib.unified_diff(old_lines, new_lines, fromfile=f'old/{old[key].get("path")}', tofile=f'new/{new[key].get("path")}', lineterm=''))
        limit = 240
        changed.append({'key': key, 'old': {name: value for name, value in old[key].items() if name != 'text'}, 'new': {name: value for name, value in new[key].items() if name != 'text'}, 'similarity': round(difflib.SequenceMatcher(None, old_text, new_text).ratio(), 4), 'diff': all_lines[:limit], 'diff_lines_total': len(all_lines), 'diff_truncated': len(all_lines) > limit})
    return {'added': [new[key] for key in sorted(new_keys - old_keys)], 'removed': [old[key] for key in sorted(old_keys - new_keys)], 'changed': changed, 'unchanged': len(old_keys & new_keys) - len(changed)}


def compare_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    availability = {key: _availability(old, new, key) for key in sorted(set(old.get('availability', {})) | set(new.get('availability', {})))}
    methods = _mapping_diff(old['methods'], new['methods'], ('function_fingerprint', 'fn_symbol', 'confidence', 'sources')) if availability['jni_methods']['comparable'] else {'added': [], 'removed': [], 'changed': []}
    for item in methods['changed']:
        changes = item['changes']
        fingerprint = changes.get('function_fingerprint')
        if fingerprint and fingerprint.get('old') and fingerprint.get('new'):
            item['classification'] = 'implementation_changed'
        elif fingerprint and fingerprint.get('new'):
            item['classification'] = 'implementation_recovered'
        elif fingerprint and fingerprint.get('old'):
            item['classification'] = 'implementation_lost'
        elif changes.keys() == {'fn_symbol'}:
            item['classification'] = 'relocated'
        else:
            item['classification'] = 'mapping_metadata_changed'
    registrations = _mapping_diff(old['registrations'], new['registrations'], ('function_fingerprint', 'registrar', 'fn_symbol', 'mapping_source')) if availability['registrations']['comparable'] else {'added': [], 'removed': [], 'changed': []}
    confidence = _mapping_diff(old['confidence'], new['confidence'], ('score', 'level', 'sources')) if availability['confidence']['comparable'] else {'added': [], 'removed': [], 'changed': []}
    old_edges = {tuple(edge) for edge in old.get('edges') or []}
    new_edges = {tuple(edge) for edge in new.get('edges') or []}
    call_graph = {'added': [list(edge) for edge in sorted(new_edges - old_edges)], 'removed': [list(edge) for edge in sorted(old_edges - new_edges)], 'unchanged': len(old_edges & new_edges), 'old_omitted_unstable': old.get('omitted_edges', 0), 'new_omitted_unstable': new.get('omitted_edges', 0)} if availability['call_graph']['comparable'] else {'added': [], 'removed': [], 'unchanged': 0, 'old_omitted_unstable': old.get('omitted_edges', 0), 'new_omitted_unstable': new.get('omitted_edges', 0)}
    strings = {
        'ghidra': _ghidra_string_diff(old['strings']['ghidra'], new['strings']['ghidra']) if availability['ghidra_strings']['comparable'] else {'added': [], 'removed': [], 'unchanged': 0, 'modified_at_address': [], 'relocated': []},
        'raw': _string_diff(old['strings']['raw'], new['strings']['raw']) if availability['raw_strings']['comparable'] else {'added': [], 'removed': [], 'unchanged': 0},
        'decrypted': _string_diff(old['strings']['decrypted'], new['strings']['decrypted']) if availability['decrypted_strings']['comparable'] else {'added': [], 'removed': [], 'unchanged': 0},
    }
    pseudocode = _pseudocode_diff(old['pseudocode'], new['pseudocode']) if availability['pseudocode']['comparable'] else {'added': [], 'removed': [], 'changed': [], 'unchanged': 0}
    summary = {
        'jni_methods_added': len(methods['added']),
        'jni_methods_removed': len(methods['removed']),
        'jni_methods_changed': len(methods['changed']),
        'registrations_changed': len(registrations['added']) + len(registrations['removed']) + len(registrations['changed']),
        'strings_added': sum(len(strings[name]['added']) for name in strings),
        'strings_removed': sum(len(strings[name]['removed']) for name in strings),
        'string_counts_changed': sum(len(strings[name].get('count_changed') or []) for name in strings),
        'call_edges_added': len(call_graph['added']),
        'call_edges_removed': len(call_graph['removed']),
        'confidence_added': len(confidence['added']),
        'confidence_removed': len(confidence['removed']),
        'confidence_changed': len(confidence['changed']),
        'pseudocode_added': len(pseudocode['added']),
        'pseudocode_removed': len(pseudocode['removed']),
        'pseudocode_changed': len(pseudocode['changed']),
    }
    return {'schema_version': 1, 'old': {'root': old['root'], 'input': old['input']}, 'new': {'root': new['root'], 'input': new['input']}, 'availability': availability, 'summary': summary, 'jni_methods': methods, 'registrations': registrations, 'strings': strings, 'call_graph': call_graph, 'confidence': confidence, 'pseudocode': pseudocode}
