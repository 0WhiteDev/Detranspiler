import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

def _split_function_blocks(pseudo_c: str) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    cur_name: Optional[str] = None
    cur_lines: List[str] = []
    marker = re.compile('^/\\* FUNCTION\\s+(?P<name>\\w+)\\s+.+?\\*/\\s*$')
    for line in pseudo_c.splitlines():
        m = marker.match(line.strip())
        if m:
            if cur_name is not None:
                blocks.append((cur_name, '\n'.join(cur_lines)))
            cur_name = m.group('name')
            cur_lines = [line]
        elif cur_name is not None:
            cur_lines.append(line)
    if cur_name is not None:
        blocks.append((cur_name, '\n'.join(cur_lines)))
    return blocks

def _find_dispatcher_loops(block: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    pat = re.compile('while\s*\(\s*true\s*\)\s*\{(?P<body>.*?)(?:switch\s*\(\s*(?P<var>\w+)\s*\)\s*\{(?P<cases>.*?)}|break\s*;)', re.DOTALL | re.IGNORECASE)
    for m in pat.finditer(block):
        var = m.group('var')
        cases_text = m.group('cases') or ''
        case_entries: List[Dict[str, Any]] = []
        for cm in re.finditer('case\\s+(?P<val>0x[0-9A-Fa-f]+|\\d+)\\s*:(?P<body>(?:.(?!case\\s+|default\\s*:))*.)', cases_text, re.DOTALL):
            body = cm.group('body')
            case_entries.append({'value': cm.group('val'), 'has_return': 'return' in body, 'has_break': 'break' in body, 'has_jni': '0x' in body and ('code' in body or 'JNIEnv' in body), 'has_puts': 'puts' in body or 'printf' in body, 'state_assign': _extract_state_assign(body, var), 'snippet': body.strip()[:200]})
        if len(case_entries) >= 3:
            hits.append({'state_var': var, 'cases_total': len(case_entries), 'cases': case_entries[:64]})
    return hits

def _extract_state_assign(body: str, state_var: Optional[str]) -> Optional[str]:
    if not state_var:
        return None
    m = re.search(f'\\b{re.escape(state_var)}\\s*=\\s*(0x[0-9A-Fa-f]+|\\d+)\\s*;', body)
    if m:
        return m.group(1)
    return None

def _score_function_flattening(block: str) -> int:
    score = 0
    if re.search('while\\s*\\(\\s*true\\s*\\)', block, re.IGNORECASE):
        score += 3
    score += len(re.findall('\\bswitch\\s*\\(', block)) * 2
    score += len(re.findall('\\bcase\\s+', block))
    score += len(re.findall('\\bgoto\\s+', block))
    return score

def _build_state_graph(dispatcher: Dict[str, Any]) -> List[Dict[str, Any]]:
    cases = dispatcher.get('cases')
    if not isinstance(cases, list) or len(cases) < 2:
        return []
    by_value: Dict[str, Dict[str, Any]] = {}
    for c in cases:
        if isinstance(c, dict) and isinstance(c.get('value'), str):
            by_value[c['value']] = c
    edges: List[Tuple[str, str]] = []
    for c in cases:
        if not isinstance(c, dict):
            continue
        src = c.get('value')
        nxt = c.get('state_assign')
        if isinstance(src, str) and isinstance(nxt, str) and (nxt in by_value):
            edges.append((src, nxt))
    start = cases[0].get('value') if isinstance(cases[0], dict) else None
    if not isinstance(start, str):
        return cases
    ordered: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    cur: Optional[str] = start
    while isinstance(cur, str) and cur not in seen and (cur in by_value):
        seen.add(cur)
        ordered.append(by_value[cur])
        nxt = by_value[cur].get('state_assign')
        cur = nxt if isinstance(nxt, str) else None
        if len(ordered) >= 64:
            break
    if len(ordered) < len(cases):
        for c in cases:
            if isinstance(c, dict):
                val = c.get('value')
                if isinstance(val, str) and val not in seen:
                    ordered.append(c)
                    seen.add(val)
    return ordered

def _extract_case_semantics(case_body: str) -> List[Dict[str, Any]]:
    islands: List[Dict[str, Any]] = []
    for m in re.finditer('puts\\s*\\(\\s*"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"\\s*\\)', case_body):
        islands.append({'kind': 'puts', 'value': m.group(1)})
    for m in re.finditer('printf\\s*\\(\\s*"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"', case_body):
        islands.append({'kind': 'printf', 'value': m.group(1)})
    for m in re.finditer('\\breturn\\s+([^;]+);', case_body):
        expr = m.group(1).strip()
        if len(expr) <= 80 and 'goto' not in expr:
            islands.append({'kind': 'return', 'expr': expr})
    assign_m = re.search('(\\w+)\\s*=\\s*([^;]+);', case_body)
    if assign_m:
        rhs = assign_m.group(2).strip()
        if len(rhs) <= 60 and '0x' not in rhs and ('code' not in rhs):
            islands.append({'kind': 'assign', 'lhs': assign_m.group(1), 'rhs': rhs})
    return islands

def _extract_semantic_islands(block: str) -> List[Dict[str, Any]]:
    islands: List[Dict[str, Any]] = []
    for m in re.finditer('puts\\s*\\(\\s*"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"\\s*\\)', block):
        islands.append({'kind': 'puts', 'value': m.group(1), 'line_hint': block[:m.start()].count('\n') + 1})
    for m in re.finditer('\\breturn\\s+([^;]+);', block):
        expr = m.group(1).strip()
        if len(expr) <= 80 and 'goto' not in expr:
            islands.append({'kind': 'return', 'expr': expr, 'line_hint': block[:m.start()].count('\n') + 1})
    return islands[:40]

def analyze_flattening(*, pseudo_c_path: Optional[Path]=None, pseudo_c: Optional[str]=None, max_functions: int=500) -> Dict[str, Any]:
    text = pseudo_c or ''
    if pseudo_c_path is not None and pseudo_c_path.is_file() and (not text):
        text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(text) > 2000000:
            text = text[:2000000]
    if not text:
        return {'status': 'SKIPPED_NO_PSEUDO_C'}
    blocks = _split_function_blocks(text)
    flattened_functions: List[Dict[str, Any]] = []
    total_dispatchers = 0
    total_cases = 0
    scored = [(name, blk, _score_function_flattening(blk)) for name, blk in blocks]
    scored.sort(key=lambda x: -x[2])
    for name, blk, fscore in scored[:max_functions]:
        if fscore < 4:
            continue
        dispatchers = _find_dispatcher_loops(blk)
        state_sequences: List[Dict[str, Any]] = []
        for d in dispatchers:
            ordered = _build_state_graph(d)
            case_semantics: List[Dict[str, Any]] = []
            for i, c in enumerate(ordered):
                if not isinstance(c, dict):
                    continue
                snippet = c.get('snippet') or ''
                sem = _extract_case_semantics(snippet if isinstance(snippet, str) else '')
                if sem:
                    case_semantics.append({'case_index': i, 'value': c.get('value'), 'semantics': sem})
            state_sequences.append({'state_var': d.get('state_var'), 'ordered_cases': len(ordered), 'case_semantics': case_semantics[:32]})
        if not dispatchers and fscore < 8:
            continue
        islands = _extract_semantic_islands(blk)
        total_dispatchers += len(dispatchers)
        for d in dispatchers:
            total_cases += d.get('cases_total', 0)
        flattened_functions.append({'function': name, 'flatten_score': fscore, 'dispatchers': dispatchers, 'state_sequences': state_sequences, 'semantic_islands': islands, 'recovery_hint': _build_recovery_hint(islands, dispatchers)})
    level = 'NONE'
    if len(flattened_functions) >= 5 or total_cases >= 30:
        level = 'HIGH'
    elif flattened_functions:
        level = 'MEDIUM'
    return {'status': 'OK', 'pseudo_c_path': str(pseudo_c_path.resolve()) if pseudo_c_path and pseudo_c_path.is_file() else None, 'functions_scanned': len(blocks), 'flattened_functions_total': len(flattened_functions), 'dispatcher_loops_total': total_dispatchers, 'switch_cases_total': total_cases, 'flatten_level': level, 'functions': flattened_functions[:max_functions]}

def _build_recovery_hint(islands: List[Dict[str, Any]], dispatchers: List[Dict[str, Any]]) -> str:
    puts = [i.get('value') for i in islands if i.get('kind') == 'puts' and isinstance(i.get('value'), str)]
    if puts:
        return f"Likely prints: {', '.join(puts[:3])}"
    if dispatchers:
        return f"Flattened dispatcher with {dispatchers[0].get('cases_total', 0)} cases inspect semantic islands"
    returns = [i.get('expr') for i in islands if i.get('kind') == 'return']
    if returns:
        return f'Returns: {returns[0]}'
    return 'Flattened control flow detected'
