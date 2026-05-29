import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
ANTI_DEBUG_APIS = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'QueryPerformanceCounter', 'GetTickCount', 'rdtsc', 'NtSetInformationThread', 'HideThreadFromDebugger']
TIMING_PATTERNS = ['\\bclock\\s*\\(', '\\btime\\s*\\(', 'QueryPerformanceCounter', 'GetTickCount64']

def _split_function_blocks(pseudo_c: str) -> List[tuple[str, str]]:
    blocks: List[tuple[str, str]] = []
    cur_name: Optional[str] = None
    cur_lines: List[str] = []
    marker = re.compile('^/\\* FUNCTION\\s+(?P<name>\\w+)\\s+')
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

def analyze_anti_analysis(*, pseudo_c_path: Optional[Path]=None, pseudo_c: Optional[str]=None, imports: Optional[List[str]]=None, strings: Optional[List[str]]=None) -> Dict[str, Any]:
    text = pseudo_c or ''
    if pseudo_c_path is not None and pseudo_c_path.is_file() and (not text):
        text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(text) > 2000000:
            text = text[:2000000]
    combined = '\n'.join(imports or []) + '\n' + '\n'.join(strings or [])
    global_hits = [api for api in ANTI_DEBUG_APIS if api in combined or api in text]
    suspicious_functions: List[Dict[str, Any]] = []
    low_trust_symbols: Set[str] = set()
    for name, block in _split_function_blocks(text):
        hits: List[str] = []
        for api in ANTI_DEBUG_APIS:
            if api in block:
                hits.append(api)
        for pat in TIMING_PATTERNS:
            if re.search(pat, block, re.IGNORECASE):
                hits.append(pat.strip('\\b'))
        if hits:
            low_trust_symbols.add(name)
            suspicious_functions.append({'function': name, 'hits': hits[:20], 'recommendation': 'Exclude from semantic Java recovery or mark as untrusted'})
    level = 'NONE'
    if len(suspicious_functions) >= 5:
        level = 'HIGH'
    elif suspicious_functions:
        level = 'MEDIUM'
    elif global_hits:
        level = 'LOW'
    return {'status': 'OK' if text or imports or strings else 'SKIPPED_NO_INPUT', 'risk_level': level, 'global_hits': global_hits[:50], 'suspicious_functions_total': len(suspicious_functions), 'low_trust_symbols': sorted(low_trust_symbols)[:500], 'suspicious_functions': suspicious_functions[:200], 'recommendations': ['Skip or comment-out recovery for low_trust_symbols when generating Java bodies.', 'Cross-check timing/debug paths against JAR bytecode when available.']}

def is_low_trust_symbol(symbol: Optional[str], anti_analysis: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(symbol, str) or not symbol:
        return False
    if not isinstance(anti_analysis, dict):
        return False
    low = anti_analysis.get('low_trust_symbols')
    if not isinstance(low, list):
        return False
    return symbol in low
