import re
from typing import Any, Dict, List, Optional, Set

def _java_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')

def _looks_like_descriptor(s: str) -> bool:
    v = s.strip()
    if v.startswith('(') and ')' in v:
        return True
    if re.match('^L[A-Za-z0-9_/$]+;$', v):
        return True
    return v in {'println', 'format', 'out'} or ('/' in v and '.' not in v)

def _map_params(expr: str, param_map: Dict[str, str]) -> str:
    out = expr
    for c_var, j_var in sorted(param_map.items(), key=lambda x: -len(x[0])):
        out = re.sub(f'\\b{re.escape(c_var)}\\b', j_var, out)
    return re.sub('\\s+', ' ', out).strip()

def _flattening_for_function(flattening: Optional[Dict[str, Any]], fn_symbol: Optional[str]) -> Optional[Dict[str, Any]]:
    if not isinstance(flattening, dict) or not isinstance(fn_symbol, str):
        return None
    for fn in flattening.get('functions') or []:
        if isinstance(fn, dict) and fn.get('function') == fn_symbol:
            return fn
    return None

def _island_to_statements(island: Dict[str, Any], *, param_map: Dict[str, str], ret_java: str, seen_puts: Set[str], return_emitted: bool) -> List[str]:
    kind = island.get('kind')
    out: List[str] = []
    if kind in {'puts', 'printf'}:
        val = island.get('value')
        if isinstance(val, str) and val.strip() and (val not in seen_puts) and (not _looks_like_descriptor(val)):
            seen_puts.add(val)
            if kind == 'printf':
                out.append(f'System.out.printf("{_java_escape(val)}");')
            elif re.search('\\b(exception|error|fail)\\b', val, re.IGNORECASE):
                out.append(f'System.err.println("{_java_escape(val)}");')
            else:
                out.append(f'System.out.println("{_java_escape(val)}");')
    elif kind == 'return' and ret_java != 'void' and (not return_emitted):
        expr = island.get('expr')
        if isinstance(expr, str) and expr:
            mapped = _map_params(expr, param_map)
            if re.match('^[A-Za-z0-9_\\s+\\-*/%()?:\'\\"\\\\]+$', mapped):
                out.append(f'return {mapped};')
    elif kind == 'assign':
        lhs = island.get('lhs')
        rhs = island.get('rhs')
        if isinstance(lhs, str) and isinstance(rhs, str):
            mapped_rhs = _map_params(rhs, param_map)
            if re.match('^[A-Za-z0-9_\\s+\\-*/%()]+$', mapped_rhs):
                pass
    return out

def _recover_switch_from_state_sequences(state_sequences: List[Any], *, param_map: Dict[str, str], ret_java: str) -> Optional[List[str]]:
    for seq in state_sequences:
        if not isinstance(seq, dict):
            continue
        case_semantics = seq.get('case_semantics')
        if not isinstance(case_semantics, list) or len(case_semantics) < 3:
            continue
        state_var = seq.get('state_var')
        jvar = param_map.get(state_var, state_var) if isinstance(state_var, str) else 'state'
        seen_puts: Set[str] = set()
        case_blocks: List[str] = []
        for case in case_semantics:
            if not isinstance(case, dict):
                continue
            val = case.get('value')
            if not isinstance(val, str):
                continue
            inner: List[str] = []
            return_emitted = False
            for island in case.get('semantics') or []:
                if not isinstance(island, dict):
                    continue
                stmts = _island_to_statements(island, param_map=param_map, ret_java=ret_java, seen_puts=seen_puts, return_emitted=return_emitted)
                for stmt in stmts:
                    if stmt.startswith('return '):
                        return_emitted = True
                    inner.append(stmt)
            if inner:
                case_blocks.append(f'        case {val}:')
                for stmt in inner:
                    case_blocks.append(f'            {stmt}')
                case_blocks.append('            break;')
        if len(case_blocks) >= 6:
            return [ f'switch ({jvar}) {{', *case_blocks, '    }']
    return None

def recover_java_from_flattening(*, fn_symbol: Optional[str], flattening: Optional[Dict[str, Any]], param_map: Optional[Dict[str, str]]=None, ret_java: str='void') -> Optional[List[str]]:
    item = _flattening_for_function(flattening, fn_symbol)
    if item is None:
        return None
    param_map = dict(param_map or {})
    state_sequences = item.get('state_sequences')
    if isinstance(state_sequences, list) and state_sequences:
        switch_body = _recover_switch_from_state_sequences(state_sequences, param_map=param_map, ret_java=ret_java)
        if isinstance(switch_body, list) and switch_body:
            return switch_body
    lines: List[str] = []
    seen_puts: set = set()
    return_emitted = False
    if isinstance(state_sequences, list) and state_sequences:
        for seq in state_sequences:
            if not isinstance(seq, dict):
                continue
            for case in seq.get('case_semantics') or []:
                if not isinstance(case, dict):
                    continue
                for island in case.get('semantics') or []:
                    if not isinstance(island, dict):
                        continue
                    for stmt in _island_to_statements(island, param_map=param_map, ret_java=ret_java, seen_puts=seen_puts, return_emitted=return_emitted):
                        if stmt.startswith('return '):
                            return_emitted = True
                        lines.append(stmt)
    islands = item.get('semantic_islands')
    if not isinstance(islands, list) or not islands:
        return lines if lines else None
    ordered = sorted([i for i in islands if isinstance(i, dict)], key=lambda x: int(x.get('line_hint') or 0))
    for island in ordered:
        for stmt in _island_to_statements(island, param_map=param_map, ret_java=ret_java, seen_puts=seen_puts, return_emitted=return_emitted):
            if stmt.startswith('return '):
                return_emitted = True
            lines.append(stmt)
    return lines if lines else None
