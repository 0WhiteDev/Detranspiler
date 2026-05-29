from typing import Any, Dict, List, Optional, Set

def _sanitize(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '$'):
            out.append(ch)
        else:
            out.append('_')
    return ''.join(out) or '_'

def collect_related_blocks(*, root_symbol: Optional[str], callgraph: Optional[Dict[str, Any]], blocks_by_name: Dict[str, str], max_helpers: int=12, max_chars: int=48000) -> Optional[str]:
    if not isinstance(root_symbol, str) or not root_symbol:
        return None
    if not isinstance(blocks_by_name, dict):
        return None
    symbols: List[str] = []
    seen: Set[str] = set()

    def add(sym: Optional[str]) -> None:
        if not isinstance(sym, str) or not sym or sym in seen:
            return
        seen.add(sym)
        symbols.append(sym)
    add(root_symbol)
    if isinstance(callgraph, dict):
        for item in callgraph.get('java_export_helpers') or []:
            if not isinstance(item, dict):
                continue
            if item.get('java_export') == root_symbol:
                for h in item.get('helpers') or []:
                    add(h if isinstance(h, str) else None)
                    if len(symbols) >= max_helpers + 1:
                        break
        for item in callgraph.get('native_method_chains') or []:
            if not isinstance(item, dict):
                continue
            if item.get('root') == root_symbol:
                for h in item.get('reachable') or []:
                    add(h if isinstance(h, str) else None)
                    if len(symbols) >= max_helpers + 1:
                        break
        for export in callgraph.get('java_exports') or []:
            if not isinstance(export, dict):
                continue
            if export.get('name') == root_symbol:
                for c in export.get('callees') or []:
                    add(c if isinstance(c, str) else None)
    parts: List[str] = []
    total = 0
    for sym in symbols:
        block = blocks_by_name.get(_sanitize(sym)) or blocks_by_name.get(sym)
        if not isinstance(block, str) or not block.strip():
            continue
        chunk = f'{block}\n'
        if total + len(chunk) > max_chars:
            break
        parts.append(chunk)
        total += len(chunk)
    if len(parts) <= 1 and parts:
        return parts[0]
    return '\n'.join(parts) if parts else None
