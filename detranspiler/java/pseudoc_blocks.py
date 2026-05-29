import re
from typing import Dict, List, Optional, Tuple

def _split_pseudoc_blocks(pseudo_c: str, *, max_blocks: int=5000) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    current_name: Optional[str] = None
    current_lines: List[str] = []
    marker = re.compile('^/\\* FUNCTION\\s+(?P<name>.+?)\\s+.+?\\*/\\s*$')
    for line in pseudo_c.splitlines():
        m = marker.match(line.strip())
        if m:
            if current_name is not None:
                blocks.append((current_name, '\n'.join(current_lines).rstrip() + '\n'))
                if len(blocks) >= max_blocks:
                    return blocks
            current_name = m.group('name').strip()
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)
    if current_name is not None:
        blocks.append((current_name, '\n'.join(current_lines).rstrip() + '\n'))
    return blocks

def _extract_label_block(pseudo_c_text: str, *, label: str, max_lines: int=120) -> Optional[str]:
    if not pseudo_c_text or not label:
        return None
    pat = re.compile(f'(?m)^\\s*{re.escape(label)}\\s*:\\s*$')
    m = pat.search(pseudo_c_text)
    if m is None:
        return None
    start = m.start()
    tail = pseudo_c_text[start:]
    out_lines: List[str] = []
    for line in tail.splitlines():
        if re.match('^/\\* FUNCTION\\s+', line.strip()):
            break
        if line.strip().startswith('LAB_') and line.strip().endswith(':') and (not line.strip().startswith(f'{label}:')):
            break
        out_lines.append(line)
        if len(out_lines) >= max_lines:
            break
    block = '\n'.join(out_lines).strip()
    if not block:
        return None
    return block + '\n'
