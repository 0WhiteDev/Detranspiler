from typing import List

def inject_java_imports(lines: List[str]) -> List[str]:
    if not lines:
        return lines
    text = '\n'.join(lines)
    needed: List[str] = []
    if 'Objects.' in text:
        needed.append('import java.util.Objects;')
    if 'Arrays.' in text:
        needed.append('import java.util.Arrays;')
    if not needed:
        return lines
    out: List[str] = []
    inserted = False
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        if not inserted and line.startswith('package '):
            if i + 1 < len(lines) and (not lines[i + 1].strip()):
                i += 1
                out.append(lines[i])
            for imp in sorted(set(needed)):
                out.append(imp)
            out.append('')
            inserted = True
        i += 1
    if not inserted:
        for imp in sorted(set(needed)):
            out.insert(0, imp)
        if out and out[-1].strip():
            out.append('')
    return out
