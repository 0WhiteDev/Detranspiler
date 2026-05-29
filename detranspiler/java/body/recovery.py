import re
from typing import Dict, List, Optional
from detranspiler.jar.similarity import similarity_between_bodies
from detranspiler.native.strings.resolver import substitute_symbols_in_block
_QUALITY_MARKERS = ('System.out.', 'System.err.', 'throw new', 'for (', 'while (', '.append(', 'Math.', 'Objects.', 'String.format', 'new ', '.equals(', '.length()')
_NATIVE_JUNK_RE = re.compile('\\b(cVar\\d*|local_[0-9A-Za-z_]+|uVar\\d*|param_\\d+|DAT_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+)\\b')
_INVALID_NATIVE_JAVA_RE = re.compile('(/\\*|\\*/|\\bstd::|_Throw_Cpp_error|_invoke_watson|\\(void\\s*\\*\\)|\\bundefined\\d*\\b|\\bulonglong\\b|\\blonglong\\b|->)')

def prepare_pseudoc_block(block: Optional[str], *, string_symbol_map: Optional[Dict[str, str]]=None) -> Optional[str]:
    if not isinstance(block, str) or not block.strip():
        return block
    if isinstance(string_symbol_map, dict) and string_symbol_map:
        return substitute_symbols_in_block(block, string_symbol_map)
    return block

def is_stub_body_lines(lines: List[str]) -> bool:
    if is_invalid_java_body_lines(lines):
        return True
    meaningful = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        if '[jar-guided]' in s or '[jar-repair]' in s:
            continue
        if s == 'return;' or (s.startswith('return ') and s in {'return 0;', 'return false;', 'return 0L;', 'return 0.0f;', 'return 0.0d;', "return '\\0';", 'return null;'}):
            continue
        meaningful += 1
    return meaningful == 0

def is_invalid_java_body_lines(lines: List[str]) -> bool:
    if not isinstance(lines, list) or not lines:
        return False
    meaningful = _meaningful_statements(lines)
    if not meaningful:
        return False
    bad = 0
    for s in meaningful:
        if _INVALID_NATIVE_JAVA_RE.search(s):
            bad += 1
        elif s.startswith('return ') and ('*' in s and ';' in s and ('Math.' not in s)):
            bad += 1
    return bad >= max(1, len(meaningful) // 2)

def _meaningful_statements(lines: List[str]) -> List[str]:
    out: List[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        if s == 'return;':
            continue
        out.append(s)
    return out

def is_low_quality_body_lines(lines: List[str], *, jar_reference: Optional[List[str]]=None) -> bool:
    if is_invalid_java_body_lines(lines):
        return True
    if is_stub_body_lines(lines):
        return True
    meaningful = _meaningful_statements(lines)
    if not meaningful:
        return True
    text = '\n'.join(lines)
    if any((marker in text for marker in _QUALITY_MARKERS)):
        if jar_reference:
            sim = similarity_between_bodies(lines, jar_reference)
            if sim >= 0.45:
                return False
        else:
            return False
    junk_lines = sum((1 for s in meaningful if _NATIVE_JUNK_RE.search(s)))
    if junk_lines >= max(1, len(meaningful) // 2) and len(meaningful) <= 3:
        return True
    if jar_reference:
        ref_meaningful = _meaningful_statements(jar_reference)
        if len(ref_meaningful) >= 2:
            sim = similarity_between_bodies(lines, jar_reference)
            if sim < 0.35:
                return True
    return False

def body_should_prefer_jar(lines: List[str], jar_reference: Optional[List[str]], *, min_reference_statements: int=2, max_similarity: float=0.4) -> bool:
    if not isinstance(jar_reference, list) or not jar_reference:
        return False
    if len(_meaningful_statements(jar_reference)) < min_reference_statements:
        return False
    if is_stub_body_lines(lines):
        return True
    if is_low_quality_body_lines(lines, jar_reference=jar_reference):
        return True
    return similarity_between_bodies(lines, jar_reference) < max_similarity
