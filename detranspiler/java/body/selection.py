import re
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.body.recovery import is_invalid_java_body_lines, is_stub_body_lines
from detranspiler.jar.similarity import jar_similarity_bonus, similarity_between_bodies
from detranspiler.java.body.recovery import body_should_prefer_jar
_QUALITY_MARKERS = ('System.out.', 'System.err.', 'throw new', 'if (', 'for (', 'while (', '.append(', 'Math.', 'Objects.', 'String.format', 'new ', '.equals(', '.length()', '.length')
_WEAK_RETURN_EXPRS = frozenset({'0', 'false', 'null', '0L', '0.0f', '0.0d', 'true'})
_SOURCE_BONUS = {'jar': 18, 'dispatch': 20, 'bytecode': 12, 'jni': 10, 'simple': 8, 'flatten': 6, 'pseudoc': 5, 'composed': 9, 'return': 4}

def _strategy_source_bonus(source: str, strategy: Optional[Dict[str, Any]]) -> int:
    if not isinstance(strategy, dict):
        return 0
    order = strategy.get('fallback_order')
    if not isinstance(order, list):
        return 0
    try:
        idx = order.index(source)
    except ValueError:
        return 0
    return max(0, (len(order) - idx) * 2)

def score_java_body_lines(lines: Optional[List[str]], *, source: str='', strategy: Optional[Dict[str, Any]]=None) -> int:
    if not isinstance(lines, list) or not lines:
        return 0
    if is_invalid_java_body_lines(lines):
        return 0
    if is_stub_body_lines(lines):
        return 2
    score = 10
    text = '\n'.join(lines)
    meaningful = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        if '[jar-guided]' in s or '[jar-repair]' in s:
            score += 10
            continue
        meaningful += 1
        if re.search('\\b(cVar|local_|uVar|param_\\d+)\\b', s) and 'System.out.' not in s:
            score -= 3
    score += min(meaningful * 3, 72)
    for marker in _QUALITY_MARKERS:
        if marker in text:
            score += 4
    score += _SOURCE_BONUS.get(source, 0)
    score += _strategy_source_bonus(source, strategy)
    return score

def pick_best_java_body(candidates: List[Tuple[str, Optional[List[str]]]], *, strategy: Optional[Dict[str, Any]]=None) -> Tuple[Optional[str], Optional[List[str]], int]:
    best_source: Optional[str] = None
    best_body: Optional[List[str]] = None
    best_score = -1
    for source, body in candidates:
        if isinstance(body, list) and is_invalid_java_body_lines(body):
            continue
        s = score_java_body_lines(body, source=source, strategy=strategy)
        if s > best_score:
            best_score = s
            best_source = source
            best_body = body if isinstance(body, list) else None
    return best_source, best_body, best_score

def normalize_body_lines(lines: List[str]) -> List[str]:
    out: List[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        out.append(line if line.startswith('    ') else f'    {s}')
    return out

def format_recovery_comment() -> str:
    return ''

def compose_method_body(*, prelude_lines: Optional[List[str]]=None, return_expr: Optional[str]=None) -> Optional[List[str]]:
    out: List[str] = []
    seen: set[str] = set()
    for line in prelude_lines or []:
        s = line.strip()
        if not s or s.startswith('return '):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(line if line.startswith('    ') else f'    {s}')
    if isinstance(return_expr, str) and return_expr.strip():
        out.append(f'    return {return_expr.strip()};')
    return out if out else None

def merge_complementary_bodies(candidates: List[Tuple[str, Optional[List[str]]]], *, strategy: Optional[Dict[str, Any]]=None, jar_reference: Optional[List[str]]=None, max_lines: int=200) -> Tuple[Optional[str], Optional[List[str]], int, List[str]]:
    ranked: List[Tuple[int, str, List[str]]] = []
    for source, body in candidates:
        if not isinstance(body, list) or not body:
            continue
        score = score_java_body_lines(body, source=source, strategy=strategy)
        score += jar_similarity_bonus(body, jar_reference)
        ranked.append((score, source, body))
    if not ranked:
        return None, None, 0, []
    ranked.sort(key=lambda x: -x[0])
    best_score, best_source, best_body = ranked[0]
    merged = normalize_body_lines(list(best_body))
    seen = {ln.strip() for ln in merged}
    sources_used: List[str] = [best_source]
    guards: List[str] = []
    extras: List[str] = []
    hints: List[str] = []
    _EXTRA_MARKERS = ('System.out.', 'System.err.', 'throw new', '.append(', 'String.format', ' = ', 'new ')
    for score, merge_source, body in ranked[1:]:
        if score < 6:
            continue
        contributed = False
        for line in normalize_body_lines(body):
            s = line.strip()
            if not s or s in seen or s.startswith('return '):
                continue
            if s.startswith('if (') and ('null' in s or '== null' in s):
                guards.append(line)
                seen.add(s)
                contributed = True
            elif s.startswith('//') and '[flatten]' not in s:
                hints.append(line)
                seen.add(s)
                contributed = True
            elif any((marker in s for marker in _EXTRA_MARKERS)):
                extras.append(line)
                seen.add(s)
                contributed = True
        if contributed and merge_source not in sources_used:
            sources_used.append(merge_source)
    final = guards + merged + extras + hints
    if len(final) > max_lines:
        final = final[:max_lines]
    if len(final) > len(merged):
        return best_source, final, score_java_body_lines(final, source=best_source, strategy=strategy), sources_used
    return best_source, best_body, best_score, sources_used

def select_java_body(candidates: List[Tuple[str, Optional[List[str]]]], *, strategy: Optional[Dict[str, Any]]=None, jar_reference: Optional[List[str]]=None) -> Tuple[Optional[str], Optional[List[str]], int, List[str]]:
    if isinstance(jar_reference, list) and jar_reference:
        jar_body = None
        for source, body in candidates:
            if source == 'jar' and isinstance(body, list) and body:
                jar_body = body
                break
        if jar_body is None:
            jar_body = jar_reference
        for source, body in candidates:
            if source == 'jar' or not isinstance(body, list) or (not body):
                continue
            if body_should_prefer_jar(body, jar_body):
                score = score_java_body_lines(jar_body, source='jar', strategy=strategy)
                score += jar_similarity_bonus(jar_body, jar_body)
                return 'jar', normalize_body_lines(jar_body), score, ['jar']
    return merge_complementary_bodies(candidates, strategy=strategy, jar_reference=jar_reference)

def score_return_expr(expr: Optional[str], *, source: str='') -> int:
    if not isinstance(expr, str) or not expr.strip():
        return 0
    e = expr.strip()
    if e in _WEAK_RETURN_EXPRS:
        return 1
    score = 8 + _SOURCE_BONUS.get(source, 0) // 2
    if 'Math.' in e:
        score += 14
    if '.equals(' in e or 'Objects.equals' in e:
        score += 12
    if '.length' in e:
        score += 8
    if '?' in e and ':' in e:
        score += 10
    if '[' in e and ']' in e:
        score += 6
    score += min(len(e) // 12, 8)
    return score

def pick_best_return_expr(candidates: List[Tuple[str, Optional[str]]], *, jar_reference_expr: Optional[str]=None) -> Tuple[Optional[str], List[str]]:
    best_expr: Optional[str] = None
    best_score = -1
    best_source: Optional[str] = None
    jar_norm = jar_reference_expr.replace(' ', '') if isinstance(jar_reference_expr, str) else ''
    for source, expr in candidates:
        s = score_return_expr(expr, source=source)
        if isinstance(expr, str) and jar_norm:
            from difflib import SequenceMatcher
            ratio = SequenceMatcher(None, expr.replace(' ', ''), jar_norm).ratio()
            if ratio >= 0.75:
                s += 30
            elif ratio >= 0.5:
                s += 15
        if s > best_score:
            best_score = s
            best_expr = expr if isinstance(expr, str) else None
            best_source = source
    sources = [best_source] if isinstance(best_source, str) else []
    return best_expr, sources
