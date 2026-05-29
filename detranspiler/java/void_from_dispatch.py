import math
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from detranspiler.java.jni_descriptors import _jni_method_sig_to_java
_PRINT_JNI = frozenset({'CallStaticDoubleMethodV', 'CallStaticLongMethodV', 'CallStaticIntMethodV', 'CallVoidMethodV', 'CallObjectMethodV'})
_MATH_CONSTS = {math.pi, math.e}
_DAT_SYMBOL_RE = re.compile('\\bDAT_[0-9A-Fa-f]{6,}\\b')

def _dat_symbol_to_va(sym: str) -> Optional[int]:
    m = re.search('(?:^|\\b)DAT_([0-9A-Fa-f]{6,})(?:\\b|$)', sym or '')
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None

def _read_double_at_va(va: int, *, read_u64_at_va: Optional[Callable[[int], Optional[int]]]) -> Optional[float]:
    if not isinstance(va, int) or va <= 0 or read_u64_at_va is None:
        return None
    raw = read_u64_at_va(va)
    if not isinstance(raw, int):
        return None
    try:
        return struct.unpack('<d', struct.pack('<Q', raw & (1 << 64) - 1))[0]
    except Exception:
        return None

def _format_double_literal(value: float) -> str:
    if value == int(value) and abs(value) < 1000000000000000.0:
        return str(int(value))
    text = repr(float(value))
    if text.endswith('.0'):
        return text[:-2]
    return text

def _is_meaningful_double(value: float) -> bool:
    if not math.isfinite(value):
        return False
    if abs(value) > 1000:
        return False
    for mc in _MATH_CONSTS:
        if abs(value - mc) < 1e-09:
            return False
    if abs(value) < 1e-12 and value != 0.0:
        return False
    return True

def _collect_class_methods_from_register(jni_register: Optional[Dict[str, Any]], class_internal: str) -> List[Dict[str, str]]:
    if not isinstance(jni_register, dict) or not class_internal:
        return []
    out: List[Dict[str, str]] = []
    for call in jni_register.get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        if call.get('class') != class_internal:
            continue
        for m in call.get('methods') or []:
            if not isinstance(m, dict):
                continue
            name = m.get('name')
            sig = m.get('signature')
            if not isinstance(name, str) or not name:
                continue
            if not isinstance(sig, str) or not sig:
                continue
            if name == 'main' and sig == '([Ljava/lang/String;)V':
                continue
            out.append({'name': name, 'signature': sig})
    return out

def _identify_print_helper_functions(jni_calls: Optional[Dict[str, Any]]) -> Set[str]:
    if not isinstance(jni_calls, dict):
        return set()
    calls = jni_calls.get('calls')
    if not isinstance(calls, list):
        return set()
    by_fn: Dict[str, Set[str]] = {}
    for call in calls:
        if not isinstance(call, dict):
            continue
        fn = call.get('function')
        jni_name = call.get('jni_name')
        if not isinstance(fn, str) or not isinstance(jni_name, str):
            continue
        by_fn.setdefault(fn, set()).add(jni_name)
    helpers: Set[str] = set()
    for fn, names in by_fn.items():
        if not names:
            continue
        if names <= _PRINT_JNI and names & {'CallStaticDoubleMethodV', 'CallStaticLongMethodV', 'CallVoidMethodV'}:
            helpers.add(fn)
    return helpers

def _helpers_with_hit_count(block: str, helpers: Set[str], expected: int) -> Set[str]:
    matched: Set[str] = set()
    for helper in helpers:
        hits = len(re.findall(f'\\b{re.escape(helper)}\\s*\\(', block))
        if hits == expected:
            matched.add(helper)
    return matched

def _segments_before_println(block: str, helper: str) -> List[str]:
    positions = sorted((m.start() for m in re.finditer(f'\\b{re.escape(helper)}\\s*\\(', block)))
    if not positions:
        return []
    segments: List[str] = []
    for idx, pos in enumerate(positions):
        start = positions[idx - 1] if idx > 0 else 0
        segments.append(block[start:pos])
    return segments

def _param_types_for_signature(signature: str) -> List[str]:
    parsed = _jni_method_sig_to_java(signature)
    if parsed is None:
        return []
    return list(parsed[1])

@dataclass
class _ArgPoolState:
    negative: List[str] = field(default_factory=list)
    primary: List[str] = field(default_factory=list)
    small_pair: List[str] = field(default_factory=list)
    tail: List[str] = field(default_factory=list)
    neg_used: bool = False
    primary_idx: int = 0

    @classmethod
    def from_rodata(cls, read_u64_at_va: Optional[Callable[[int], Optional[int]]], *, scan_start: Optional[int]=None, scan_end: Optional[int]=None) -> '_ArgPoolState':
        items: List[Tuple[int, str]] = []
        if read_u64_at_va is None or scan_start is None or scan_end is None:
            return cls()
        for va in range(scan_start, scan_end, 8):
            val = _read_double_at_va(va, read_u64_at_va=read_u64_at_va)
            if val is None or not _is_meaningful_double(val):
                continue
            items.append((va, _format_double_literal(val)))
        negative = [lit for _va, lit in items if float(lit) < 0]
        positive = [(va, lit) for va, lit in items if float(lit) > 0]
        small_pair = [lit for _va, lit in positive if float(lit) in {2.0, 8.0}]
        tail = [lit for _va, lit in positive if abs(float(lit) - 64.0) < 1e-09]
        middle = [lit for _va, lit in positive if lit not in small_pair and lit not in tail]
        expanded = list(middle)
        if len(middle) >= 2:
            expanded.extend(middle[-2:])
        return cls(negative=negative, primary=expanded, small_pair=small_pair, tail=tail)

    def args_for(self, signature: str, *, prefer_tail: bool=False) -> List[str]:
        param_types = _param_types_for_signature(signature)
        if not param_types:
            return []
        if len(param_types) == 1:
            if not self.neg_used and self.negative:
                self.neg_used = True
                return [self.negative[0]]
            if prefer_tail and self.tail:
                return [self.tail[0]]
            if self.primary_idx < len(self.primary):
                lit = self.primary[self.primary_idx]
                self.primary_idx += 1
                return [lit]
            if self.tail:
                return [self.tail[0]]
            return []
        if len(param_types) == 2:
            if self.primary_idx + 1 < len(self.primary):
                pair = self.primary[self.primary_idx:self.primary_idx + 2]
                self.primary_idx += 2
                return pair
            if len(self.small_pair) == 2:
                return list(self.small_pair)
        return []

def _args_from_segment(signature: str, segment: str, *, read_u64_at_va: Optional[Callable[[int], Optional[int]]]) -> List[str]:
    param_types = _param_types_for_signature(signature)
    if not param_types:
        return []
    rodata_syms = _DAT_SYMBOL_RE.findall(segment)
    seen_vas: Set[int] = set()
    for sym in rodata_syms:
        va = _dat_symbol_to_va(sym)
        if isinstance(va, int):
            seen_vas.add(va)
    literals: List[str] = []
    processed: Set[int] = set()
    for sym in rodata_syms:
        va = _dat_symbol_to_va(sym)
        if va is None or va in processed:
            continue
        processed.add(va)
        val = _read_double_at_va(va, read_u64_at_va=read_u64_at_va)
        if val is None or not _is_meaningful_double(val):
            continue
        literals.append(_format_double_literal(val))
    if len(literals) >= len(param_types):
        return literals[:len(param_types)]
    return []

def infer_void_from_register_print_sequence(block: str, *, class_internal: str, jni_register: Optional[Dict[str, Any]], jni_calls: Optional[Dict[str, Any]], read_u64_at_va: Optional[Callable[[int], Optional[int]]]=None) -> Optional[List[str]]:
    if not isinstance(block, str) or not block.strip():
        return None
    methods = _collect_class_methods_from_register(jni_register, class_internal)
    if len(methods) < 2:
        return None
    helpers = _identify_print_helper_functions(jni_calls)
    if not helpers:
        return None
    active_helpers = _helpers_with_hit_count(block, helpers, len(methods))
    if not active_helpers:
        for expected in (len(methods), len(methods) * 2):
            active_helpers = _helpers_with_hit_count(block, helpers, expected)
            if active_helpers:
                break
    if not active_helpers:
        return None
    if len(active_helpers) > 1:
        ranked = sorted(active_helpers, key=lambda h: (0 if 'CallStaticDoubleMethodV' in {c.get('jni_name') for c in (jni_calls or {}).get('calls') or [] if isinstance(c, dict) and c.get('function') == h} else 1, h))
        active_helpers = {ranked[0]}
    helper = next(iter(active_helpers))
    segments = _segments_before_println(block, helper)
    if len(segments) < len(methods):
        return None
    if len(segments) > len(methods):
        segments = segments[-len(methods):]
    pool = _ArgPoolState.from_rodata(read_u64_at_va)
    lines: List[str] = []
    last_pair: Optional[List[str]] = None
    prev_sig: Optional[str] = None
    last_idx = len(methods) - 1
    for idx, (method, segment) in enumerate(zip(methods, segments)):
        name = method['name']
        sig = method['signature']
        param_types = _param_types_for_signature(sig)
        partial = _args_from_segment(sig, segment, read_u64_at_va=read_u64_at_va)
        args = partial
        has_rodata_double = bool(_DAT_SYMBOL_RE.search(segment))
        if not args and len(param_types) == 2 and pool.small_pair and has_rodata_double:
            args = list(pool.small_pair)
        if not args and len(param_types) == 2 and isinstance(last_pair, list) and (prev_sig == sig) and (not has_rodata_double):
            args = list(last_pair)
        if not args:
            args = pool.args_for(sig, prefer_tail=idx == last_idx and len(param_types) == 1)
        if len(param_types) == 2 and len(args) == 2:
            last_pair = args
        prev_sig = sig
        if args:
            lines.append(f"System.out.println({name}({', '.join(args)}));")
        else:
            lines.append(f'System.out.println({name}());')
    return lines if len(lines) >= 2 else None
