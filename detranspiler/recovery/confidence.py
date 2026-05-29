from typing import Any, Dict, List, Optional

def score_method(*, fn_symbol: Optional[str], class_internal: Optional[str], method: Optional[str], descriptor: Optional[str], native_index: Optional[Dict[str, Any]], had_bytecode_body: bool=False, had_pseudoc_body: bool=False, had_jni_body: bool=False, had_jar_repair: bool=False, is_low_trust: bool=False) -> Dict[str, Any]:
    score = 0
    sources: List[str] = []
    if isinstance(native_index, dict):
        for item in native_index.get('methods') or []:
            if not isinstance(item, dict):
                continue
            match = False
            if fn_symbol and item.get('fn_symbol') == fn_symbol:
                match = True
            elif class_internal and method and (item.get('class') == class_internal) and (item.get('method') == method):
                if descriptor is None or item.get('descriptor') == descriptor:
                    match = True
            if match:
                score += int(item.get('confidence') or 0) // 5
                for s in item.get('sources') or []:
                    if isinstance(s, str) and s not in sources:
                        sources.append(s)
    if had_bytecode_body:
        score += 40
        sources.append('bytecode')
    if had_pseudoc_body:
        score += 25
        sources.append('pseudo_c')
    if had_jni_body:
        score += 20
        sources.append('jni_synthesis')
    if had_jar_repair:
        score += 25
        sources.append('jar_repair')
    if is_low_trust:
        score = max(0, score - 35)
        sources.append('low_trust_penalty')
    score = min(100, score)
    if score >= 75:
        level = 'HIGH'
    elif score >= 50:
        level = 'MEDIUM'
    elif score >= 25:
        level = 'LOW'
    else:
        level = 'MINIMAL'
    return {'score': score, 'level': level, 'sources': sources, 'fn_symbol': fn_symbol, 'class': class_internal, 'method': method, 'descriptor': descriptor}

def build_method_confidence_report(*, native_index: Optional[Dict[str, Any]], anti_analysis: Optional[Dict[str, Any]], java_like: Optional[Dict[str, Any]]=None, jar_repair: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    if not isinstance(native_index, dict):
        return {'status': 'SKIPPED_NO_NATIVE_INDEX'}
    jar_repaired: set = set()
    if isinstance(jar_repair, dict):
        for item in jar_repair.get('repairs') or []:
            if isinstance(item, dict) and isinstance(item.get('method'), str):
                jar_repaired.add(item['method'])
    low_trust = set()
    if isinstance(anti_analysis, dict):
        for s in anti_analysis.get('low_trust_symbols') or []:
            if isinstance(s, str):
                low_trust.add(s)
    scored: List[Dict[str, Any]] = []
    for item in native_index.get('methods') or []:
        if not isinstance(item, dict):
            continue
        method = item.get('method')
        scored.append(score_method(fn_symbol=item.get('fn_symbol') if isinstance(item.get('fn_symbol'), str) else None, class_internal=item.get('class') if isinstance(item.get('class'), str) else None, method=method if isinstance(method, str) else None, descriptor=item.get('descriptor') if isinstance(item.get('descriptor'), str) else None, native_index=native_index, had_jar_repair=isinstance(method, str) and method in jar_repaired, is_low_trust=isinstance(item.get('fn_symbol'), str) and item.get('fn_symbol') in low_trust))
    high = sum((1 for s in scored if s.get('level') == 'HIGH'))
    medium = sum((1 for s in scored if s.get('level') == 'MEDIUM'))
    return {'status': 'OK', 'methods_total': len(scored), 'high_confidence': high, 'medium_confidence': medium, 'methods': scored[:2000]}
