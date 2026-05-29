import re
from pathlib import Path
from typing import Any, Dict, List, Optional

def _uniq_limited(items: List[str], *, limit: int=100) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if not isinstance(item, str) or not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= limit:
            break
    return out

def _risk_score(indicators: Dict[str, Any]) -> int:
    score = 0
    score += min(25, int(indicators.get('indirect_calls', {}).get('count', 0)) * 2)
    score += min(20, int(indicators.get('control_flow_flattening', {}).get('count', 0)) * 5)
    score += min(20, int(indicators.get('string_decryption', {}).get('count', 0)) * 4)
    score += min(15, int(indicators.get('opaque_predicates', {}).get('count', 0)) * 3)
    score += min(10, int(indicators.get('anti_debug', {}).get('count', 0)) * 5)
    score += min(10, int(indicators.get('jni_heavy', {}).get('count', 0)))
    score += min(10, int(indicators.get('stack_strings', {}).get('count', 0)) * 2)
    score += min(10, int(indicators.get('dead_code', {}).get('count', 0)))
    score += min(10, int(indicators.get('import_hooks', {}).get('count', 0)) * 3)
    return min(100, score)

def analyze_deobfuscation(*, pseudo_c_path: Optional[Path], imports: Optional[List[str]]=None, strings: Optional[List[str]]=None, max_pseudo_c_chars: int=2000000, decrypted_strings: Optional[List[str]]=None) -> Dict[str, Any]:
    pseudo_c = ''
    if pseudo_c_path is not None and pseudo_c_path.is_file():
        pseudo_c = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(pseudo_c) > max_pseudo_c_chars:
            pseudo_c = pseudo_c[:max_pseudo_c_chars]
    return analyze_deobfuscation_text(pseudo_c, pseudo_c_path=str(pseudo_c_path.resolve()) if pseudo_c_path is not None and pseudo_c_path.is_file() else None, imports=imports, strings=strings, decrypted_strings=decrypted_strings)

def analyze_deobfuscation_text(pseudo_c: str, *, pseudo_c_path: Optional[str]=None, imports: Optional[List[str]]=None, strings: Optional[List[str]]=None, decrypted_strings: Optional[List[str]]=None) -> Dict[str, Any]:
    imports = imports or []
    strings = strings or []
    combined_names = '\n'.join(imports + strings)
    indicators: Dict[str, Any] = {}
    indirect_call_hits = re.findall('\\(\\*\\*\\(code\\s+\\*\\*\\)\\([^)]+\\)\\)\\s*\\(', pseudo_c)
    indicators['indirect_calls'] = {'count': len(indirect_call_hits), 'meaning': 'Many indirect code-pointer calls often indicate JNI vtable use, dispatchers, or obfuscator thunks.'}
    switch_hits = re.findall('\\bswitch\\s*\\([^)]+\\)\\s*\\{', pseudo_c)
    dispatcher_hits = re.findall('\\bwhile\\s*\\(\\s*true\\s*\\).*?\\bswitch\\s*\\(', pseudo_c, flags=re.DOTALL)
    indicators['control_flow_flattening'] = {'count': len(switch_hits) + len(dispatcher_hits), 'switches': len(switch_hits), 'dispatcher_loops': len(dispatcher_hits), 'meaning': 'Dispatcher loops and large switches are common in flattened control flow.'}
    xor_hits = re.findall('\\^\\s*(?:0x[0-9A-Fa-f]+|\\d+)', pseudo_c)
    rolling_loop_hits = re.findall('\\bfor\\s*\\([^)]*\\)|\\bwhile\\s*\\([^)]*\\)', pseudo_c)
    string_api_hits = [s for s in strings if isinstance(s, str) and any((token in s for token in ('GetStringUTFChars', 'NewStringUTF', 'ReleaseStringUTFChars')))]
    indicators['string_decryption'] = {'count': len(xor_hits), 'xor_ops_sample': _uniq_limited(xor_hits, limit=20), 'loop_count': len(rolling_loop_hits), 'jni_string_api_hits': _uniq_limited(string_api_hits, limit=20), 'meaning': 'XOR-heavy loops and JNI string APIs are useful places to inspect for runtime string reconstruction.'}
    opaque_hits = re.findall('\\bif\\s*\\(\\s*(?:\\([^)]*\\)\\s*)?(?:0x[0-9A-Fa-f]+|\\d+)\\s*(?:==|!=|<|>|<=|>=)\\s*(?:0x[0-9A-Fa-f]+|\\d+)\\s*\\)', pseudo_c)
    indicators['opaque_predicates'] = {'count': len(opaque_hits), 'sample': _uniq_limited(opaque_hits, limit=20), 'meaning': 'Constant-looking branches may be opaque predicates or decompiler artifacts.'}
    anti_debug_needles = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'QueryPerformanceCounter', 'GetTickCount', 'rdtsc']
    anti_debug_hits = []
    for needle in anti_debug_needles:
        if needle in combined_names or needle in pseudo_c:
            anti_debug_hits.append(needle)
    indicators['anti_debug'] = {'count': len(anti_debug_hits), 'hits': _uniq_limited(anti_debug_hits, limit=50), 'meaning': 'Timing and debugger APIs can mark anti-analysis checks.'}
    jni_names = ['FindClass', 'GetMethodID', 'GetStaticMethodID', 'CallObjectMethod', 'CallStaticObjectMethod', 'RegisterNatives', 'NewStringUTF']
    jni_hits = []
    for name in jni_names:
        if name in combined_names or name in pseudo_c:
            jni_hits.append(name)
    indicators['jni_heavy'] = {'count': len(jni_hits), 'hits': _uniq_limited(jni_hits, limit=50), 'meaning': 'JNI-heavy code is a strong signal for Java/native boundary reconstruction.'}
    stack_copy_hits = re.findall('local_[0-9A-Fa-f]+\[\d+]\s*=\s*(?:DAT_|s_)\w+\[\d+]', pseudo_c)
    indicators['stack_strings'] = {'count': len(stack_copy_hits), 'sample': _uniq_limited(stack_copy_hits, limit=15), 'meaning': 'Stack copies from global byte arrays often hide obfuscated string tables.'}
    dead_code_hits = re.findall('\\b(?:goto|LAB_[0-9A-Fa-f]+)\\b', pseudo_c)
    indicators['dead_code'] = {'count': len(dead_code_hits), 'meaning': 'Excessive gotos/labels may indicate control-flow obfuscation or decompiler artifacts.'}
    hook_needles = ['VirtualProtect', 'VirtualAlloc', 'FlushInstructionCache', 'LoadLibrary', 'GetProcAddress']
    hook_hits = [n for n in hook_needles if n in combined_names or n in pseudo_c]
    indicators['import_hooks'] = {'count': len(hook_hits), 'hits': _uniq_limited(hook_hits, limit=20), 'meaning': 'Runtime memory/import manipulation can indicate packers or dynamic JNI resolution.'}
    if decrypted_strings:
        indicators['recovered_strings'] = {'count': len(decrypted_strings), 'sample': _uniq_limited(decrypted_strings, limit=20), 'meaning': 'Strings recovered by XOR/rolling decrypt heuristics use as seeds for Java reconstruction.'}
    score = _risk_score(indicators)
    if score >= 70:
        level = 'HIGH'
    elif score >= 35:
        level = 'MEDIUM'
    elif score > 0:
        level = 'LOW'
    else:
        level = 'NONE'
    recommendations: List[str] = []
    if indicators['control_flow_flattening']['count']:
        recommendations.append('Inspect switch dispatcher variables and recover state-machine edges before translating to Java.')
    if indicators['string_decryption']['count']:
        recommendations.append('Trace XOR/string loops and dump decrypted literals into the string resolver.')
    if indicators['indirect_calls']['count']:
        recommendations.append('Correlate indirect calls with JNIEnv offsets and function-pointer tables.')
    if indicators['anti_debug']['count']:
        recommendations.append('Mark anti-debug/timing paths as low-confidence or remove them from semantic Java reconstruction.')
    if indicators['jni_heavy']['count']:
        recommendations.append('Use jni_calls.json and jni_register.json as primary anchors for class/method recovery.')
    if indicators.get('stack_strings', {}).get('count'):
        recommendations.append('Resolve stack-copied DAT_/s_ arrays via string_decrypt.json before Java emission.')
    if indicators.get('recovered_strings', {}).get('count'):
        recommendations.append('Feed recovered decrypted strings into void-body and format-string heuristics.')
    if indicators.get('import_hooks', {}).get('count'):
        recommendations.append('Inspect VirtualProtect/LoadLibrary paths for dynamically resolved JNI entry points.')
    flat_list = [{'name': k, **({} if not isinstance(v, dict) else {'count': v.get('count'), 'detail': v.get('meaning', '')})} for k, v in indicators.items() if isinstance(v, dict) and int(v.get('count') or 0) > 0]
    return {'status': 'OK' if pseudo_c or imports or strings else 'SKIPPED_NO_INPUT', 'pseudo_c_path': pseudo_c_path, 'risk_score': score, 'risk_level': level, 'indicators': indicators, 'indicator_list': flat_list, 'recommendations': recommendations}
