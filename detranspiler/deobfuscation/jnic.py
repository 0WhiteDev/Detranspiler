import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
JNIC_MARKERS = ['native0/Loader', 'native0.Loader', 'native0/hidden/Hidden0', 'native0.hidden.Hidden0', 'registerNativesForClass', 'special_clinit_', 'jnic', 'JNIC', 'native-lib', 'native_obfuscator', 'native-obfuscator', 'RegisterNatives', 'JNINativeMethod', 'GetStringUTFChars', 'ReleaseStringUTFChars', 'NewStringUTF', 'FindClass', 'GetMethodID', 'GetStaticMethodID', 'CallStaticVoidMethod', 'CallVoidMethod', 'CallObjectMethod', 'CallStaticObjectMethod', 'CallStaticIntMethod', 'CallIntMethod', 'CallStaticLongMethod', 'CallLongMethod', 'CallStaticBooleanMethod', 'CallBooleanMethod', 'ExceptionCheck', 'ExceptionClear', 'ThrowNew', 'MonitorEnter', 'MonitorExit']
JNIC_FUNCTION_PATTERNS = [re.compile('\\bJava_[A-Za-z0-9_]+\\b'), re.compile('\\bJNI_OnLoad\\s*\\('), re.compile('\\bRegisterNatives\\s*\\('), re.compile('\\bJNINativeMethod\\b'), re.compile('jnic_\\w+', re.IGNORECASE), re.compile('native_\\w+_register', re.IGNORECASE)]
OBFUSCATION_HINTS = [re.compile('switch\\s*\\(\\s*\\w+\\s*\\)\\s*\\{[^}]{200,}', re.DOTALL), re.compile('while\\s*\\(\\s*1\\s*\\)\\s*\\{[^}]*switch', re.DOTALL), re.compile('\\^=\\s*0x[0-9A-Fa-f]+'), re.compile('for\s*\([^;]*;\s*\w+\s*<\s*\d+\s*;\s*\w+\+\+\)\s*\{[^}]*\[\w+]\s*\^=')]

def _scan_text(text: str, *, limit: int=200) -> Dict[str, Any]:
    hits: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for marker in JNIC_MARKERS:
        if marker in text and marker not in seen:
            seen.add(marker)
            hits.append({'kind': 'marker', 'value': marker})
        if len(hits) >= limit:
            break
    for pat in JNIC_FUNCTION_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            if val not in seen:
                seen.add(val)
                hits.append({'kind': 'pattern', 'value': val, 'pattern': pat.pattern})
            if len(hits) >= limit:
                break
    obf_hits: List[str] = []
    for pat in OBFUSCATION_HINTS:
        if pat.search(text):
            obf_hits.append(pat.pattern[:80])
    return {'hits': hits, 'obfuscation_hints': obf_hits}

def analyze_jnic_patterns(*, pseudo_c_path: Optional[Path]=None, pseudo_c: Optional[str]=None, exports: Optional[List[str]]=None, strings: Optional[List[str]]=None) -> Dict[str, Any]:
    text = pseudo_c or ''
    if pseudo_c_path is not None and pseudo_c_path.is_file() and (not text):
        text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(text) > 2000000:
            text = text[:2000000]
    combined = text
    if exports:
        combined += '\n' + '\n'.join(exports[:500])
    if strings:
        combined += '\n' + '\n'.join(strings[:2000])
    scan = _scan_text(combined)
    hits = scan['hits']
    obf = scan['obfuscation_hints']
    radioegor_hits = [h for h in hits if h.get('value') in {'native0/Loader', 'native0.Loader', 'native0/hidden/Hidden0', 'native0.hidden.Hidden0', 'registerNativesForClass', 'special_clinit_'}]
    java_exports = sorted({h['value'] for h in hits if h.get('kind') == 'pattern' and str(h.get('value', '')).startswith('Java_')})
    confidence = 'NONE'
    if len(radioegor_hits) >= 2:
        confidence = 'HIGH'
    elif any((h.get('value') == 'RegisterNatives' for h in hits)) and java_exports:
        confidence = 'HIGH'
    elif hits:
        confidence = 'MEDIUM' if len(hits) >= 5 else 'LOW'
    return {'status': 'OK' if hits or text else 'SKIPPED_NO_INPUT', 'transpiler_guess': 'radioegor/native-obfuscator' if len(radioegor_hits) >= 2 else 'JNIC' if confidence in {'HIGH', 'MEDIUM'} else 'unknown', 'radioegor_markers': radioegor_hits[:50], 'confidence': confidence, 'markers_total': len(hits), 'java_exports_detected': java_exports[:100], 'obfuscation_hints': obf[:20], 'hits': hits[:200], 'recommendations': ['JNIC: recover RegisterNatives tables from $jnicLoader exports; string decryption uses JNI_OnLoad keystream.', 'Use --jar when available; JNICLoader may supply ByteBuffer seed bytes for static ChaCha recovery.', 'Cross-check RegisterNatives tables with jni_register.json output.', 'Flattening recovery helps when CFG flattening is present.']}
