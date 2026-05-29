from typing import Any, Dict, List, Optional

def scan_patterns(*, exports: List[str], imports: List[str], strings: List[str], pseudo_c: Optional[str]=None, limit_per_category: int=100) -> Dict[str, Any]:
    categories: Dict[str, List[str]] = {'jni': ['JNI_OnLoad', 'JNI_OnUnload', 'RegisterNatives', 'JNINativeInterface', 'JNIEnv', 'Java_'], 'crypto': ['AES', 'RC4', 'RSA', 'ECDSA', 'Curve25519', 'SHA1', 'SHA256', 'SHA512', 'MD5', 'bcrypt', 'scrypt', 'PBKDF2'], 'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'DbgBreakPoint'], 'network': ['WinHttp', 'InternetOpen', 'HttpSendRequest', 'recv', 'send', 'connect', 'WSAStartup'], 'compression': ['zlib', 'inflate', 'deflate', 'LZ4', 'LZMA', 'ZSTD'], 'vm_obfuscation': ['VMProtect', 'Themida', 'Obsidium', 'virtual machine'], 'native_transpiler': ['JNIC', 'jnic', 'native-lib', 'RegisterNatives', 'JNI_OnLoad', 'Java_', 'JNINativeMethod', 'libnative', 'native_obfuscator', 'native-obfuscator', 'skidfuscator', 'ZKM', 'Allatori', 'DashO']}
    sources: Dict[str, List[str]] = {'exports': exports, 'imports': imports, 'strings': strings}
    if pseudo_c:
        sources['pseudo_c'] = [pseudo_c]
    out_categories: Dict[str, Any] = {}
    total_hits = 0
    for category, needles in categories.items():
        hits: List[Dict[str, Any]] = []
        for source, values in sources.items():
            for v in values:
                for n in needles:
                    if n in v:
                        hits.append({'source': source, 'needle': n, 'value': v[:240]})
                        break
                if len(hits) >= limit_per_category:
                    break
            if len(hits) >= limit_per_category:
                break
        out_categories[category] = {'count': len(hits), 'hits': hits}
        total_hits += len(hits)
    return {'status': 'OK', 'total_hits': total_hits, 'categories': out_categories}
