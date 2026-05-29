from typing import Any, Dict, List, Optional

def build_recovery_strategy(*, deobfuscation: Optional[Dict[str, Any]]=None, flattening: Optional[Dict[str, Any]]=None, string_decrypt: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    indicators = {}
    if isinstance(deobfuscation, dict):
        indicators = deobfuscation.get('indicators') or {}
    flat_count = 0
    if isinstance(indicators.get('control_flow_flattening'), dict):
        flat_count = int(indicators['control_flow_flattening'].get('count') or 0)
    if isinstance(flattening, dict):
        flat_count = max(flat_count, int(flattening.get('flattened_functions_total') or 0))
    xor_count = 0
    if isinstance(indicators.get('string_decryption'), dict):
        xor_count = int(indicators['string_decryption'].get('count') or 0)
    if isinstance(string_decrypt, dict):
        xor_count = max(xor_count, int(string_decrypt.get('strings_total') or 0))
    jni_count = 0
    if isinstance(indicators.get('jni_heavy'), dict):
        jni_count = int(indicators['jni_heavy'].get('count') or 0)
    anti_count = 0
    if isinstance(indicators.get('anti_debug'), dict):
        anti_count = int(indicators['anti_debug'].get('count') or 0)
    prefer_flattening = flat_count >= 3
    prefer_jni = jni_count >= 4 and flat_count < 5
    prefer_strings = xor_count >= 10 and (not prefer_flattening)
    skip_semantic_on_anti = anti_count >= 2
    fallback_order: List[str] = ['bytecode', 'pseudoc', 'pseudoc_patterns']
    if prefer_flattening:
        fallback_order += ['flatten', 'jni', 'jar']
    elif prefer_jni:
        fallback_order += ['jni', 'flatten', 'jar']
    else:
        fallback_order += ['jni', 'flatten', 'jar']
    return {'status': 'OK', 'prefer_flattening_first': prefer_flattening, 'prefer_jni_first': prefer_jni, 'prefer_string_seeds': prefer_strings, 'skip_semantic_on_anti': skip_semantic_on_anti, 'fallback_order': fallback_order, 'signals': {'flattening': flat_count, 'string_decrypt': xor_count, 'jni_heavy': jni_count, 'anti_debug': anti_count}}

def should_try_jar_fallback(*, strategy: Optional[Dict[str, Any]]=None, body_emitted: bool, low_trust: bool=False) -> bool:
    del strategy, low_trust
    return not body_emitted
