from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.jar.guided import build_jar_method_index
from detranspiler.java.body.recovery import prepare_pseudoc_block
from detranspiler.java.ghidra_json import _load_ghidra_functions_json
from detranspiler.java.identifiers import _sanitize_java_identifier
from detranspiler.jar.scan import _jar_scan_classes
from detranspiler.java.pseudoc_blocks import _split_pseudoc_blocks
from detranspiler.java.recovery_hints import _flattening_hints_by_function, _jni_call_hints_by_function
from detranspiler.java.type_mapping import _ghidra_type_to_java
from detranspiler.native.strings.resolver import build_string_symbol_map
from detranspiler.recovery.strategy import build_recovery_strategy

def prepare_core(*, exports: List[str], pseudo_c_path: Optional[Path], functions_json_path: Optional[Path], class_name: str, max_functions: int, max_pseudo_c_chars: int, jni_calls: Optional[Dict[str, Any]], jar_path: Optional[Path], callgraph: Optional[Dict[str, Any]], extra_seed_strings: Optional[List[str]], flattening: Optional[Dict[str, Any]], jar_sources_dir: Optional[Path], deobfuscation: Optional[Dict[str, Any]], string_decrypt: Optional[Dict[str, Any]], string_symbol_map: Optional[Dict[str, str]]) -> dict:
    pseudo_c_text: Optional[str] = None
    blocks: List[Tuple[str, str]] = []
    if pseudo_c_path is not None and pseudo_c_path.is_file():
        pseudo_c_text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        if len(pseudo_c_text) > max_pseudo_c_chars:
            pseudo_c_text = pseudo_c_text[:max_pseudo_c_chars]
        blocks = _split_pseudoc_blocks(pseudo_c_text)
    by_name: Dict[str, str] = {}
    for name, block in blocks:
        by_name[_sanitize_java_identifier(name)] = block
    if not isinstance(string_symbol_map, dict) or not string_symbol_map:
        string_symbol_map = build_string_symbol_map(string_decrypt=string_decrypt)
    if string_symbol_map:
        by_name = {k: prepare_pseudoc_block(v, string_symbol_map=string_symbol_map) or v for k, v in by_name.items()}
    ghidra_json = _load_ghidra_functions_json(functions_json_path)
    ghidra_funcs: List[Dict[str, Any]] = []
    if isinstance(ghidra_json, dict):
        raw_funcs = ghidra_json.get('functions')
        if isinstance(raw_funcs, list):
            ghidra_funcs = [f for f in raw_funcs if isinstance(f, dict)]
    jar_meta = _jar_scan_classes(jar_path)
    jni_hints = _jni_call_hints_by_function(jni_calls)
    flat_hints = _flattening_hints_by_function(flattening)
    recovery_strategy = build_recovery_strategy(deobfuscation=deobfuscation, flattening=flattening, string_decrypt=string_decrypt)
    jar_index: Optional[Dict[str, Any]] = None
    if jar_sources_dir is not None and Path(jar_sources_dir).is_dir():
        jar_index = build_jar_method_index(jar_sources_dir=Path(jar_sources_dir))
    if isinstance(string_decrypt, dict):
        for item in string_decrypt.get('strings') or []:
            if isinstance(item, dict) and isinstance(item.get('value'), str):
                if extra_seed_strings is None:
                    extra_seed_strings = []
                if item['value'] not in extra_seed_strings:
                    extra_seed_strings.append(item['value'])
    helper_blocks: Dict[str, str] = {}
    if isinstance(callgraph, dict):
        for item in callgraph.get('java_export_helpers') or []:
            if not isinstance(item, dict):
                continue
            export_name = item.get('java_export')
            helpers = item.get('helpers')
            if not isinstance(export_name, str) or not isinstance(helpers, list):
                continue
            merged: List[str] = []
            for h in helpers:
                if not isinstance(h, str):
                    continue
                blk = by_name.get(_sanitize_java_identifier(h)) or by_name.get(h)
                if isinstance(blk, str) and blk.strip():
                    merged.append(blk)
            if merged:
                helper_blocks[export_name] = '\n'.join(merged)
    sig_by_raw: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {}
    sig_by_sanitized: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {}
    for f in ghidra_funcs:
        raw_name = f.get('name')
        if not isinstance(raw_name, str) or not raw_name:
            continue
        ret_java = _ghidra_type_to_java(f.get('return_type') if isinstance(f.get('return_type'), str) else None, is_return=True)
        params_out: List[Tuple[str, str]] = []
        raw_params = f.get('parameters')
        if isinstance(raw_params, list):
            for idx, p in enumerate(raw_params):
                if not isinstance(p, dict):
                    continue
                p_name = p.get('name')
                if not isinstance(p_name, str) or not p_name:
                    p_name = f'arg{idx + 1}'
                p_type = p.get('data_type')
                p_java = _ghidra_type_to_java(p_type if isinstance(p_type, str) else None, is_return=False)
                params_out.append((p_java, _sanitize_java_identifier(p_name)))
        sig = (ret_java, params_out)
        sig_by_raw[raw_name] = sig
        sig_by_sanitized[_sanitize_java_identifier(raw_name)] = sig
    method_items: List[Tuple[str, str]] = []
    if exports:
        for e in exports[:max_functions]:
            method_items.append((e, _sanitize_java_identifier(e)))
    elif ghidra_funcs:
        for f in ghidra_funcs[:max_functions]:
            raw_name = f.get('name')
            if isinstance(raw_name, str) and raw_name:
                method_items.append((raw_name, _sanitize_java_identifier(raw_name)))
    elif blocks:
        for name, _block in blocks[:max_functions]:
            method_items.append((name, _sanitize_java_identifier(name)))
    else:
        method_items = [('placeholder', 'placeholder')]
    used_method_names = set()
    uniq_items: List[Tuple[str, str]] = []
    for raw_name, method_name in method_items:
        base = method_name
        if base in used_method_names:
            suffix = 2
            while f'{base}_{suffix}' in used_method_names:
                suffix += 1
            method_name = f'{base}_{suffix}'
        used_method_names.add(method_name)
        uniq_items.append((raw_name, method_name))
    return {'pseudo_c_text': pseudo_c_text, 'by_name': by_name, 'ghidra_funcs': ghidra_funcs, 'jar_meta': jar_meta, 'jni_hints': jni_hints, 'flat_hints': flat_hints, 'recovery_strategy': recovery_strategy, 'jar_index': jar_index, 'helper_blocks': helper_blocks, 'sig_by_raw': sig_by_raw, 'sig_by_sanitized': sig_by_sanitized, 'method_items': uniq_items, 'class_ident': _sanitize_java_identifier(class_name), 'extra_seed_strings': extra_seed_strings}
