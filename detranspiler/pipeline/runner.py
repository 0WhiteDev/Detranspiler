import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from detranspiler.pipeline.progress import ProgressCallback, emit_progress
from detranspiler.pipeline.util import (
    detect_format,
    detect_jni_indicators,
    extract_ascii_strings,
    generate_jni_stubs,
    lief_parse,
    resolve_mode,
    sha256_file,
    utc_now_iso,
    write_json,
)

def run_pipeline(*, input_path: Path, out_dir: Path, requested_mode: str='AUTO', use_ghidra: bool=True, ghidra_install_dir: Optional[Path]=None, external_pseudo_c_path: Optional[Path]=None, external_functions_json_path: Optional[Path]=None, external_strings_json_path: Optional[Path]=None, jar_path: Optional[Path]=None, force: bool=False, decompile_jar: bool=True, progress_callback: Optional[ProgressCallback]=None) -> Dict[str, Any]:
    global strings_json_path
    emit_progress(progress_callback, phase='init', percent=2, message='Initializing analysis workspace…')
    input_path = input_path.expanduser()
    if not input_path.is_file():
        raise FileNotFoundError(str(input_path))
    out_dir = out_dir.expanduser()
    if out_dir.exists():
        if force:
            shutil.rmtree(out_dir)
        else:
            raise FileExistsError(str(out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir = out_dir / 'metadata'
    preprocess_dir = out_dir / 'preprocess'
    ghidra_dir = out_dir / 'ghidra'
    pseudo_c_dir = out_dir / 'pseudo_c'
    pseudocode_dir = out_dir / 'pseudocode'
    analysis_dir = out_dir / 'analysis'
    logs_dir = out_dir / 'logs'
    for d in (metadata_dir, preprocess_dir, ghidra_dir, pseudo_c_dir, pseudocode_dir, analysis_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)
    copied_input = preprocess_dir / input_path.name
    shutil.copy2(input_path, copied_input)
    sha256 = sha256_file(input_path)
    fmt = detect_format(input_path)
    strings = extract_ascii_strings(input_path)
    lief_meta, exports, imports = lief_parse(input_path)
    jni_detected, jni_hits = detect_jni_indicators(exports, imports, strings)
    resolved_mode = resolve_mode(requested_mode, jni_detected)
    ghidra_enabled = bool(use_ghidra and ghidra_install_dir)
    if not use_ghidra:
        ghidra_state = 'SKIPPED'
    elif ghidra_install_dir is None:
        ghidra_state = 'SKIPPED_NO_INSTALL_DIR'
    else:
        ghidra_state = 'ENABLED'
    ghidra_status: Dict[str, Any] = {'requested': bool(use_ghidra), 'install_dir': str(ghidra_install_dir) if ghidra_install_dir else None, 'enabled': ghidra_enabled, 'state': ghidra_state, 'run': None, 'output_c_path': None, 'output_functions_json_path': None, 'output_strings_json_path': None}
    project_dir: Optional[Path] = None
    project_name: Optional[str] = None
    write_json(ghidra_dir / 'status.json', ghidra_status)
    job_id = str(uuid.uuid4())
    job: Dict[str, Any] = {'job_id': job_id, 'created_at': utc_now_iso(), 'input': {'path': str(input_path.resolve()), 'name': input_path.name, 'size': input_path.stat().st_size, 'sha256': sha256, 'format': fmt}, 'mode': {'requested': requested_mode, 'resolved': resolved_mode}, 'analysis': {'lief': lief_meta, 'exports_count': len(exports), 'imports_count': len(imports), 'strings_count': len(strings)}, 'jni': {'detected': jni_detected, 'hits': jni_hits}, 'ghidra': ghidra_status, 'artifacts': {'out_dir': str(out_dir.resolve()), 'job_json': str((out_dir / 'job.json').resolve()), 'metadata_dir': str(metadata_dir.resolve()), 'preprocess_dir': str(preprocess_dir.resolve()), 'ghidra_dir': str(ghidra_dir.resolve()), 'pseudo_c_dir': str(pseudo_c_dir.resolve()), 'pseudocode_dir': str(pseudocode_dir.resolve()), 'analysis_dir': str(analysis_dir.resolve()), 'logs_dir': str(logs_dir.resolve()), 'pseudo_c_file': None, 'ghidra_functions_json': None, 'ghidra_strings_json': None, 'jni_register_json': None, 'jni_calls_json': None, 'deobfuscation_json': None, 'java_like_file': None, 'jni_export_sources_dir': None, 'jni_export_manifest': None, 'report_html': None, 'jni_stubs_file': None, 'jar_decompile_dir': None}}
    write_json(out_dir / 'job.json', job)
    write_json(metadata_dir / 'binary.json', job['input'])
    write_json(metadata_dir / 'exports.json', {'exports': exports})
    write_json(metadata_dir / 'imports.json', {'imports': imports})
    write_json(metadata_dir / 'strings.json', {'strings': strings})
    write_json(metadata_dir / 'jni.json', job['jni'])
    emit_progress(progress_callback, phase='metadata', percent=12, message=f'Binary parsed ({fmt}, {len(exports)} exports)')
    if ghidra_enabled:
        output_c_path = pseudo_c_dir / 'decompiled.c'
        output_functions_json_path = ghidra_dir / 'functions.json'
        output_strings_json_path = ghidra_dir / 'strings.json'
        project_dir = ghidra_dir / 'project'
        project_name = f"detranspiler_{job_id.replace('-', '')}"
        emit_progress(progress_callback, phase='ghidra', percent=18, message='Running Ghidra headless decompilation (this may take several minutes)…')
        try:
            from detranspiler.ghidra.headless import run_headless_decompile
            res = run_headless_decompile(ghidra_install_dir=ghidra_install_dir, binary_path=copied_input, project_dir=project_dir, project_name=project_name, output_c_path=output_c_path, output_functions_json_path=output_functions_json_path, output_strings_json_path=output_strings_json_path, logs_dir=logs_dir)
            ghidra_status = {**ghidra_status, 'run': res, 'output_c_path': res.get('output_c_path'), 'output_functions_json_path': res.get('output_functions_json_path'), 'output_strings_json_path': res.get('output_strings_json_path')}
            job['ghidra'] = ghidra_status
            job['artifacts']['pseudo_c_file'] = res.get('output_c_path')
            job['artifacts']['ghidra_functions_json'] = res.get('output_functions_json_path')
            job['artifacts']['ghidra_strings_json'] = res.get('output_strings_json_path')
        except Exception as e:
            ghidra_status = {**ghidra_status, 'run': {'status': 'EXCEPTION', 'error': repr(e)}}
            job['ghidra'] = ghidra_status
        write_json(ghidra_dir / 'status.json', ghidra_status)
        write_json(metadata_dir / 'ghidra.json', ghidra_status)
        write_json(out_dir / 'job.json', job)
        emit_progress(progress_callback, phase='ghidra', percent=45, message='Ghidra decompilation finished')
    if job['artifacts'].get('pseudo_c_file') is None and external_pseudo_c_path is not None:
        try:
            p = external_pseudo_c_path.expanduser().resolve()
            if p.is_file():
                job['artifacts']['pseudo_c_file'] = str(p)
        except Exception:
            pass
    if job['artifacts'].get('ghidra_functions_json') is None and external_functions_json_path is not None:
        try:
            p = external_functions_json_path.expanduser().resolve()
            if p.is_file():
                job['artifacts']['ghidra_functions_json'] = str(p)
        except Exception:
            pass
    if job['artifacts'].get('ghidra_strings_json') is None and external_strings_json_path is not None:
        try:
            p = external_strings_json_path.expanduser().resolve()
            if p.is_file():
                job['artifacts']['ghidra_strings_json'] = str(p)
        except Exception:
            pass
    if resolved_mode == 'JNI':
        jni_stubs_path = pseudocode_dir / 'jni_stubs.java'
        generate_jni_stubs(exports, jni_stubs_path)
        job['artifacts']['jni_stubs_file'] = str(jni_stubs_path.resolve())
    pseudo_c_path = None
    if job['artifacts'].get('pseudo_c_file'):
        try:
            pseudo_c_path = Path(str(job['artifacts']['pseudo_c_file']))
        except Exception:
            pseudo_c_path = None
    functions_json_path = None
    if job['artifacts'].get('ghidra_functions_json'):
        try:
            functions_json_path = Path(str(job['artifacts']['ghidra_functions_json']))
        except Exception:
            functions_json_path = None
    patterns_res: Dict[str, Any]
    pseudo_c_text: Optional[str] = None
    emit_progress(progress_callback, phase='patterns', percent=50, message='Scanning native patterns and CFG…')
    try:
        from detranspiler.binary.patterns import scan_patterns
        if pseudo_c_path is not None and pseudo_c_path.is_file():
            pseudo_c_text = pseudo_c_path.read_text(encoding='utf-8', errors='replace')
        scan_text = pseudo_c_text[:1000000] if isinstance(pseudo_c_text, str) else None
        patterns_res = scan_patterns(exports=exports, imports=imports, strings=strings, pseudo_c=scan_text)
    except Exception as e:
        patterns_res = {'status': 'EXCEPTION', 'error': repr(e)}
    jnic_patterns_res: Dict[str, Any]
    jnic_patterns_path = analysis_dir / 'jnic_patterns.json'
    try:
        from detranspiler.deobfuscation.jnic import analyze_jnic_patterns
        jnic_patterns_res = analyze_jnic_patterns(pseudo_c_path=pseudo_c_path, pseudo_c=pseudo_c_text, exports=exports, strings=strings)
    except Exception as e:
        jnic_patterns_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(jnic_patterns_path, jnic_patterns_res)
    job['artifacts']['jnic_patterns_json'] = str(jnic_patterns_path.resolve())
    cfg_res: Dict[str, Any]
    try:
        from detranspiler.binary.cfg import build_cfg
        cfg_res = build_cfg(binary_path=copied_input)
    except Exception as e:
        cfg_res = {'status': 'EXCEPTION', 'error': repr(e)}
    jni_register_res: Dict[str, Any]
    jni_register_path = analysis_dir / 'jni_register.json'
    try:
        from detranspiler.jni.register import extract_jni_register
        strings_json_path = None
        if job['artifacts'].get('ghidra_strings_json'):
            try:
                strings_json_path = Path(str(job['artifacts']['ghidra_strings_json']))
            except Exception:
                strings_json_path = None
        jni_register_res = extract_jni_register(pseudo_c_path=pseudo_c_path, strings_json_path=strings_json_path, binary_path=copied_input, binary_fmt=fmt)
    except Exception as e:
        jni_register_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(jni_register_path, jni_register_res)
    job['artifacts']['jni_register_json'] = str(jni_register_path.resolve())
    jnic_keystream_res: Dict[str, Any] = {'status': 'SKIPPED'}
    jnic_keystream_bytes: Optional[bytes] = None
    if isinstance(jnic_patterns_res, dict) and jnic_patterns_res.get('transpiler_guess') == 'JNIC':
        try:
            from detranspiler.deobfuscation.jnic_keystream import build_jnic_keystream
            from detranspiler.deobfuscation.jnic_register import enrich_jnic_register_calls
            from detranspiler.java.gen.pe_context import build_pe_context
            strings_by_addr: Dict[int, str] = {}
            if strings_json_path is not None and strings_json_path.is_file():
                try:
                    strings_doc = json.loads(strings_json_path.read_text(encoding='utf-8'))
                    for item in strings_doc.get('strings') or []:
                        if not isinstance(item, dict):
                            continue
                        addr_raw = item.get('address')
                        val = item.get('value')
                        if isinstance(addr_raw, str) and isinstance(val, str):
                            strings_by_addr[int(addr_raw, 16)] = val
                except Exception:
                    strings_by_addr = {}
            pe_ctx = build_pe_context(pseudo_c_text=pseudo_c_text, pseudo_c_path=pseudo_c_path, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, binary_path=copied_input if copied_input.is_file() else None, extra_seed_strings=[], jar_meta={})
            jnic_keystream_res = build_jnic_keystream(pseudo_c=pseudo_c_text, binary_path=copied_input if copied_input.is_file() else None, read_u64_at_va=pe_ctx.get('read_u64_at_va'), strings_by_addr=strings_by_addr or None, jar_path=jar_path)
            if isinstance(jnic_keystream_res, dict) and jnic_keystream_res.get('keystream'):
                jnic_keystream_bytes = bytes(jnic_keystream_res['keystream'])
                jni_register_res = enrich_jnic_register_calls(jni_register_res if isinstance(jni_register_res, dict) else None, pseudo_c=pseudo_c_text, keystream=jnic_keystream_res.get('keystream'), read_u64_at_va=pe_ctx.get('read_u64_at_va'))
                write_json(jni_register_path, jni_register_res)
                jnic_keystream_res = {k: v for k, v in jnic_keystream_res.items() if k != 'keystream'}
                jnic_keystream_res['status'] = 'OK'
        except Exception as e:
            jnic_keystream_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['jnic_keystream'] = jnic_keystream_res
    jnic_dispatch_res: Dict[str, Any] = {'status': 'SKIPPED'}
    jnic_instruction_aliases: Dict[str, str] = {}
    if jnic_keystream_bytes and ghidra_enabled and project_dir is not None and project_name is not None and pseudo_c_path is not None:
        try:
            from detranspiler.deobfuscation.jnic_dispatch import merge_dispatch_pseudoc, resolve_jnic_dispatch_targets, write_dispatch_targets
            from detranspiler.ghidra.headless import run_headless_decompile_targets, run_headless_export_functions
            seen_targets: set[tuple[str, str]] = set()
            all_targets: List[Dict[str, Any]] = []
            dispatch_runs: List[Dict[str, Any]] = []
            recovered_count = 0
            last_targets_c_path: Optional[Path] = None
            max_dispatch_iterations = 10
            registered_method_count = sum(
                len(call.get('methods') or [])
                for call in (jni_register_res or {}).get('register_calls', [])
                if isinstance(call, dict)
            )
            max_dispatch_targets = min(1536, max(512, registered_method_count * 16))
            for iteration in range(max_dispatch_iterations):
                discovered = resolve_jnic_dispatch_targets(pseudo_c=pseudo_c_text or '', binary_path=copied_input, keystream=jnic_keystream_bytes, jni_register=jni_register_res)
                targets = [item for item in discovered if (str(item.get('function')), str(item.get('target'))) not in seen_targets]
                targets = targets[:max(0, max_dispatch_targets - len(seen_targets))]
                if not targets:
                    break
                for item in targets:
                    seen_targets.add((str(item.get('function')), str(item.get('target'))))
                all_targets.extend(targets)
                iteration_targets_path = analysis_dir / f'jnic_dispatch_targets_{iteration + 1}.txt'
                targets_c_path = pseudo_c_dir / f'jnic_dispatch_targets_{iteration + 1}.c'
                last_targets_c_path = targets_c_path
                write_dispatch_targets(iteration_targets_path, targets)
                target_run = run_headless_decompile_targets(ghidra_install_dir=ghidra_install_dir, project_dir=project_dir, project_name=project_name, program_name=copied_input.name, targets_path=iteration_targets_path, output_c_path=targets_c_path, logs_dir=logs_dir)
                dispatch_runs.append(target_run)
                recovered_text = targets_c_path.read_text(encoding='utf-8', errors='replace') if targets_c_path.is_file() else ''
                iteration_count = recovered_text.count('/* FUNCTION ')
                recovered_count += iteration_count
                if not iteration_count:
                    break
                pseudo_c_text = merge_dispatch_pseudoc(pseudo_c_text or '', recovered_text)
                pseudo_c_path.write_text(pseudo_c_text, encoding='utf-8', errors='replace')
                if len(seen_targets) >= max_dispatch_targets:
                    break
            targets_path = analysis_dir / 'jnic_dispatch_targets.txt'
            write_dispatch_targets(targets_path, all_targets)
            jnic_instruction_aliases = {
                str(item.get('target') or '').lower().removeprefix('0x'): str(item.get('function'))
                for item in all_targets if item.get('target') and item.get('function')
            }
            functions_refresh = None
            if all_targets and functions_json_path is not None:
                functions_refresh = run_headless_export_functions(ghidra_install_dir=ghidra_install_dir, project_dir=project_dir, project_name=project_name, program_name=copied_input.name, output_functions_json_path=functions_json_path, logs_dir=logs_dir)
            dispatch_status = 'OK' if dispatch_runs and all(run.get('status') == 'OK' for run in dispatch_runs) else 'ERROR' if dispatch_runs else 'SKIPPED'
            jnic_dispatch_res = {
                'status': dispatch_status,
                'targets_total': len(all_targets),
                'targets_decompiled': recovered_count,
                'target_limit': max_dispatch_targets,
                'limit_reached': len(seen_targets) >= max_dispatch_targets,
                'iterations': len(dispatch_runs),
                'runs': dispatch_runs,
                'functions_refresh': functions_refresh,
            }
            job['artifacts']['jnic_dispatch_targets'] = str(targets_path.resolve())
            if last_targets_c_path is not None:
                job['artifacts']['jnic_dispatch_pseudo_c'] = str(last_targets_c_path.resolve())
        except Exception as error:
            jnic_dispatch_res = {'status': 'EXCEPTION', 'error': repr(error)}
    job['analysis']['jnic_dispatch'] = jnic_dispatch_res
    jni_calls_res: Dict[str, Any]
    jni_calls_path = analysis_dir / 'jni_calls.json'
    try:
        from detranspiler.jni.calls import extract_jni_calls
        jni_calls_res = extract_jni_calls(pseudo_c_path=pseudo_c_path, strings_json_path=strings_json_path if strings_json_path is not None and strings_json_path.is_file() else None, binary_path=copied_input if copied_input.is_file() else None)
        if isinstance(jnic_patterns_res, dict) and jnic_patterns_res.get('transpiler_guess') == 'JNIC':
            from detranspiler.deobfuscation.jnic_instructions import augment_jni_calls_from_instructions
            from detranspiler.deobfuscation.jnic_locals import enrich_jni_calls_with_local_strings
            jni_calls_res = augment_jni_calls_from_instructions(jni_calls_res, functions_json_path=functions_json_path, function_aliases=jnic_instruction_aliases)
            read_u64_at_va = pe_ctx.get('read_u64_at_va') if isinstance(pe_ctx, dict) else None
            if callable(read_u64_at_va):
                jni_calls_res = enrich_jni_calls_with_local_strings(jni_calls_res, pseudo_c=pseudo_c_text, read_u64_at_va=read_u64_at_va, keystream=jnic_keystream_bytes)
    except Exception as e:
        jni_calls_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(jni_calls_path, jni_calls_res)
    job['artifacts']['jni_calls_json'] = str(jni_calls_path.resolve())
    string_decrypt_res: Dict[str, Any]
    string_decrypt_path = analysis_dir / 'string_decrypt.json'
    decrypted_seed_strings: List[str] = []
    try:
        from detranspiler.native.strings.decrypt import extract_decrypted_strings
        string_decrypt_res = extract_decrypted_strings(pseudo_c_path=pseudo_c_path)
        from detranspiler.native.strings.resolver import build_string_symbol_map, seeds_from_string_decrypt
        decrypted_seed_strings = seeds_from_string_decrypt(string_decrypt=string_decrypt_res if isinstance(string_decrypt_res, dict) else None)
        string_symbol_map = build_string_symbol_map(string_decrypt=string_decrypt_res if isinstance(string_decrypt_res, dict) else None)
    except Exception as e:
        string_decrypt_res = {'status': 'EXCEPTION', 'error': repr(e)}
        string_symbol_map = {}
    write_json(string_decrypt_path, string_decrypt_res)
    job['artifacts']['string_decrypt_json'] = str(string_decrypt_path.resolve())
    if string_symbol_map:
        write_json(analysis_dir / 'string_symbol_map.json', {'symbols': string_symbol_map})
        job['artifacts']['string_symbol_map_json'] = str((analysis_dir / 'string_symbol_map.json').resolve())
    callgraph_res: Dict[str, Any]
    callgraph_path = analysis_dir / 'callgraph.json'
    try:
        from detranspiler.binary.callgraph import analyze_callgraph
        callgraph_res = analyze_callgraph(functions_json_path=functions_json_path, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, cfg=cfg_res if isinstance(cfg_res, dict) else None)
    except Exception as e:
        callgraph_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(callgraph_path, callgraph_res)
    job['artifacts']['callgraph_json'] = str(callgraph_path.resolve())
    flattening_res: Dict[str, Any]
    flattening_path = analysis_dir / 'flattening.json'
    try:
        from detranspiler.native.flattening import analyze_flattening
        flattening_res = analyze_flattening(pseudo_c_path=pseudo_c_path)
    except Exception as e:
        flattening_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(flattening_path, flattening_res)
    job['artifacts']['flattening_json'] = str(flattening_path.resolve())
    anti_analysis_res: Dict[str, Any]
    anti_analysis_path = analysis_dir / 'anti_analysis.json'
    try:
        from detranspiler.deobfuscation.anti_analysis import analyze_anti_analysis
        anti_analysis_res = analyze_anti_analysis(pseudo_c_path=pseudo_c_path, imports=imports, strings=strings)
    except Exception as e:
        anti_analysis_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(anti_analysis_path, anti_analysis_res)
    job['artifacts']['anti_analysis_json'] = str(anti_analysis_path.resolve())
    deobfuscation_res: Dict[str, Any]
    deobfuscation_path = analysis_dir / 'deobfuscation.json'
    try:
        from detranspiler.deobfuscation.analysis import analyze_deobfuscation
        deobfuscation_res = analyze_deobfuscation(pseudo_c_path=pseudo_c_path, imports=imports, strings=strings, decrypted_strings=decrypted_seed_strings or None)
    except Exception as e:
        deobfuscation_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(deobfuscation_path, deobfuscation_res)
    job['artifacts']['deobfuscation_json'] = str(deobfuscation_path.resolve())
    jar_decompile_res: Dict[str, Any] = {'status': 'SKIPPED'}
    if jar_path is not None and decompile_jar:
        try:
            from detranspiler.jar.decompiler import decompile_jar_with_cfr
            jar_decompile_res = decompile_jar_with_cfr(jar_path=jar_path, out_dir=pseudocode_dir / 'jar_sources', cache_dir=out_dir / '.tools')
            if jar_decompile_res.get('output_dir'):
                job['artifacts']['jar_decompile_dir'] = jar_decompile_res.get('output_dir')
        except Exception as e:
            jar_decompile_res = {'status': 'EXCEPTION', 'error': repr(e)}
    recovery_strategy_res: Dict[str, Any]
    try:
        from detranspiler.recovery.strategy import build_recovery_strategy
        recovery_strategy_res = build_recovery_strategy(deobfuscation=deobfuscation_res if isinstance(deobfuscation_res, dict) else None, flattening=flattening_res if isinstance(flattening_res, dict) else None, string_decrypt=string_decrypt_res if isinstance(string_decrypt_res, dict) else None)
    except Exception as e:
        recovery_strategy_res = {'status': 'EXCEPTION', 'error': repr(e)}
    java_like_res: Dict[str, Any]
    java_like_path = pseudocode_dir / 'NativeDecompiled.java'
    emit_progress(progress_callback, phase='java', percent=58, message='Recovering Java-like sources from native code…')
    try:
        from detranspiler.java.generate import generate_java_like
        java_like_res = generate_java_like(exports=exports, pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, out_path=java_like_path, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, jni_calls=jni_calls_res if isinstance(jni_calls_res, dict) else None, jar_path=jar_path, binary_path=copied_input, callgraph=callgraph_res if isinstance(callgraph_res, dict) else None, extra_seed_strings=decrypted_seed_strings or None, flattening=flattening_res if isinstance(flattening_res, dict) else None, anti_analysis=anti_analysis_res if isinstance(anti_analysis_res, dict) else None, jar_sources_dir=pseudocode_dir / 'jar_sources' if (pseudocode_dir / 'jar_sources').is_dir() else None, deobfuscation=deobfuscation_res if isinstance(deobfuscation_res, dict) else None, string_decrypt=string_decrypt_res if isinstance(string_decrypt_res, dict) else None, string_symbol_map=string_symbol_map if string_symbol_map else None)
        if java_like_res.get('output_path'):
            job['artifacts']['java_like_file'] = str(java_like_path.resolve())
        if java_like_res.get('jni_export_sources_dir'):
            job['artifacts']['jni_export_sources_dir'] = java_like_res.get('jni_export_sources_dir')
        if java_like_res.get('jni_export_manifest'):
            job['artifacts']['jni_export_manifest'] = java_like_res.get('jni_export_manifest')
    except Exception as e:
        java_like_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['patterns'] = patterns_res
    job['analysis']['jnic_patterns'] = jnic_patterns_res
    job['analysis']['cfg'] = cfg_res
    job['analysis']['java_like'] = java_like_res
    job['analysis']['jni_register'] = jni_register_res
    job['analysis']['jni_calls'] = jni_calls_res
    job['analysis']['deobfuscation'] = deobfuscation_res
    job['analysis']['jar_decompile'] = jar_decompile_res
    job['analysis']['string_decrypt'] = string_decrypt_res
    job['analysis']['callgraph'] = callgraph_res
    job['analysis']['flattening'] = flattening_res
    job['analysis']['anti_analysis'] = anti_analysis_res
    job['analysis']['recovery_strategy'] = recovery_strategy_res
    emit_progress(progress_callback, phase='java', percent=68, message='Java recovery stage complete')
    native_index_res: Dict[str, Any]
    native_index_path = analysis_dir / 'native_index.json'
    try:
        from detranspiler.jar.scan import _jar_scan_classes
        from detranspiler.native.index import augment_native_index_from_java_sources, augment_native_index_with_jni_register, build_native_method_index
        jar_meta = _jar_scan_classes(jar_path) if jar_path is not None else None
        if isinstance(jar_meta, dict) and isinstance(jni_calls_res, dict) and jnic_patterns_res.get('transpiler_guess') == 'JNIC':
            from detranspiler.deobfuscation.jnic_locals import enrich_jni_calls_from_jar
            jni_calls_res = enrich_jni_calls_from_jar(jni_calls_res, jar_meta=jar_meta)
            job['analysis']['jni_calls'] = jni_calls_res
            write_json(jni_calls_path, jni_calls_res)
        if isinstance(jar_meta, dict) and isinstance(jni_register_res, dict) and jnic_patterns_res.get('transpiler_guess') == 'JNIC':
            from detranspiler.deobfuscation.jnic_register import enrich_jnic_register_from_jar
            jni_register_res = enrich_jnic_register_from_jar(jni_register_res, jar_meta=jar_meta)
            job['analysis']['jni_register'] = jni_register_res
            write_json(jni_register_path, jni_register_res)
        if jnic_keystream_bytes and isinstance(jni_calls_res, dict) and isinstance(jni_register_res, dict):
            from detranspiler.deobfuscation.jnic_patterns.constant_pool import extract_constant_pool_models
            from detranspiler.deobfuscation.jnic_patterns.string_decrypt import extract_string_decrypt_models
            decryptors = extract_string_decrypt_models(pseudo_c=pseudo_c_text or '', binary_path=copied_input, keystream=jnic_keystream_bytes, jni_register=jni_register_res)
            constant_pool_decoders = extract_constant_pool_models(pseudo_c=pseudo_c_text or '', binary_path=copied_input, keystream=jnic_keystream_bytes, jni_register=jni_register_res, functions_json_path=functions_json_path)
            if decryptors or constant_pool_decoders:
                jni_calls_res = dict(jni_calls_res)
                if decryptors:
                    jni_calls_res['jnic_string_decryptors'] = decryptors
                    jni_calls_res['jnic_string_decryptors_resolved'] = len(decryptors)
                if constant_pool_decoders:
                    jni_calls_res['jnic_constant_pool_decoders'] = constant_pool_decoders
                    jni_calls_res['jnic_constant_pool_decoders_resolved'] = len(constant_pool_decoders)
                job['analysis']['jni_calls'] = jni_calls_res
                write_json(jni_calls_path, jni_calls_res)
        native_index_res = build_native_method_index(exports=exports, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, jni_calls=jni_calls_res if isinstance(jni_calls_res, dict) else None, java_like=java_like_res if isinstance(java_like_res, dict) else None, jar_meta=jar_meta)
        jar_sources_index = pseudocode_dir / 'jar_sources'
        if jar_sources_index.is_dir():
            native_index_res = augment_native_index_from_java_sources(native_index_res, jar_sources_index)
            native_index_res = augment_native_index_with_jni_register(native_index_res, jni_register_res if isinstance(jni_register_res, dict) else None)
    except Exception as e:
        native_index_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(native_index_path, native_index_res)
    job['artifacts']['native_index_json'] = str(native_index_path.resolve())
    job['analysis']['native_index'] = native_index_res
    jar_repair_res: Dict[str, Any] = {'status': 'SKIPPED'}
    jar_sources_repair = pseudocode_dir / 'jar_sources'
    emit_progress(progress_callback, phase='repair', percent=72, message='Repairing stub methods and building native index…')
    if java_like_res.get('status') == 'OK':
        try:
            from detranspiler.jar.repair import repair_stub_methods
            jar_repair_res = repair_stub_methods(pseudocode_dir=pseudocode_dir, jar_sources_dir=jar_sources_repair if jar_sources_repair.is_dir() else None, native_index=native_index_res if isinstance(native_index_res, dict) else None, job=job)
        except Exception as e:
            jar_repair_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['jar_repair'] = jar_repair_res
    if isinstance(native_index_res, dict) and jar_repair_res.get('status') == 'OK':
        try:
            from detranspiler.native.index import augment_native_index_with_repairs
            native_index_res = augment_native_index_with_repairs(native_index_res, jar_repair_res)
            job['analysis']['native_index'] = native_index_res
            write_json(native_index_path, native_index_res)
        except Exception:
            pass
    radioegor_res: Dict[str, Any] = {'status': 'SKIPPED'}
    try:
        from detranspiler.jar.radioegor import build_radioegor_overlay_sources
        radioegor_res = build_radioegor_overlay_sources(pseudocode_dir=pseudocode_dir, native_index=native_index_res if isinstance(native_index_res, dict) else None)
    except Exception as e:
        radioegor_res = {'status': 'EXCEPTION', 'pattern': 'radioegor', 'error': repr(e)}
    job['analysis']['radioegor'] = radioegor_res
    jnic_overlay_res: Dict[str, Any] = {'status': 'SKIPPED'}
    try:
        from detranspiler.jar.jnic import build_jnic_overlay_sources
        jnic_overlay_res = build_jnic_overlay_sources(pseudocode_dir=pseudocode_dir, jar_path=jar_path, exports=exports, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, jnic_patterns=jnic_patterns_res if isinstance(jnic_patterns_res, dict) else None, native_index=native_index_res if isinstance(native_index_res, dict) else None, pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, jni_calls=jni_calls_res if isinstance(jni_calls_res, dict) else None, binary_path=copied_input if copied_input.is_file() else None, callgraph=callgraph_res if isinstance(callgraph_res, dict) else None, flattening=flattening_res if isinstance(flattening_res, dict) else None, anti_analysis=anti_analysis_res if isinstance(anti_analysis_res, dict) else None, string_decrypt=string_decrypt_res if isinstance(string_decrypt_res, dict) else None, string_symbol_map=string_symbol_map if string_symbol_map else None)
        if jnic_overlay_res.get('output_dir'):
            job['artifacts']['jnic_sources_dir'] = jnic_overlay_res.get('output_dir')
        if jnic_overlay_res.get('manifest_path'):
            job['artifacts']['jnic_manifest_json'] = jnic_overlay_res.get('manifest_path')
    except Exception as e:
        jnic_overlay_res = {'status': 'EXCEPTION', 'pattern': 'jnic', 'error': repr(e)}
    job['analysis']['jnic'] = jnic_overlay_res
    jar_native_decl_repair: Dict[str, Any] = {'status': 'SKIPPED'}
    if radioegor_res.get('status') != 'OK' and jnic_overlay_res.get('status') != 'OK':
        try:
            from detranspiler.jar.repair import repair_jar_native_declarations
            jar_native_decl_repair = repair_jar_native_declarations(pseudocode_dir=pseudocode_dir, native_index=native_index_res if isinstance(native_index_res, dict) else None, job=job, source_subdirs=('jar_sources',), in_place=True)
        except Exception as e:
            jar_native_decl_repair = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['jar_native_decl_repair'] = jar_native_decl_repair
    final_sources_res: Dict[str, Any] = {'status': 'SKIPPED'}
    try:
        from detranspiler.jar.final_sources import build_final_sources
        final_sources_res = build_final_sources(pseudocode_dir=pseudocode_dir)
        if final_sources_res.get('output_dir'):
            job['artifacts']['sources_dir'] = final_sources_res.get('output_dir')
        if final_sources_res.get('manifest_path'):
            job['artifacts']['sources_manifest_json'] = final_sources_res.get('manifest_path')
    except Exception as e:
        final_sources_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['final_sources'] = final_sources_res
    method_confidence_res: Dict[str, Any]
    method_confidence_path = analysis_dir / 'method_confidence.json'
    try:
        from detranspiler.recovery.confidence import build_method_confidence_report
        method_confidence_res = build_method_confidence_report(native_index=native_index_res if isinstance(native_index_res, dict) else None, anti_analysis=anti_analysis_res if isinstance(anti_analysis_res, dict) else None, java_like=java_like_res if isinstance(java_like_res, dict) else None, jar_repair=jar_repair_res if isinstance(jar_repair_res, dict) else None)
    except Exception as e:
        method_confidence_res = {'status': 'EXCEPTION', 'error': repr(e)}
    write_json(method_confidence_path, method_confidence_res)
    job['analysis']['method_confidence'] = method_confidence_res
    export_project_res: Dict[str, Any]
    export_project_dir = out_dir / 'recovered_project'
    try:
        from detranspiler.recovery.export import export_recovered_project
        export_project_res = export_recovered_project(pseudocode_dir=pseudocode_dir, out_dir=export_project_dir, job=job, native_index=native_index_res if isinstance(native_index_res, dict) else None, method_confidence=method_confidence_res if isinstance(method_confidence_res, dict) else None, min_confidence_level='MINIMAL')
        if export_project_res.get('output_dir'):
            job['artifacts']['recovered_project_dir'] = export_project_res.get('output_dir')
    except Exception as e:
        export_project_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['export_project'] = export_project_res
    recovery_res: Dict[str, Any]
    try:
        from detranspiler.recovery.metrics import build_recovery_summary
        recovery_res = build_recovery_summary(job=job)
    except Exception as e:
        recovery_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['recovery'] = recovery_res
    report_res: Dict[str, Any]
    report_path = analysis_dir / 'report.html'
    emit_progress(progress_callback, phase='reports', percent=88, message='Generating HTML reports and RE map…')
    try:
        from detranspiler.reporting.report import write_html_report
        report_res = write_html_report(job=job, out_path=report_path)
        if report_res.get('output_path'):
            job['artifacts']['report_html'] = str(report_path.resolve())
    except Exception as e:
        report_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['report'] = report_res
    re_map_res: Dict[str, Any]
    try:
        from detranspiler.reporting.re_map import write_re_map_from_job
        re_map_res = write_re_map_from_job(job=job, analysis_dir=analysis_dir)
        if re_map_res.get('output_path'):
            job['artifacts']['re_map_html'] = re_map_res.get('output_path')
        if re_map_res.get('json_path'):
            job['artifacts']['re_map_json'] = re_map_res.get('json_path')
    except Exception as e:
        re_map_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['re_map'] = re_map_res
    native_map_res: Dict[str, Any]
    emit_progress(progress_callback, phase='reports', percent=92, message='Mapping native methods to DLL functions…')
    try:
        from detranspiler.reporting.native_map import build_native_map
        native_map_res = build_native_map(out_dir=out_dir, pseudo_c_path=pseudo_c_path, functions_json_path=functions_json_path, native_index=native_index_res if isinstance(native_index_res, dict) else None, jni_register=jni_register_res if isinstance(jni_register_res, dict) else None, binary_name=input_path.name)
        if native_map_res.get('output_dir'):
            job['artifacts']['native_map_dir'] = native_map_res.get('output_dir')
        if native_map_res.get('readme_path'):
            job['artifacts']['native_map_readme'] = native_map_res.get('readme_path')
    except Exception as e:
        native_map_res = {'status': 'EXCEPTION', 'error': repr(e)}
    job['analysis']['native_map'] = native_map_res
    write_json(analysis_dir / 'native_map.json', native_map_res)
    write_json(analysis_dir / 'patterns.json', patterns_res)
    write_json(analysis_dir / 'jnic_patterns.json', jnic_patterns_res)
    write_json(analysis_dir / 'cfg.json', cfg_res)
    write_json(analysis_dir / 'java_like.json', java_like_res)
    if isinstance(java_like_res, dict) and java_like_res.get('method_recovery'):
        method_recovery_path = analysis_dir / 'method_recovery.json'
        method_recovery_doc = {'status': 'OK', 'methods_total': len(java_like_res.get('method_recovery') or []), 'methods': java_like_res.get('method_recovery')}
        write_json(method_recovery_path, method_recovery_doc)
        job['artifacts']['method_recovery_json'] = str(method_recovery_path.resolve())
        job['analysis']['method_recovery'] = method_recovery_doc
    write_json(analysis_dir / 'recovery.json', recovery_res)
    write_json(analysis_dir / 'jar_decompile.json', jar_decompile_res)
    write_json(analysis_dir / 'final_sources.json', final_sources_res)
    write_json(analysis_dir / 'flattening.json', flattening_res)
    write_json(analysis_dir / 'native_index.json', native_index_res)
    write_json(analysis_dir / 'method_confidence.json', method_confidence_res)
    write_json(analysis_dir / 'anti_analysis.json', anti_analysis_res)
    write_json(analysis_dir / 'jar_repair.json', jar_repair_res)
    write_json(analysis_dir / 'radioegor.json', radioegor_res)
    write_json(analysis_dir / 'jnic.json', jnic_overlay_res)
    write_json(analysis_dir / 'recovery_strategy.json', recovery_strategy_res)
    write_json(analysis_dir / 'report.json', report_res)
    write_json(out_dir / 'job.json', job)
    emit_progress(progress_callback, phase='done', percent=100, message='Analysis complete')
    return job
