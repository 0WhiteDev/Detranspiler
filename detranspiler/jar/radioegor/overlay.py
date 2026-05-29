import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from detranspiler.jar.radioegor.context import (
    _descriptor_from_decl,
    build_native_method_lookup,
)
from detranspiler.jar.radioegor.detect import _is_radioegor_native_obfuscator
from detranspiler.jar.radioegor.jni import _radioegor_native_body
from detranspiler.jar.radioegor.records import _canonicalize_records
from detranspiler.jar.radioegor.util import _NATIVE_DECL_RE, _format_body, _param_names, _translate_params
from detranspiler.jar.radioegor.validate import _meaningful_count, _radioegor_body_is_usable

def _replace_native_declarations(text: str, *, class_internal: str, recovered_body_index: Dict[str, Dict[str, Any]], native_by_class_method: Dict[tuple[str, str], Dict[str, Any]], native_by_class_descriptor: Dict[tuple[str, str], Dict[str, Any]], native_by_method_descriptor: Dict[tuple[str, str], Dict[str, Any]], native_by_method_name: Dict[str, Dict[str, Any]], pseudoc_blocks: Dict[str, str], strings_by_addr: Dict[int, str], dat_ptr_values: Dict[str, int], repair_state: Any=None, jar_class_texts: Optional[Dict[str, str]]=None) -> tuple[str, int]:
    replaced = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal replaced
        method = match.group('name')
        params_out = match.group('params').strip()
        item = recovered_body_index.get(f'{class_internal}::{method}')
        body = None
        target_params = _param_names(params_out)
        if isinstance(item, dict):
            body = item.get('body')
            if isinstance(body, list) and body:
                body = _translate_params([str(ln) for ln in body], [str(p) for p in item.get('params') or []], target_params)
            if not isinstance(body, list) or not body or (not _radioegor_body_is_usable(body)):
                body = None
        native_method = native_by_class_method.get((class_internal, method))
        desc = _descriptor_from_decl(match.group('ret'), params_out)
        if not isinstance(native_method, dict):
            if isinstance(desc, str):
                native_method = native_by_class_descriptor.get((class_internal, desc))
                if not isinstance(native_method, dict):
                    native_method = native_by_method_descriptor.get((method, desc))
        if not isinstance(native_method, dict):
            native_method = native_by_method_name.get(method)
        native_body = None
        if isinstance(native_method, dict):
            fn_symbol = native_method.get('fn_symbol')
            block = pseudoc_blocks.get(fn_symbol) if isinstance(fn_symbol, str) else None
            native_body = _radioegor_native_body(method=native_method, block=block, target_params=target_params, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, class_text=text, class_internal=class_internal, repair_state=repair_state, jar_class_texts=jar_class_texts)
        if isinstance(native_body, list) and native_body:
            if body is None or _meaningful_count(native_body) > _meaningful_count(body):
                body = native_body
        if not isinstance(body, list) or not body or (not _radioegor_body_is_usable(body)):
            return match.group(0)
        indent = match.group('indent')
        mods = re.sub('\\s+', ' ', match.group('mods')).strip()
        prefix = f"{indent}{(mods + ' ' if mods else '')}{match.group('ret').strip()} {method}({params_out})"
        replaced += 1
        return prefix + ' {\n' + _format_body(body, method_indent=indent) + '\n' + indent + '}'
    return (_NATIVE_DECL_RE.sub(repl, text), replaced)

def _strip_radioegor_scaffold(text: str) -> str:
    text = re.sub('(?s)^/\\*.*?Decompiled with CFR.*?\\*/\\s*', '', text, count=1)
    text = re.sub('(?m)^\\s*import\\s+native0(?:\\.[\\w*]+)*;\\s*\\n', '', text)
    pkg_match = re.search('(?m)^package\\s+([^;]+);', text)
    if pkg_match:
        pkg = pkg_match.group(1).strip()
        text = re.sub(f'(?m)^\\s*import\\s+{re.escape(pkg)}\\.[A-Za-z_$][A-Za-z0-9_$]*;\\s*\\n', '', text)
    text = re.sub('(?s)\\n\\s*static\\s*\\{\\s*Loader\\.registerNativesForClass\\([^;]+;\\s*Hidden0\\.special_clinit_[^;]+;\\s*\\}\\s*', '\n', text)
    text = re.sub('\\n{3,}', '\n\n', text)
    return _inject_radioegor_imports(text.strip() + '\n')

def _inject_radioegor_imports(text: str) -> str:
    imports: List[str] = []
    if 'new LinkedHashMap<>' in text and 'import java.util.LinkedHashMap;' not in text:
        imports.append('import java.util.LinkedHashMap;')
    if 'new ArrayList<>' in text and 'import java.util.ArrayList;' not in text:
        imports.append('import java.util.ArrayList;')
    if 'StandardCharsets.UTF_8' in text and 'import java.nio.charset.StandardCharsets;' not in text:
        imports.append('import java.nio.charset.StandardCharsets;')
    if not imports:
        return text
    m = re.search('(?m)^package\\s+[^;]+;\\s*$', text)
    if not m:
        return '\n'.join(imports) + '\n\n' + text
    existing = set(re.findall('(?m)^import\\s+[^;]+;', text))
    new_imports = [imp for imp in imports if imp not in existing]
    if not new_imports:
        return text
    result = text[:m.end()] + '\n\n' + '\n'.join(new_imports) + text[m.end():]
    return re.sub('\\n{3,}', '\n\n', result)

def build_radioegor_overlay_sources(*, pseudocode_dir: Path, native_index: Optional[Dict[str, Any]]=None, max_files: int=2000) -> Dict[str, Any]:
    pseudocode_dir = pseudocode_dir.expanduser().resolve()
    jar_sources_dir = pseudocode_dir / 'jar_sources'
    if not jar_sources_dir.is_dir():
        return {'status': 'SKIPPED_NO_JAR_SOURCES', 'pattern': 'radioegor'}
    if not _is_radioegor_native_obfuscator(jar_sources_dir):
        return {'status': 'SKIPPED_NOT_RADIOEGOR', 'pattern': 'radioegor'}
    from detranspiler.native.index import resolve_native_index
    job_path = pseudocode_dir.parent / 'job.json'
    job = None
    if job_path.is_file():
        try:
            import json
            job = json.loads(job_path.read_text(encoding='utf-8', errors='replace'))
        except Exception:
            job = None
    analysis_dir = pseudocode_dir.parent / 'analysis'
    native_index = resolve_native_index(job=job if isinstance(job, dict) else None, analysis_dir=analysis_dir if analysis_dir.is_dir() else None, native_index=native_index if isinstance(native_index, dict) else None)
    lookup = build_native_method_lookup(pseudocode_dir=pseudocode_dir, native_index=native_index)
    recovered_body_index = lookup['recovered_body_index']
    native_by_class_method = lookup['native_by_class_method']
    native_by_class_descriptor = lookup['native_by_class_descriptor']
    native_by_method_descriptor = lookup['native_by_method_descriptor']
    native_by_method_name = lookup['native_by_method_name']
    pseudoc_blocks = lookup['pseudoc_blocks']
    strings_by_addr = lookup['strings_by_addr']
    dat_ptr_values = lookup['dat_ptr_values']
    from detranspiler.jar.native_repair import build_repair_state_from_job
    repair_state = build_repair_state_from_job(job, pseudocode_dir=pseudocode_dir) if isinstance(job, dict) else None
    jar_class_texts: Dict[str, str] = {}
    for java_file in jar_sources_dir.rglob('*.java'):
        rel = java_file.relative_to(jar_sources_dir)
        rel_posix = str(rel).replace('\\', '/')
        if rel_posix.startswith('native0/') or not rel_posix.endswith('.java'):
            continue
        class_name = rel_posix[:-5].split('/')[-1]
        try:
            jar_class_texts[class_name] = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
    out_dir = pseudocode_dir / 'radioegor_sources'
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files_written = 0
    methods_overlaid = 0
    records_canonicalized = 0
    classes: List[str] = []
    for java_file in sorted(jar_sources_dir.rglob('*.java'))[:max_files]:
        rel = java_file.relative_to(jar_sources_dir)
        rel_posix = str(rel).replace('\\', '/')
        if rel_posix.startswith('native0/'):
            continue
        try:
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        class_internal = rel_posix[:-5] if rel_posix.endswith('.java') else rel_posix
        new_text, replaced = _replace_native_declarations(text, class_internal=class_internal, recovered_body_index=recovered_body_index, native_by_class_method=native_by_class_method, native_by_class_descriptor=native_by_class_descriptor, native_by_method_descriptor=native_by_method_descriptor, native_by_method_name=native_by_method_name, pseudoc_blocks=pseudoc_blocks, strings_by_addr=strings_by_addr, dat_ptr_values=dat_ptr_values, repair_state=repair_state, jar_class_texts=jar_class_texts)
        if replaced == 0:
            new_text = text
        new_text = _strip_radioegor_scaffold(new_text)
        record_text = _canonicalize_records(new_text)
        if record_text != new_text:
            records_canonicalized += 1
            new_text = record_text
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(new_text, encoding='utf-8')
        files_written += 1
        methods_overlaid += replaced
        classes.append(class_internal)
    return {'status': 'OK', 'pattern': 'radioegor', 'output_dir': str(out_dir.resolve()), 'files_written': files_written, 'methods_overlaid': methods_overlaid, 'records_canonicalized': records_canonicalized, 'native_patterns_available': len(pseudoc_blocks), 'strings_available': len(strings_by_addr), 'classes': classes[:500]}
