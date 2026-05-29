from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.jni_descriptors import _internal_class_to_package_and_class, _jni_method_sig_to_java
try:
    from detranspiler.jni.vtable import JNI_INDEX_NAMES
except Exception:
    JNI_INDEX_NAMES = {}
_FUNCTION_MARKER_RE = re.compile('^\\s*/\\*\\s*FUNCTION\\s+(?P<name>[A-Za-z_$][\\w$]*)\\b')
_VTABLE_OFFSET_RE = re.compile('\\*\\s*(?:param_\\w+|\\w+)\\s*\\+\\s*(0x[0-9a-fA-F]+)\\s*\\)')
_INLINE_BODY_CAP = 200

def _extract_function_blocks(pseudo_c_text: str) -> Dict[str, Dict[str, Any]]:
    lines = pseudo_c_text.splitlines()
    markers: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        m = _FUNCTION_MARKER_RE.match(line)
        if m:
            markers.append((idx, m.group('name')))
    out: Dict[str, Dict[str, Any]] = {}
    for pos, (start_idx, symbol) in enumerate(markers):
        end_idx = markers[pos + 1][0] if pos + 1 < len(markers) else len(lines)
        block_lines = lines[start_idx:end_idx]
        while block_lines and (not block_lines[-1].strip()):
            block_lines.pop()
        body = '\n'.join(block_lines)
        signature = None
        for bl in block_lines:
            if re.search(f'\\b{re.escape(symbol)}\\s*\\(', bl) and 'FUNCTION' not in bl:
                signature = bl.strip()
                break
        out.setdefault(symbol, {'start_line': start_idx + 1, 'end_line': start_idx + len(block_lines), 'signature': signature, 'body': body})
    return out

def _load_functions_meta(functions_json_path: Optional[Path]) -> Tuple[Optional[str], Optional[str], Dict[str, Dict[str, Any]]]:
    if not functions_json_path or not Path(functions_json_path).is_file():
        return None, None, {}
    try:
        data = json.loads(Path(functions_json_path).read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return None, None, {}
    program = data.get('program') if isinstance(data, dict) else None
    image_base = str(program.get('image_base')) if isinstance(program, dict) and program.get('image_base') else None
    binary_name = str(program.get('name')) if isinstance(program, dict) and program.get('name') else None
    meta: Dict[str, Dict[str, Any]] = {}
    for fn in data.get('functions') or [] if isinstance(data, dict) else []:
        if not isinstance(fn, dict):
            continue
        name = fn.get('name')
        if not isinstance(name, str):
            continue
        callees = []
        for c in fn.get('callees') or []:
            if isinstance(c, dict) and isinstance(c.get('name'), str):
                callees.append(c['name'])
        meta[name] = {'entry': fn.get('entry'), 'return_type': fn.get('return_type'), 'calling_convention': fn.get('calling_convention'), 'parameters': fn.get('parameters') or [], 'callees': callees}
    return image_base, binary_name, meta

def _address_from_symbol(symbol: Optional[str], entry: Optional[str]) -> Optional[str]:
    if isinstance(entry, str) and entry:
        return '0x' + entry.lstrip('0x').lstrip('0X') if not entry.startswith('0x') else entry
    if isinstance(symbol, str):
        m = re.search('(?:FUN_|LAB_|sub_)?([0-9a-fA-F]{6,})$', symbol)
        if m:
            return '0x' + m.group(1)
    return None

def _java_signature(method: str, descriptor: str) -> Tuple[Optional[str], List[str], str]:
    parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
    if parsed is None:
        return None, [], f'{method}(?)'
    ret, params = parsed
    display_method = {'<init>': method, '<clinit>': method}.get(method, method)
    param_str = ', '.join(params)
    if method == '<init>':
        pretty = f'<init>({param_str})'
    elif method == '<clinit>':
        pretty = '<clinit>()'
    else:
        pretty = f'{ret} {display_method}({param_str})'
    return ret, params, pretty

def _collect_native_methods(native_index: Optional[Dict[str, Any]], jni_register: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []

    def add(cls: Any, method: Any, desc: Any, fn_symbol: Any, confidence: Any, sources: Any, fn_address: Any=None) -> None:
        if not (isinstance(cls, str) and isinstance(method, str) and isinstance(desc, str) and isinstance(fn_symbol, str)):
            return
        key = (cls, method, desc, fn_symbol)
        if key in seen:
            return
        seen.add(key)
        out.append({'class_internal': cls, 'method': method, 'descriptor': desc, 'fn_symbol': fn_symbol, 'fn_address': fn_address if isinstance(fn_address, str) else None, 'confidence': confidence if isinstance(confidence, (int, float)) else None, 'sources': sources if isinstance(sources, list) else []})
    if isinstance(native_index, dict):
        for m in native_index.get('methods') or []:
            if isinstance(m, dict):
                add(m.get('class'), m.get('method'), m.get('descriptor'), m.get('fn_symbol'), m.get('confidence'), m.get('sources'))
    if isinstance(jni_register, dict):
        for call in jni_register.get('register_calls') or []:
            if not isinstance(call, dict):
                continue
            cls = call.get('class')
            for m in call.get('methods') or []:
                if isinstance(m, dict):
                    add(cls, m.get('name'), m.get('signature'), m.get('fn_symbol'), 70, ['register_natives'], m.get('fn_address'))
    return out

def _sanitize_file_component(value: str) -> str:
    value = value.replace('<', '_').replace('>', '_')
    return re.sub('[^A-Za-z0-9_.$-]', '_', value)

def _vtable_offsets_used(bodies: List[str]) -> List[Tuple[int, str]]:
    offs: set = set()
    for body in bodies:
        for m in _VTABLE_OFFSET_RE.finditer(body):
            try:
                off = int(m.group(1), 16)
            except Exception:
                continue
            if 2048 > off > 0 == off % 8:
                offs.add(off)
    named: List[Tuple[int, str]] = []
    for off in sorted(offs):
        name = JNI_INDEX_NAMES.get(off // 8)
        if name:
            named.append((off, name))
    return named

def _c_file_header(entry: Dict[str, Any]) -> str:
    return ''

def build_native_map(*, out_dir: Path, pseudo_c_path: Optional[Path], functions_json_path: Optional[Path], native_index: Optional[Dict[str, Any]]=None, jni_register: Optional[Dict[str, Any]]=None, binary_name: Optional[str]=None) -> Dict[str, Any]:
    out_dir = Path(out_dir).expanduser().resolve()
    methods = _collect_native_methods(native_index, jni_register)
    if not methods:
        return {'status': 'SKIPPED_NO_NATIVE_METHODS'}
    pseudo_c_text = ''
    if pseudo_c_path and Path(pseudo_c_path).is_file():
        try:
            pseudo_c_text = Path(pseudo_c_path).read_text(encoding='utf-8', errors='replace')
        except Exception:
            pseudo_c_text = ''
    blocks = _extract_function_blocks(pseudo_c_text) if pseudo_c_text else {}
    image_base, fn_binary_name, fn_meta = _load_functions_meta(functions_json_path)
    binary_label = binary_name or fn_binary_name or 'binary'
    map_dir = out_dir / 'native_map'
    c_dir = map_dir / 'c'
    c_dir.mkdir(parents=True, exist_ok=True)
    used_names: set = set()
    entries: List[Dict[str, Any]] = []
    for m in methods:
        cls_internal = m['class_internal']
        pkg, cls_simple = _internal_class_to_package_and_class(cls_internal)
        fqcn = (pkg + '.' if pkg else '') + cls_simple
        ret, params, pretty = _java_signature(m['method'], m['descriptor'])
        symbol = m['fn_symbol']
        block = blocks.get(symbol)
        meta = fn_meta.get(symbol, {})
        address = m.get('fn_address') or _address_from_symbol(symbol, meta.get('entry'))
        entry: Dict[str, Any] = {'package': pkg, 'class_simple': cls_simple, 'class_internal': cls_internal, 'class_fqcn': fqcn, 'method': m['method'], 'descriptor': m['descriptor'], 'java_return': ret, 'java_params': params, 'java_signature': pretty, 'fn_symbol': symbol, 'address': address, 'c_signature': (block or {}).get('signature') or _c_sig_from_meta(symbol, meta), 'calling_convention': meta.get('calling_convention'), 'callees': meta.get('callees') or [], 'confidence': m.get('confidence'), 'sources': m.get('sources') or [], 'body_found': block is not None, 'decompiled_c_lines': [block['start_line'], block['end_line']] if block else None, 'body_line_count': block['end_line'] - block['start_line'] + 1 if block else 0, 'c_file': None}
        if block is not None:
            base = _sanitize_file_component(f"{fqcn}.{m['method']}")
            fname = base + '.c'
            n = 2
            while fname in used_names:
                fname = f'{base}-{n}.c'
                n += 1
            used_names.add(fname)
            (c_dir / fname).write_text(_c_file_header(entry) + block['body'] + '\n', encoding='utf-8')
            entry['c_file'] = f'c/{fname}'
            body_lines = block['body'].splitlines()
            if len(body_lines) > _INLINE_BODY_CAP:
                entry['_body_preview'] = '\n'.join(body_lines[:_INLINE_BODY_CAP])
            else:
                entry['_body_preview'] = block['body']
        entries.append(entry)
    entries.sort(key=lambda e: (e['package'] or '', e['class_simple'], e['method'], e['descriptor']))
    offsets_used = _vtable_offsets_used([b['body'] for b in blocks.values()]) if blocks else []
    readme = _render_readme(entries=entries, binary_label=binary_label, image_base=image_base, offsets_used=offsets_used)
    readme_path = map_dir / 'README.md'
    readme_path.write_text(readme, encoding='utf-8')
    classes = sorted({e['class_internal'] for e in entries})
    public_methods = [{k: v for k, v in e.items() if not k.startswith('_')} for e in entries]
    return {'status': 'OK', 'binary': binary_label, 'image_base': image_base, 'methods_total': len(entries), 'classes_total': len(classes), 'bodies_found': sum((1 for e in entries if e['body_found'])), 'output_dir': str(map_dir), 'readme_path': str(readme_path), 'methods': public_methods}

def _c_sig_from_meta(symbol: str, meta: Dict[str, Any]) -> Optional[str]:
    if not meta:
        return None
    ret = meta.get('return_type') or 'undefined'
    params = meta.get('parameters') or []
    parts = []
    for p in params:
        if isinstance(p, dict):
            parts.append(f"{p.get('type', '?')} {p.get('name', '')}".strip())
    return f"{ret} {symbol}({', '.join(parts)})"

def _md_escape(text: str) -> str:
    return str(text).replace('|', '\\|')

def _render_readme(*, entries: List[Dict[str, Any]], binary_label: str, image_base: Optional[str], offsets_used: List[Tuple[int, str]]) -> str:
    total = len(entries)
    classes = sorted({e['class_internal'] for e in entries})
    bodies = sum((1 for e in entries if e['body_found']))
    L: List[str] = []
    L.append(f'# Native method map `{binary_label}`')
    L.append('')
    L.append('Every Java `native` method in this program was transpiled into a function inside the native binary. This section links each Java method to the exact decompiled C function that implements it, so you can read the C/C++ and reconstruct the method by hand.')
    L.append('')
    L.append('## Overview')
    L.append('')
    L.append(f'- **Binary:** `{binary_label}`' + (f" · image base `0x{image_base.lstrip('0x')}`" if image_base else ''))
    L.append(f'- **Native methods:** {total}')
    L.append(f'- **Classes:** {len(classes)}')
    L.append(f'- **With decompiled body:** {bodies} / {total}')
    L.append(f'- **Per-method C files:** [`c/`](c/)')
    L.append('')
    L.append('## How to read the C')
    L.append('')
    L.append('These functions are JNI callbacks produced by a bytecode transpiler:')
    L.append('')
    L.append('- `param_1` is the `JNIEnv*`. Real Java operations show up as vtable calls of')
    L.append('  the form `(**(code **)(*param_1 + 0xNN))(param_1, ...)` the offset `0xNN`')
    L.append('  selects the JNI function (see the legend at the bottom).')
    L.append('- `param_2` is the receiver (`this`) for instance methods, or the declaring')
    L.append('  `jclass` for static methods.')
    L.append('- `param_3`, `param_4`, … are the Java arguments in declaration order.')
    L.append('- Field reads/writes, method invokes, object allocations and string constants')
    L.append('  are the meaningful steps; everything else is interpreter/stack bookkeeping.')
    L.append('')
    by_pkg: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for e in entries:
        pkg = e['package'] or '(default package)'
        by_pkg.setdefault(pkg, {}).setdefault(e['class_simple'], []).append(e)
    L.append('## Methods by class')
    L.append('')
    for pkg in sorted(by_pkg):
        L.append(f'### package `{pkg}`')
        L.append('')
        for cls in sorted(by_pkg[pkg]):
            cls_entries = by_pkg[pkg][cls]
            L.append(f'#### `{cls}`')
            L.append('')
            L.append('| Java method | DLL function | Address | C lines | Conf. | C file |')
            L.append('| --- | --- | --- | --- | --- | --- |')
            for e in cls_entries:
                span = e['decompiled_c_lines']
                span_str = f"{span[0]}–{span[1]} ({e['body_line_count']})" if span else '-'
                cfile = f"[open]({e['c_file']})" if e['c_file'] else '_no body_'
                conf = e['confidence']
                conf_str = str(conf) if conf is not None else '-'
                L.append(f"| `{_md_escape(e['java_signature'])}` | `{_md_escape(e['fn_symbol'])}` | `{_md_escape(e['address'] or '-')}` | {span_str} | {conf_str} | {cfile} |")
            L.append('')
            for e in cls_entries:
                L.append(_render_method_details(e))
            L.append('')
    if offsets_used:
        L.append('## JNI vtable offset legend')
        L.append('')
        L.append('Offsets that actually appear in the functions above:')
        L.append('')
        L.append('| Offset | JNI function |')
        L.append('| --- | --- |')
        for off, name in offsets_used:
            L.append(f'| `0x{off:x}` | `{name}` |')
        L.append('')
    return '\n'.join(L) + '\n'

def _render_method_details(e: Dict[str, Any]) -> str:
    L: List[str] = []
    summary = f"<code>{_html_escape(e['java_signature'])}</code> &rarr; <code>{e['fn_symbol']}</code>"
    if e.get('address'):
        summary += f" @ {e['address']}"
    L.append('<details>')
    L.append(f'<summary>{summary}</summary>')
    L.append('')
    meta_bits = []
    if e.get('calling_convention'):
        meta_bits.append(f"`{e['calling_convention']}`")
    if e.get('decompiled_c_lines'):
        span = e['decompiled_c_lines']
        meta_bits.append(f'decompiled.c lines {span[0]}–{span[1]}')
    if e.get('confidence') is not None:
        meta_bits.append(f"confidence {e['confidence']} ({', '.join(e.get('sources') or []) or 'n/a'})")
    if meta_bits:
        L.append('- ' + ' · '.join(meta_bits))
    if e.get('c_signature'):
        L.append(f"- C signature: `{e['c_signature']}`")
    if e.get('callees'):
        callees = e['callees']
        shown = ', '.join((f'`{c}`' for c in callees[:20])) + (' …' if len(callees) > 20 else '')
        L.append(f'- calls: {shown}')
    if e.get('c_file'):
        L.append(f"- full C file: [`native_map/{e['c_file']}`]({e['c_file']})")
    L.append('')
    if e.get('c_file') and e.get('_body_preview'):
        L.append('```c')
        L.append(e['_body_preview'].rstrip())
        L.append('```')
    else:
        L.append('> No decompiled body was found for this function in `decompiled.c`.')
    L.append('</details>')
    L.append('')
    return '\n'.join(L)

def _html_escape(text: str) -> str:
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
