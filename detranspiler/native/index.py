from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from detranspiler.jar.body_index import _path_to_internal

from detranspiler.jar.radioegor.context import _descriptor_from_decl
from detranspiler.jar.radioegor.util import _NATIVE_DECL_RE as _JAR_NATIVE_DECL_RE


def _add_method(registry: Dict[str, Dict[str, Any]], *, class_internal: str, method: str, descriptor: Optional[str], fn_symbol: Optional[str], source: str, confidence: int) -> None:
    if not class_internal or not method:
        return
    key = f"{class_internal}::{method}::{descriptor or '?'}"
    existing = registry.get(key)
    item = {'class': class_internal, 'method': method, 'descriptor': descriptor, 'fn_symbol': fn_symbol, 'sources': [source], 'confidence': confidence}
    if existing:
        for s in item['sources']:
            if s not in existing['sources']:
                existing['sources'].append(s)
        existing['confidence'] = max(int(existing.get('confidence') or 0), confidence)
        if not existing.get('fn_symbol') and fn_symbol:
            existing['fn_symbol'] = fn_symbol
        if not existing.get('descriptor') and descriptor:
            existing['descriptor'] = descriptor
        registry[key] = existing
    else:
        registry[key] = item


def _registry_from_methods(methods: Any) -> Dict[str, Dict[str, Any]]:
    registry: Dict[str, Dict[str, Any]] = {}
    for item in methods or []:
        if not isinstance(item, dict):
            continue
        key = f"{item.get('class')}::{item.get('method')}::{item.get('descriptor') or '?'}"
        registry[key] = dict(item)
    return registry


def _dedupe_methods(methods: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_pair: Dict[tuple[str, str], Dict[str, Any]] = {}
    for item in methods:
        if not isinstance(item, dict):
            continue
        cls = str(item.get('class') or '')
        method = str(item.get('method') or '')
        if not cls or not method:
            continue
        key = (cls, method)
        existing = by_pair.get(key)
        if existing is None:
            by_pair[key] = dict(item)
            continue
        if not existing.get('fn_symbol') and item.get('fn_symbol'):
            existing['fn_symbol'] = item.get('fn_symbol')
        if not existing.get('descriptor') and item.get('descriptor'):
            existing['descriptor'] = item.get('descriptor')
        elif isinstance(existing.get('descriptor'), str) and isinstance(item.get('descriptor'), str):
            if len(item['descriptor']) > len(existing['descriptor']):
                existing['descriptor'] = item['descriptor']
        for src in item.get('sources') or []:
            sources = existing.get('sources')
            if isinstance(sources, list) and src not in sources:
                sources.append(src)
        existing['confidence'] = max(int(existing.get('confidence') or 0), int(item.get('confidence') or 0))
    return list(by_pair.values())


def _recompute_native_index_stats(native_index: Dict[str, Any]) -> Dict[str, Any]:
    methods = _dedupe_methods([m for m in native_index.get('methods') or [] if isinstance(m, dict)])
    methods.sort(key=lambda x: (-int(x.get('confidence') or 0), str(x.get('class') or ''), str(x.get('method') or '')))
    by_class: Dict[str, int] = {}
    for m in methods:
        cls = str(m.get('class') or '<unknown>')
        by_class[cls] = by_class.get(cls, 0) + 1
    native_index = dict(native_index)
    native_index['status'] = native_index.get('status') or 'OK'
    native_index['methods'] = methods[:2000]
    native_index['methods_total'] = len(methods)
    native_index['classes_total'] = len(by_class)
    native_index['by_class'] = dict(sorted(by_class.items(), key=lambda x: -x[1])[:100])
    native_index['multi_source_methods'] = sum((1 for m in methods if len(m.get('sources') or []) >= 2))
    return native_index


def augment_native_index_from_java_sources(native_index: Optional[Dict[str, Any]], sources_dir: Path, *, source: str='jar_sources', confidence: int=55) -> Dict[str, Any]:
    sources_dir = sources_dir.expanduser().resolve()
    if not sources_dir.is_dir():
        return native_index if isinstance(native_index, dict) else {'status': 'SKIPPED', 'methods': []}
    registry = _registry_from_methods((native_index or {}).get('methods'))
    for java_file in sorted(sources_dir.rglob('*.java')):
        if not java_file.is_file():
            continue
        try:
            rel = java_file.relative_to(sources_dir).as_posix()
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        class_internal = _path_to_internal(rel)
        for match in _JAR_NATIVE_DECL_RE.finditer(text):
            name = match.group('name')
            if name in {'class', 'interface', 'enum'}:
                continue
            desc = _descriptor_from_decl(match.group('ret'), match.group('params'))
            _add_method(registry, class_internal=class_internal, method=name, descriptor=desc, fn_symbol=None, source=source, confidence=confidence)
    base = dict(native_index) if isinstance(native_index, dict) else {'status': 'OK'}
    base['methods'] = list(registry.values())
    return _recompute_native_index_stats(base)


def augment_native_index_with_jni_register(native_index: Optional[Dict[str, Any]], jni_register: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(native_index, dict):
        native_index = {'status': 'SKIPPED', 'methods': []}
    if not isinstance(jni_register, dict):
        return native_index
    registry = _registry_from_methods(native_index.get('methods'))
    by_method_desc: Dict[tuple[str, str], Dict[str, Any]] = {}
    by_method: Dict[str, List[Dict[str, Any]]] = {}
    for item in registry.values():
        method = item.get('method')
        desc = item.get('descriptor')
        if isinstance(method, str) and isinstance(desc, str):
            by_method_desc[method, desc] = item
        if isinstance(method, str):
            by_method.setdefault(method, []).append(item)
    for call in jni_register.get('register_calls') or []:
        if not isinstance(call, dict):
            continue
        reg_cls = call.get('class') if isinstance(call.get('class'), str) else None
        for m in call.get('methods') or []:
            if not isinstance(m, dict):
                continue
            name = m.get('name')
            sig = m.get('signature')
            fn = m.get('fn_symbol')
            if not isinstance(name, str) or not isinstance(sig, str) or not isinstance(fn, str):
                continue
            target = by_method_desc.get((name, sig))
            if target is None and reg_cls:
                target = registry.get(f"{reg_cls}::{name}::{sig}")
            candidates = by_method.get(name) or []
            if target is None and len(candidates) == 1:
                target = candidates[0]
            if target is None:
                cls = reg_cls
                if not isinstance(cls, str) and len(candidates) == 1:
                    cls = candidates[0].get('class')
                if isinstance(cls, str):
                    _add_method(registry, class_internal=cls, method=name, descriptor=sig, fn_symbol=fn, source='register_natives', confidence=85)
                continue
            if not target.get('fn_symbol'):
                target['fn_symbol'] = fn
            sources = target.get('sources')
            if not isinstance(sources, list):
                sources = []
            if 'register_natives' not in sources:
                sources.append('register_natives')
            target['sources'] = sources
            target['confidence'] = max(int(target.get('confidence') or 0), 85)
    base = dict(native_index)
    base['methods'] = list(registry.values())
    return _recompute_native_index_stats(base)


def resolve_native_index(*, job: Optional[Dict[str, Any]]=None, analysis_dir: Optional[Path]=None, native_index: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    if native_index is None and analysis_dir is not None:
        path = analysis_dir.expanduser().resolve() / 'native_index.json'
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding='utf-8', errors='replace'))
                native_index = loaded if isinstance(loaded, dict) else None
            except Exception:
                native_index = None
    if not isinstance(native_index, dict):
        native_index = {'status': 'SKIPPED', 'methods': []}
    pseudo: Optional[str] = None
    jni_register = None
    if isinstance(job, dict):
        artifacts = job.get('artifacts') if isinstance(job.get('artifacts'), dict) else {}
        pseudo = artifacts.get('pseudocode_dir')
        analysis = job.get('analysis') if isinstance(job.get('analysis'), dict) else {}
        jni_register = analysis.get('jni_register')
    if not pseudo and analysis_dir is not None:
        candidate = analysis_dir.expanduser().resolve().parent / 'pseudocode'
        if candidate.is_dir():
            pseudo = str(candidate)
    if isinstance(pseudo, str):
        jar_src = Path(pseudo).expanduser() / 'jar_sources'
        if jar_src.is_dir():
            native_index = augment_native_index_from_java_sources(native_index, jar_src)
    if jni_register is None and analysis_dir is not None:
        reg_path = analysis_dir.expanduser().resolve() / 'jni_register.json'
        if reg_path.is_file():
            try:
                loaded = json.loads(reg_path.read_text(encoding='utf-8', errors='replace'))
                jni_register = loaded if isinstance(loaded, dict) else None
            except Exception:
                jni_register = None
    native_index = augment_native_index_with_jni_register(native_index, jni_register)
    return native_index


def augment_native_index_with_repairs(native_index: Optional[Dict[str, Any]], jar_repair: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(native_index, dict):
        return native_index or {'status': 'SKIPPED'}
    if not isinstance(jar_repair, dict) or jar_repair.get('status') != 'OK':
        return native_index
    registry = _registry_from_methods(native_index.get('methods'))
    repaired_count = 0
    for repair in jar_repair.get('repairs') or []:
        if not isinstance(repair, dict):
            continue
        cls = repair.get('class')
        method = repair.get('method')
        if not isinstance(cls, str) or not isinstance(method, str):
            continue
        desc = repair.get('descriptor')
        key = f"{cls}::{method}::{desc or '?'}"
        item = registry.get(key)
        if item is None:
            item = {'class': cls, 'method': method, 'descriptor': desc if isinstance(desc, str) else None, 'fn_symbol': None, 'sources': ['jar_repair'], 'confidence': 70}
            registry[key] = item
        else:
            sources = item.get('sources')
            if not isinstance(sources, list):
                sources = []
            if 'jar_repair' not in sources:
                sources.append('jar_repair')
            item['sources'] = sources
            item['confidence'] = max(int(item.get('confidence') or 0), 75)
        repaired_count += 1
    native_index = dict(native_index)
    native_index['methods'] = list(registry.values())
    native_index['methods_repaired'] = repaired_count
    return _recompute_native_index_stats(native_index)


def build_native_method_index(*, exports: Optional[List[str]]=None, jni_register: Optional[Dict[str, Any]]=None, jni_calls: Optional[Dict[str, Any]]=None, java_like: Optional[Dict[str, Any]]=None, jar_meta: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    del java_like
    registry: Dict[str, Dict[str, Any]] = {}
    for sym in exports or []:
        if not isinstance(sym, str) or not sym.startswith('Java_'):
            continue
        parts = sym.split('__', 1)
        prefix = parts[0][5:] if sym.startswith('Java_') else sym
        segs = prefix.split('_')
        if len(segs) < 2:
            continue
        method = segs[-1]
        cls = '/'.join(segs[:-1]).replace('_', '/')
        desc = parts[1] if len(parts) > 1 else None
        _add_method(registry, class_internal=cls, method=method, descriptor=desc, fn_symbol=sym, source='export', confidence=90)
    if isinstance(jni_register, dict):
        for call in jni_register.get('register_calls') or []:
            if not isinstance(call, dict):
                continue
            cls = call.get('class')
            if not isinstance(cls, str):
                cls = ''
            for m in call.get('methods') or []:
                if not isinstance(m, dict):
                    continue
                _add_method(registry, class_internal=cls, method=str(m.get('name') or ''), descriptor=m.get('signature') if isinstance(m.get('signature'), str) else None, fn_symbol=m.get('fn_symbol') if isinstance(m.get('fn_symbol'), str) else None, source='register_natives', confidence=85)
        for table in jni_register.get('static_method_tables') or []:
            if not isinstance(table, dict):
                continue
            cls = table.get('class')
            for m in table.get('methods') or []:
                if not isinstance(m, dict):
                    continue
                _add_method(registry, class_internal=cls if isinstance(cls, str) else '', method=str(m.get('name') or ''), descriptor=m.get('signature') if isinstance(m.get('signature'), str) else None, fn_symbol=m.get('fn_symbol') if isinstance(m.get('fn_symbol'), str) else None, source='static_jni_table', confidence=80)
    if isinstance(jni_calls, dict):
        for fn in jni_calls.get('functions') or []:
            if not isinstance(fn, dict):
                continue
            fn_sym = fn.get('function')
            for meth in fn.get('methods') or []:
                if not isinstance(meth, dict):
                    continue
                cls = meth.get('class')
                name = meth.get('method')
                if isinstance(cls, str) and isinstance(name, str):
                    _add_method(registry, class_internal=cls, method=name, descriptor=meth.get('signature') if isinstance(meth.get('signature'), str) else None, fn_symbol=fn_sym if isinstance(fn_sym, str) else None, source='jni_calls', confidence=60)
    if isinstance(jar_meta, dict):
        for cls, cm in jar_meta.items():
            if not isinstance(cm, dict):
                continue
            methods = cm.get('methods')
            if not isinstance(methods, dict):
                continue
            for (name, desc), flags in methods.items():
                if not isinstance(name, str) or not isinstance(desc, str):
                    continue
                if not isinstance(flags, int) or flags & _ACC_NATIVE == 0:
                    continue
                _add_method(registry, class_internal=cls, method=name, descriptor=desc, fn_symbol=None, source='jar_metadata', confidence=50)
    base = {'status': 'OK', 'methods': list(registry.values())}
    base = augment_native_index_with_jni_register(base, jni_register)
    return _recompute_native_index_stats(base)
