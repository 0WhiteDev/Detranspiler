import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import lief
except Exception:
    lief = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')

def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')

def detect_format(path: Path) -> str:
    with path.open('rb') as f:
        head = f.read(8)
    if head.startswith(b'MZ'):
        return 'PE'
    if head.startswith(b'\x7fELF'):
        return 'ELF'
    if head[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        return 'MACHO'
    return 'UNKNOWN'

def extract_ascii_strings(path: Path, *, max_bytes: int=64 * 1024 * 1024, min_len: int=4, limit: int=5000) -> List[str]:
    size = path.stat().st_size
    to_read = min(size, max_bytes)
    with path.open('rb') as f:
        data = f.read(to_read)
    out: List[str] = []
    buf = bytearray()

    def flush() -> None:
        nonlocal buf
        if len(buf) >= min_len:
            out.append(buf.decode('ascii', errors='ignore'))
        buf = bytearray()

    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
            if len(out) >= limit:
                break
        else:
            flush()
            if len(out) >= limit:
                break
    if len(out) < limit:
        flush()
    return out

def _function_name(value: Any) -> str:
    for attr in ('demangled_name', 'name'):
        if hasattr(value, attr):
            try:
                v = getattr(value, attr)
            except Exception:
                v = None
            if v:
                return str(v)
    return str(value)

def _list_function_names(values: Any, *, limit: int=20000) -> List[str]:
    if values is None:
        return []
    out: List[str] = []
    try:
        it: Iterable[Any] = values
        for v in it:
            if v is None:
                continue
            out.append(_function_name(v))
            if len(out) >= limit:
                break
    except Exception:
        return []
    uniq: List[str] = []
    seen = set()
    for s in out:
        if s not in seen:
            uniq.append(s)
            seen.add(s)
    return uniq

def lief_parse(path: Path) -> Tuple[Optional[Dict[str, Any]], List[str], List[str]]:
    if lief is None:
        return None, [], []
    try:
        binary = lief.parse(str(path))
    except Exception:
        return None, [], []
    if binary is None:
        return None, [], []
    meta: Dict[str, Any] = {'type': type(binary).__name__}
    header = getattr(binary, 'header', None)
    if header is not None:
        meta['header_type'] = type(header).__name__
        for attr in ('machine_type', 'machine', 'cpu_type', 'endianness'):
            try:
                v = getattr(header, attr)
            except Exception:
                v = None
            if v is not None:
                meta[attr] = str(v)
    exports = _list_function_names(getattr(binary, 'exported_functions', None))
    imports = _list_function_names(getattr(binary, 'imported_functions', None))
    return meta, exports, imports

def detect_jni_indicators(exports: List[str], imports: List[str], strings: List[str]) -> Tuple[bool, List[str]]:
    strong_needles = ['JNI_OnLoad', 'JNI_OnUnload', 'RegisterNatives', 'JNINativeInterface', 'JNIEnv', 'Java_', 'JNI_CreateJavaVM', 'JNI_GetCreatedJavaVMs', 'JNI_GetDefaultJavaVMInitArgs', 'libjvm', 'jvm.dll']
    weak_needles = ['NewStringUTF', 'GetStringUTFChars', 'ReleaseStringUTFChars', 'CallObjectMethod', 'CallStaticObjectMethod', 'FindClass', 'GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID', 'ExceptionCheck', 'ExceptionDescribe']
    hits: List[str] = []
    weak_hits = 0
    strong_hit = False

    def scan(values: List[str]) -> None:
        nonlocal weak_hits, strong_hit
        for v in values:
            for n in strong_needles:
                if n in v:
                    hits.append(v)
                    strong_hit = True
                    break
            else:
                for n in weak_needles:
                    if n in v:
                        hits.append(v)
                        weak_hits += 1
                        break

    scan(exports)
    scan(imports)
    scan(strings)
    uniq: List[str] = []
    seen = set()
    for h in hits:
        if h not in seen:
            uniq.append(h)
            seen.add(h)
        if len(uniq) >= 100:
            break
    detected = strong_hit or weak_hits >= 2
    return detected, uniq

def resolve_mode(requested_mode: str, jni_detected: bool) -> str:
    if requested_mode != 'AUTO':
        return requested_mode
    if jni_detected:
        return 'JNI'
    return 'GENERIC_NATIVE'

def sanitize_java_identifier(name: str) -> str:
    out: List[str] = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '$'):
            out.append(ch)
        else:
            out.append('_')
    ident = ''.join(out)
    if not ident:
        ident = '_'
    first = ident[0]
    if not (first.isalpha() or first in ('_', '$')):
        ident = '_' + ident
    return ident

def generate_jni_stubs(exports: List[str], out_path: Path, *, limit: int=2000) -> None:
    methods: List[str] = []
    for e in exports:
        if 'Java_' in e or e in ('JNI_OnLoad', 'JNI_OnUnload'):
            methods.append(sanitize_java_identifier(e))
            if len(methods) >= limit:
                break
    if not methods:
        methods = ['placeholder']
    lines: List[str] = ['public final class NativeStubs {', '  private NativeStubs() {}', '']
    for m in methods:
        lines.append(f'  public static native void {m}();')
    lines.append('}')
    write_text(out_path, '\n'.join(lines) + '\n')
