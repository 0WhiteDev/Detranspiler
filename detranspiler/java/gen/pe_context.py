import json
import re
import struct
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from detranspiler.jni.register import _infer_dat_pointer_values, _load_strings_json, _pe_read_c_string, _pe_rva_to_file_offset

def build_pe_context(*, pseudo_c_text: Optional[str], jni_register: Optional[Dict[str, Any]], binary_path: Optional[Path], extra_seed_strings: Optional[List[str]], jar_meta: Any) -> dict:
    jar_seed_strings: List[str] = []
    if isinstance(jar_meta, dict) and jar_meta:
        seen_seed = set()
        for _cls, cm in jar_meta.items():
            if not isinstance(cm, dict):
                continue
            cp = cm.get('cp')
            if not isinstance(cp, list):
                continue
            for it in cp:
                if not isinstance(it, str):
                    continue
                v = it.strip()
                if not v or v in {'out'}:
                    continue
                if re.fullmatch('[a-z0-9]{6,80}', v) is None:
                    continue
                if v in seen_seed:
                    continue
                seen_seed.add(v)
                jar_seed_strings.append(v)
                if len(jar_seed_strings) >= 256:
                    break
            if len(jar_seed_strings) >= 256:
                break
    dat_ptr_values: Dict[str, int] = {}
    if isinstance(pseudo_c_text, str) and pseudo_c_text:
        dat_ptr_values = _infer_dat_pointer_values(pseudo_c_text.splitlines())
    strings_by_addr: Dict[int, str] = {}
    image_base = 0
    if isinstance(jni_register, dict):
        sjp = jni_register.get('strings_json_path')
        if isinstance(sjp, str) and sjp:
            sjp_path = Path(sjp)
            strings_by_addr = _load_strings_json(sjp_path)
            if sjp_path.is_file():
                try:
                    sj = json.loads(sjp_path.read_text(encoding='utf-8', errors='replace'))
                    prog = sj.get('program') if isinstance(sj, dict) else None
                    if isinstance(prog, dict) and isinstance(prog.get('image_base'), str):
                        ib = str(prog.get('image_base')).strip()
                        if ib.lower().startswith('0x'):
                            ib = ib[2:]
                        ib = ib.strip()
                        if ib:
                            image_base = int(ib, 16)
                except Exception:
                    image_base = 0
    binary_data: Optional[bytes] = None
    if binary_path is not None and binary_path.is_file():
        try:
            binary_data = binary_path.read_bytes()
        except Exception:
            binary_data = None
    bin_seed_strings: List[str] = []
    if isinstance(binary_data, (bytes, bytearray)) and binary_data:
        max_bytes = min(len(binary_data), 16 * 1024 * 1024)
        buf = bytearray()
        seen_bin = set()

        def flush() -> None:
            nonlocal buf
            if len(bin_seed_strings) >= 512:
                buf = bytearray()
                return
            if len(buf) >= 6:
                try:
                    s = buf.decode('ascii', errors='ignore')
                except Exception:
                    s = ''
                s = s.strip()
                if s and re.fullmatch('[a-z0-9]{6,80}', s):
                    if s not in {'out'} and s not in seen_bin:
                        seen_bin.add(s)
                        bin_seed_strings.append(s)
            buf = bytearray()
        for b in binary_data[:max_bytes]:
            if 32 <= b <= 126:
                buf.append(b)
            else:
                flush()
                if len(bin_seed_strings) >= 512:
                    break
        flush()
    if isinstance(extra_seed_strings, list) and extra_seed_strings:
        seen_bin = set(bin_seed_strings)
        for s in extra_seed_strings:
            if not isinstance(s, str):
                continue
            v = s.strip()
            if not v or v in seen_bin:
                continue
            seen_bin.add(v)
            bin_seed_strings.append(v)
            if len(bin_seed_strings) >= 768:
                break

    def read_string_at_va(addr: int) -> Optional[str]:
        if binary_data is None or image_base <= 0:
            return None
        return _pe_read_c_string(binary_data, va=addr, image_base=image_base)

    def read_u64_at_va(addr: int) -> Optional[int]:
        if binary_data is None or image_base <= 0:
            return None
        if addr < image_base:
            return None
        rva = addr - image_base
        off = _pe_rva_to_file_offset(binary_data, rva)
        if off is None:
            return None
        if off + 8 > len(binary_data):
            return None
        try:
            return struct.unpack_from('<Q', binary_data, off)[0]
        except Exception:
            return None
    return {'strings_by_addr': strings_by_addr, 'dat_ptr_values': dat_ptr_values, 'jar_seed_strings': jar_seed_strings, 'bin_seed_strings': bin_seed_strings, 'read_string_at_va': read_string_at_va, 'read_u64_at_va': read_u64_at_va}
