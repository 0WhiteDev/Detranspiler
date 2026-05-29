import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def _jar_scan_classes(jar_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if jar_path is None:
        return None
    try:
        p = Path(jar_path)
    except Exception:
        return None
    if not p.is_file():
        return None
    from detranspiler.java.identifiers import _sanitize_java_identifier

    def read_u1(data: bytes, off: int) -> Tuple[int, int]:
        return data[off], off + 1

    def read_u2(data: bytes, off: int) -> Tuple[int, int]:
        return struct.unpack_from('>H', data, off)[0], off + 2

    def read_u4(data: bytes, off: int) -> Tuple[int, int]:
        return struct.unpack_from('>I', data, off)[0], off + 4

    def parse_classfile(data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 16:
            return None
        magic, off = read_u4(data, 0)
        if magic != 3405691582:
            return None
        _minor, off = read_u2(data, off)
        _major, off = read_u2(data, off)
        cp_count, off = read_u2(data, off)
        if cp_count <= 1:
            return None
        cp: List[Optional[Any]] = [None] * cp_count
        i = 1
        while i < cp_count:
            tag, off = read_u1(data, off)
            if tag == 1:
                ln, off = read_u2(data, off)
                raw = data[off:off + ln]
                off += ln
                try:
                    cp[i] = raw.decode('utf-8', errors='replace')
                except Exception:
                    cp[i] = None
            elif tag in (3, 4):
                val = struct.unpack_from('>I', data, off)[0]
                off += 4
                if tag == 3:
                    cp[i] = ('Integer', int(val & 4294967295))
            elif tag in (5, 6):
                off += 8
                i += 1
            elif tag == 7:
                name_index, off = read_u2(data, off)
                cp[i] = ('Class', name_index)
            elif tag == 8:
                string_index, off = read_u2(data, off)
                cp[i] = ('String', string_index)
            elif tag == 16:
                desc_index, off = read_u2(data, off)
                cp[i] = ('MethodType', desc_index)
            elif tag in (9, 10, 11, 12, 18):
                if tag == 12:
                    name_index, off = read_u2(data, off)
                    desc_index, off = read_u2(data, off)
                    cp[i] = ('NameAndType', name_index, desc_index)
                elif tag == 18:
                    bsm_index, off = read_u2(data, off)
                    nt_index, off = read_u2(data, off)
                    cp[i] = ('InvokeDynamic', bsm_index, nt_index)
                else:
                    class_index, off = read_u2(data, off)
                    nt_index, off = read_u2(data, off)
                    kind = 'Fieldref' if tag == 9 else 'Methodref' if tag == 10 else 'InterfaceMethodref'
                    cp[i] = (kind, class_index, nt_index)
            elif tag == 15:
                ref_kind, off = read_u1(data, off)
                ref_index, off = read_u2(data, off)
                cp[i] = ('MethodHandle', ref_kind, ref_index)
            elif tag == 17:
                off += 4
            elif tag in (19, 20):
                off += 2
            else:
                return None
            i += 1
        access_flags, off = read_u2(data, off)
        this_class, off = read_u2(data, off)
        _super_class, off = read_u2(data, off)
        if not 0 < this_class < cp_count:
            return None
        class_info = cp[this_class]
        if not (isinstance(class_info, tuple) and len(class_info) == 2 and (class_info[0] == 'Class')):
            return None
        name_index = class_info[1]
        if not (isinstance(name_index, int) and 0 < name_index < cp_count):
            return None
        class_name = cp[name_index]
        if not isinstance(class_name, str) or not class_name:
            return None
        interfaces_count, off = read_u2(data, off)
        off += 2 * interfaces_count
        fields_count, off = read_u2(data, off)
        for _fi in range(fields_count):
            _af, off = read_u2(data, off)
            _ni, off = read_u2(data, off)
            _di, off = read_u2(data, off)
            ac, off = read_u2(data, off)
            for _ai in range(ac):
                _an, off = read_u2(data, off)
                alen, off = read_u4(data, off)
                off += alen
        methods: Dict[Tuple[str, str], int] = {}
        methods_code: Dict[Tuple[str, str], bytes] = {}
        methods_locals: Dict[Tuple[str, str], Dict[int, str]] = {}
        methods_lvt: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        methods_count, off = read_u2(data, off)
        for _mi in range(methods_count):
            maf, off = read_u2(data, off)
            mn, off = read_u2(data, off)
            md, off = read_u2(data, off)
            ac, off = read_u2(data, off)
            name = cp[mn] if 0 < mn < cp_count else None
            desc = cp[md] if 0 < md < cp_count else None
            if isinstance(name, str) and isinstance(desc, str):
                methods[name, desc] = maf
            for _ai in range(ac):
                an, off = read_u2(data, off)
                alen, off = read_u4(data, off)
                end = off + alen
                if end < off or end > len(data):
                    return None
                aname = cp[an] if 0 < an < cp_count else None
                if aname == 'Code' and isinstance(name, str) and isinstance(desc, str):
                    o = off
                    try:
                        _max_stack, o = read_u2(data, o)
                        _max_locals, o = read_u2(data, o)
                        code_len, o = read_u4(data, o)
                        if code_len < 0 or o + code_len > end:
                            raise ValueError('bad code_len')
                        code = data[o:o + code_len]
                        o = o + code_len
                        ex_len, o = read_u2(data, o)
                        o = o + 8 * int(ex_len)
                        sub_ac, o = read_u2(data, o)
                        locals_for_method: Dict[int, Tuple[int, str]] = {}
                        lvt_entries: List[Dict[str, Any]] = []
                        for _ in range(int(sub_ac)):
                            san, o = read_u2(data, o)
                            slen, o = read_u4(data, o)
                            send = o + int(slen)
                            if send < o or send > end:
                                raise ValueError('bad sub-attr')
                            sname = cp[san] if 0 < san < cp_count else None
                            if sname == 'LocalVariableTable':
                                tt, o2 = read_u2(data, o)
                                for _k in range(int(tt)):
                                    start_pc, o2 = read_u2(data, o2)
                                    _ln, o2 = read_u2(data, o2)
                                    name_i, o2 = read_u2(data, o2)
                                    _desc_i, o2 = read_u2(data, o2)
                                    idx, o2 = read_u2(data, o2)
                                    nm2 = cp[name_i] if 0 < name_i < cp_count else None
                                    if isinstance(idx, int) and isinstance(nm2, str) and nm2:
                                        nm_s = _sanitize_java_identifier(nm2)
                                        lvt_entries.append({'start_pc': int(start_pc), 'length': int(_ln), 'index': int(idx), 'name': nm_s})
                                        prev = locals_for_method.get(int(idx))
                                        if prev is None or int(start_pc) < int(prev[0]):
                                            locals_for_method[int(idx)] = (int(start_pc), nm2)
                                o = send
                            else:
                                o = send
                        methods_code[name, desc] = bytes(code)
                        if locals_for_method:
                            methods_locals[name, desc] = {int(k): _sanitize_java_identifier(v[1]) for k, v in locals_for_method.items()}
                        if lvt_entries:
                            methods_lvt[name, desc] = lvt_entries
                    except Exception:
                        pass
                off = end
        bootstrap_methods: List[Dict[str, Any]] = []
        class_attr_count, off = read_u2(data, off)
        for _ai in range(int(class_attr_count)):
            an, off = read_u2(data, off)
            alen, off = read_u4(data, off)
            end = off + int(alen)
            if end < off or end > len(data):
                return None
            aname = cp[an] if 0 < an < cp_count else None
            if aname == 'BootstrapMethods':
                o = off
                try:
                    n, o = read_u2(data, o)
                    for _ in range(int(n)):
                        bmr, o = read_u2(data, o)
                        na, o = read_u2(data, o)
                        args: List[int] = []
                        for _k in range(int(na)):
                            ai2, o = read_u2(data, o)
                            args.append(int(ai2))
                        bootstrap_methods.append({'method_ref': int(bmr), 'args': args})
                except Exception:
                    pass
            off = end
        return {'class': class_name, 'access_flags': access_flags, 'methods': methods, 'methods_code': methods_code, 'methods_locals': methods_locals, 'methods_lvt': methods_lvt, 'bootstrap_methods': bootstrap_methods, 'cp': cp}
    out: Dict[str, Any] = {}
    try:
        with zipfile.ZipFile(p, 'r') as zf:
            for info in zf.infolist():
                name = info.filename
                if not isinstance(name, str) or not name.endswith('.class'):
                    continue
                try:
                    data = zf.read(info)
                except Exception:
                    continue
                parsed = parse_classfile(data)
                if not isinstance(parsed, dict):
                    continue
                cls = parsed.get('class')
                if isinstance(cls, str) and cls:
                    out[cls] = parsed
    except Exception:
        return None
    return out
