from __future__ import annotations

import hashlib
import json
import lzma
import os
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple


MAX_ARCHIVE_ENTRIES = 100_000
MAX_ENTRY_SIZE = 1_073_741_824
MAX_CLASS_SIZE = 16_777_216
MAX_TOTAL_SIZE = 2_147_483_648
MAX_COMPRESSION_RATIO = 1_000


class ExtractionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _Method:
    name: str
    descriptor: str
    code: bytes


@dataclass(frozen=True)
class _ClassFile:
    name: str
    constant_pool: List[Any]
    methods: List[_Method]


def _u1(data: bytes, off: int) -> Tuple[int, int]:
    if off + 1 > len(data):
        raise ValueError("truncated class file")
    return data[off], off + 1


def _u2(data: bytes, off: int) -> Tuple[int, int]:
    if off + 2 > len(data):
        raise ValueError("truncated class file")
    return struct.unpack_from(">H", data, off)[0], off + 2


def _u4(data: bytes, off: int) -> Tuple[int, int]:
    if off + 4 > len(data):
        raise ValueError("truncated class file")
    return struct.unpack_from(">I", data, off)[0], off + 4


def _skip_attributes(data: bytes, off: int, count: int) -> int:
    for _ in range(count):
        _name, off = _u2(data, off)
        size, off = _u4(data, off)
        if off + size > len(data):
            raise ValueError("truncated class attribute")
        off += size
    return off


def _parse_class_file(data: bytes) -> _ClassFile:
    magic, off = _u4(data, 0)
    if magic != 0xCAFEBABE:
        raise ValueError("invalid class magic")
    _minor, off = _u2(data, off)
    _major, off = _u2(data, off)
    cp_count, off = _u2(data, off)
    cp: List[Any] = [None] * cp_count
    idx = 1
    while idx < cp_count:
        tag, off = _u1(data, off)
        if tag == 1:
            size, off = _u2(data, off)
            if off + size > len(data):
                raise ValueError("truncated UTF-8 constant")
            cp[idx] = ("Utf8", data[off : off + size].decode("utf-8", errors="replace"))
            off += size
        elif tag == 3:
            raw, off = _u4(data, off)
            cp[idx] = ("Integer", struct.unpack(">i", struct.pack(">I", raw))[0])
        elif tag == 4:
            raw, off = _u4(data, off)
            cp[idx] = ("Float", raw)
        elif tag in (5, 6):
            if off + 8 > len(data):
                raise ValueError("truncated wide constant")
            raw = data[off : off + 8]
            off += 8
            cp[idx] = ("Long", struct.unpack(">q", raw)[0]) if tag == 5 else ("Double", raw)
            idx += 1
        elif tag in (7, 8, 16, 19, 20):
            value, off = _u2(data, off)
            cp[idx] = ({7: "Class", 8: "String", 16: "MethodType", 19: "Module", 20: "Package"}[tag], value)
        elif tag in (9, 10, 11, 12, 17, 18):
            a, off = _u2(data, off)
            b, off = _u2(data, off)
            cp[idx] = ({9: "Fieldref", 10: "Methodref", 11: "InterfaceMethodref", 12: "NameAndType", 17: "Dynamic", 18: "InvokeDynamic"}[tag], a, b)
        elif tag == 15:
            a, off = _u1(data, off)
            b, off = _u2(data, off)
            cp[idx] = ("MethodHandle", a, b)
        else:
            raise ValueError(f"unsupported constant-pool tag {tag}")
        idx += 1

    _access, off = _u2(data, off)
    this_class, off = _u2(data, off)
    _super, off = _u2(data, off)
    interfaces, off = _u2(data, off)
    off += interfaces * 2
    fields, off = _u2(data, off)
    for _ in range(fields):
        off += 6
        attrs, off = _u2(data, off)
        off = _skip_attributes(data, off, attrs)

    methods: List[_Method] = []
    method_count, off = _u2(data, off)
    for _ in range(method_count):
        _flags, off = _u2(data, off)
        name_idx, off = _u2(data, off)
        desc_idx, off = _u2(data, off)
        attrs, off = _u2(data, off)
        name = _cp_utf8(cp, name_idx)
        desc = _cp_utf8(cp, desc_idx)
        code = b""
        for _ in range(attrs):
            attr_idx, off = _u2(data, off)
            attr_size, off = _u4(data, off)
            end = off + attr_size
            if end > len(data):
                raise ValueError("truncated method attribute")
            if _cp_utf8(cp, attr_idx) == "Code":
                cursor = off
                _max_stack, cursor = _u2(data, cursor)
                _max_locals, cursor = _u2(data, cursor)
                code_size, cursor = _u4(data, cursor)
                if cursor + code_size > end:
                    raise ValueError("truncated method bytecode")
                code = data[cursor : cursor + code_size]
            off = end
        methods.append(_Method(name=name, descriptor=desc, code=code))

    class_item = cp[this_class] if 0 < this_class < len(cp) else None
    if not (isinstance(class_item, tuple) and class_item[0] == "Class"):
        raise ValueError("missing class name")
    return _ClassFile(name=_cp_utf8(cp, class_item[1]), constant_pool=cp, methods=methods)


def _cp_utf8(cp: List[Any], index: int) -> str:
    item = cp[index] if 0 < index < len(cp) else None
    return str(item[1]) if isinstance(item, tuple) and item[0] == "Utf8" else ""


def _cp_value(cp: List[Any], index: int) -> Any:
    item = cp[index] if 0 < index < len(cp) else None
    if not isinstance(item, tuple):
        return None
    if item[0] in {"Integer", "Long"}:
        return item[1]
    if item[0] == "String":
        return _cp_utf8(cp, item[1])
    if item[0] == "Class":
        return ("class", _cp_utf8(cp, item[1]))
    return None


def _cp_member(cp: List[Any], index: int) -> Optional[Tuple[str, str, str]]:
    item = cp[index] if 0 < index < len(cp) else None
    if not (isinstance(item, tuple) and item[0] in {"Fieldref", "Methodref", "InterfaceMethodref"}):
        return None
    cls_item = cp[item[1]] if 0 < item[1] < len(cp) else None
    nt_item = cp[item[2]] if 0 < item[2] < len(cp) else None
    if not (isinstance(cls_item, tuple) and cls_item[0] == "Class"):
        return None
    if not (isinstance(nt_item, tuple) and nt_item[0] == "NameAndType"):
        return None
    return _cp_utf8(cp, cls_item[1]), _cp_utf8(cp, nt_item[1]), _cp_utf8(cp, nt_item[2])


def _class_strings(parsed: _ClassFile) -> List[str]:
    return [str(item[1]) for item in parsed.constant_pool if isinstance(item, tuple) and item[0] == "Utf8"]


def _descriptor_arg_count(descriptor: str) -> int:
    if not descriptor.startswith("("):
        return 0
    count = 0
    i = 1
    while i < len(descriptor) and descriptor[i] != ")":
        while descriptor[i] == "[":
            i += 1
        if descriptor[i] == "L":
            end = descriptor.find(";", i)
            if end < 0:
                return count
            i = end + 1
        else:
            i += 1
        count += 1
    return count


def _descriptor_returns_value(descriptor: str) -> bool:
    end = descriptor.find(")")
    return end >= 0 and end + 1 < len(descriptor) and descriptor[end + 1] != "V"


_UNKNOWN = object()


def _signed16(code: bytes, off: int) -> int:
    return struct.unpack_from(">h", code, off)[0]


def _infer_windows_x64_range(parsed: _ClassFile) -> Tuple[int, int, str]:
    clinit = next((m for m in parsed.methods if m.name == "<clinit>" and m.code), None)
    if clinit is None:
        raise ExtractionError("JNIC_CLINIT_MISSING", f"JNIC loader {parsed.name} has no static initializer bytecode")
    cp = parsed.constant_pool
    code = clinit.code
    stack: List[Any] = []
    locals_: Dict[int, Any] = {}
    pc = 0
    steps = 0
    comparisons: List[Tuple[int, int, int]] = []

    def pop() -> Any:
        return stack.pop() if stack else _UNKNOWN

    def push(value: Any) -> None:
        stack.append(value)

    while 0 <= pc < len(code) and steps < 20_000:
        steps += 1
        start = pc
        op = code[pc]
        pc += 1
        if op == 0x00:
            continue
        if op == 0x01:
            push(None)
            continue
        if 0x02 <= op <= 0x08:
            push(op - 3)
            continue
        if op in (0x09, 0x0A):
            push(op - 0x09)
            continue
        if op == 0x10:
            push(struct.unpack_from("b", code, pc)[0]); pc += 1; continue
        if op == 0x11:
            push(_signed16(code, pc)); pc += 2; continue
        if op == 0x12:
            push(_cp_value(cp, code[pc])); pc += 1; continue
        if op in (0x13, 0x14):
            idx = struct.unpack_from(">H", code, pc)[0]; pc += 2; push(_cp_value(cp, idx)); continue
        if op in (0x15, 0x16, 0x19):
            idx = code[pc]; pc += 1; push(locals_.get(idx, _UNKNOWN)); continue
        if 0x1A <= op <= 0x1D:
            push(locals_.get(op - 0x1A, _UNKNOWN)); continue
        if 0x1E <= op <= 0x21:
            push(locals_.get(op - 0x1E, _UNKNOWN)); continue
        if 0x2A <= op <= 0x2D:
            push(locals_.get(op - 0x2A, _UNKNOWN)); continue
        if op in (0x36, 0x37, 0x3A):
            idx = code[pc]; pc += 1; locals_[idx] = pop(); continue
        if 0x3B <= op <= 0x3E:
            locals_[op - 0x3B] = pop(); continue
        if 0x3F <= op <= 0x42:
            locals_[op - 0x3F] = pop(); continue
        if 0x4B <= op <= 0x4E:
            locals_[op - 0x4B] = pop(); continue
        if op == 0x57:
            pop(); continue
        if op == 0x59:
            value = pop(); push(value); push(value); continue
        if op == 0x5F:
            a, b = pop(), pop(); push(a); push(b); continue
        if op in (0x61, 0x65, 0x69):
            b, a = pop(), pop()
            push(a + b if op == 0x61 and isinstance(a, int) and isinstance(b, int) else a - b if op == 0x65 and isinstance(a, int) and isinstance(b, int) else a * b if isinstance(a, int) and isinstance(b, int) else _UNKNOWN)
            continue
        if op == 0x94:
            b, a = pop(), pop()
            if isinstance(a, int) and isinstance(b, int):
                comparisons.append((a, b, start))
                push(-1 if a < b else 1 if a > b else 0)
            else:
                push(_UNKNOWN)
            continue
        if 0x99 <= op <= 0x9E:
            delta = _signed16(code, pc); pc += 2; value = pop()
            if value is _UNKNOWN:
                if len({(a, b) for a, b, _at in comparisons if 0 <= a < b}) == 1:
                    break
                raise ExtractionError("JNIC_BRANCH_AMBIGUOUS", f"Cannot resolve platform branch at bytecode offset {start} in {parsed.name}")
            cond = {0x99: value == 0, 0x9A: value != 0, 0x9B: value < 0, 0x9C: value >= 0, 0x9D: value > 0, 0x9E: value <= 0}[op]
            if cond: pc = start + delta
            continue
        if 0x9F <= op <= 0xA4:
            delta = _signed16(code, pc); pc += 2; b, a = pop(), pop()
            if a is _UNKNOWN or b is _UNKNOWN:
                raise ExtractionError("JNIC_BRANCH_AMBIGUOUS", f"Cannot resolve comparison at bytecode offset {start} in {parsed.name}")
            cond = {0x9F: a == b, 0xA0: a != b, 0xA1: a < b, 0xA2: a >= b, 0xA3: a > b, 0xA4: a <= b}[op]
            if cond: pc = start + delta
            continue
        if op in (0xA5, 0xA6):
            delta = _signed16(code, pc); pc += 2; b, a = pop(), pop()
            if a is _UNKNOWN or b is _UNKNOWN:
                raise ExtractionError("JNIC_BRANCH_AMBIGUOUS", f"Cannot resolve reference comparison at bytecode offset {start} in {parsed.name}")
            if (a == b) == (op == 0xA5): pc = start + delta
            continue
        if op == 0xA7:
            delta = _signed16(code, pc); pc = start + delta; continue
        if op in (0xB2, 0xB3, 0xBB, 0xBD, 0xC0, 0xC1):
            idx = struct.unpack_from(">H", code, pc)[0]; pc += 2
            if op == 0xB2: push(("static", _cp_member(cp, idx)))
            elif op == 0xB3: pop()
            elif op == 0xBB: push(("object", _cp_value(cp, idx)))
            elif op == 0xC1: pop(); push(_UNKNOWN)
            continue
        if op in (0xB6, 0xB7, 0xB8, 0xB9):
            idx = struct.unpack_from(">H", code, pc)[0]; pc += 2
            if op == 0xB9: pc += 2
            member = _cp_member(cp, idx)
            if member is None:
                raise ExtractionError("JNIC_BYTECODE_UNSUPPORTED", f"Unresolved method reference at bytecode offset {start}")
            owner, name, desc = member
            args = [pop() for _ in range(_descriptor_arg_count(desc))][::-1]
            receiver = None if op == 0xB8 else pop()
            value: Any = _UNKNOWN
            if owner == "java/lang/System" and name == "getProperty" and args:
                value = "Windows 10" if args[0] == "os.name" else "amd64" if args[0] == "os.arch" else _UNKNOWN
            elif owner == "java/lang/String" and name in {"toLowerCase", "toLowerCase"} and isinstance(receiver, str):
                value = receiver.lower()
            elif owner == "java/lang/String" and name == "contains" and isinstance(receiver, str) and args and isinstance(args[0], str):
                value = 1 if args[0] in receiver else 0
            elif owner == "java/lang/String" and name == "equals" and isinstance(receiver, str) and args:
                value = 1 if receiver == args[0] else 0
            elif name == "getResourceAsStream" and args and isinstance(args[0], str) and args[0].endswith(".dat"):
                break
            if _descriptor_returns_value(desc):
                push(value)
            continue
        if op == 0xBA:
            pc += 4
            push(_UNKNOWN)
            continue
        if op in (0xAC, 0xAD, 0xB0, 0xB1, 0xBF):
            break
        if op == 0xC6 or op == 0xC7:
            delta = _signed16(code, pc); pc += 2; value = pop()
            if value is _UNKNOWN:
                raise ExtractionError("JNIC_BRANCH_AMBIGUOUS", f"Cannot resolve null branch at bytecode offset {start} in {parsed.name}")
            if (value is None) == (op == 0xC6): pc = start + delta
            continue
        raise ExtractionError("JNIC_BYTECODE_UNSUPPORTED", f"Unsupported JVM opcode 0x{op:02x} at bytecode offset {start} in {parsed.name}")

    candidates = [(a, b, at) for a, b, at in comparisons if 0 <= a < b]
    unique = {(a, b) for a, b, _at in candidates}
    if len(unique) != 1:
        detail = ", ".join(f"[{a}, {b})" for a, b in sorted(unique)) or "none"
        raise ExtractionError("JNIC_RANGE_NOT_FOUND", f"Could not determine one Windows x64 range from {parsed.name}; candidates: {detail}")
    offset, end = next(iter(unique))
    return offset, end - offset, f"{parsed.name}.<clinit>"


def _infer_raw_lzma2_dictionary(parsed: _ClassFile) -> int:
    strings = set(_class_strings(parsed))
    required = {"readUnsignedByte", "readUnsignedShort", "readInt"}
    signatures = {(method.name, method.descriptor) for method in parsed.methods}
    if not required.issubset(strings) or ("read", "([BII)I") not in signatures:
        raise ExtractionError(
            "JNIC_TRANSFORM_UNKNOWN",
            f"Payload is encoded, but {parsed.name} does not match the supported raw LZMA2 stream loader",
        )
    constructor = next(
        (method for method in parsed.methods if method.name == "<init>" and method.descriptor == "(Ljava/io/InputStream;)V"),
        None,
    )
    if constructor is None:
        raise ExtractionError("JNIC_TRANSFORM_UNKNOWN", "Could not locate the JNIC stream constructor")
    constants: List[int] = []
    code = constructor.code
    pc = 0
    while pc < len(code):
        op = code[pc]
        pc += 1
        if op == 0x12 and pc < len(code):
            value = _cp_value(parsed.constant_pool, code[pc])
            pc += 1
            if isinstance(value, int) and value > 0:
                constants.append(value)
        elif op in (0x13, 0x14) and pc + 2 <= len(code):
            index = struct.unpack_from(">H", code, pc)[0]
            pc += 2
            value = _cp_value(parsed.constant_pool, index)
            if isinstance(value, int) and value > 0:
                constants.append(value)
        elif op == 0x19:
            pc += 1
        elif 0x2A <= op <= 0x2D or op in (0x01, 0xB1):
            continue
        elif op == 0xB7:
            pc += 2
        else:
            raise ExtractionError(
                "JNIC_TRANSFORM_UNKNOWN",
                f"Unsupported stream-constructor opcode 0x{op:02x} in {parsed.name}",
            )
    unique = set(constants)
    if len(unique) != 1:
        raise ExtractionError(
            "JNIC_TRANSFORM_UNKNOWN",
            f"Could not determine one LZMA2 dictionary size from {parsed.name}: {sorted(unique)}",
        )
    dictionary = next(iter(unique))
    if dictionary < 4096 or dictionary > 1_073_741_824:
        raise ExtractionError("JNIC_TRANSFORM_INVALID", f"Invalid LZMA2 dictionary size: {dictionary}")
    return dictionary


def _decode_jnic_payload(data: bytes, parsed: _ClassFile, required_end: int) -> Tuple[bytes, Dict[str, Any]]:
    if required_end <= 0 or required_end > MAX_ENTRY_SIZE:
        raise ExtractionError("JNIC_RANGE_INVALID", f"Decoded range end is outside the safety limit: {required_end}")
    if data.startswith(b"MZ"):
        if len(data) < required_end:
            raise ExtractionError(
                "JNIC_DECODE_TRUNCATED",
                f"Direct payload is too short: need {required_end} bytes, got {len(data)}",
            )
        return data, {"kind": "none"}
    dictionary = _infer_raw_lzma2_dictionary(parsed)
    try:
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dictionary}],
        )
        decoded = decoder.decompress(data, max_length=required_end)
    except lzma.LZMAError as exc:
        raise ExtractionError("JNIC_DECODE_FAILED", f"Raw LZMA2 decoding failed: {exc}") from exc
    if len(decoded) < required_end:
        raise ExtractionError(
            "JNIC_DECODE_TRUNCATED",
            f"Decoded payload is too short: need {required_end} bytes, got {len(decoded)}",
        )
    return decoded, {"kind": "raw-lzma2", "dictionary_size": dictionary}


def _validate_zip(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ExtractionError("JAR_LIMIT", f"JAR contains too many entries ({len(infos)})")
    total = 0
    seen = set()
    for info in infos:
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not name or "\x00" in name:
            raise ExtractionError("JAR_UNSAFE_PATH", f"Unsafe JAR entry path: {info.filename!r}")
        if name in seen:
            raise ExtractionError("JAR_DUPLICATE_ENTRY", f"Duplicate JAR entry: {name}")
        seen.add(name)
        if info.file_size < 0 or info.file_size > MAX_ENTRY_SIZE:
            raise ExtractionError("JAR_LIMIT", f"JAR entry is too large: {name} ({info.file_size} bytes)")
        total += info.file_size
        if total > MAX_TOTAL_SIZE:
            raise ExtractionError("JAR_LIMIT", f"JAR uncompressed size exceeds {MAX_TOTAL_SIZE} bytes")
        if info.file_size and info.compress_size == 0:
            raise ExtractionError("JAR_RATIO", f"Invalid compressed size for JAR entry: {name}")
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise ExtractionError("JAR_RATIO", f"Suspicious compression ratio for JAR entry: {name}")
    return infos


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with zf.open(info, "r") as stream:
        data = stream.read(info.file_size + 1)
    if len(data) != info.file_size:
        raise ExtractionError("JAR_READ", f"JAR entry size changed while reading: {info.filename}")
    return data


def _pe_info(data: bytes, *, require_amd64: bool) -> Dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ExtractionError("PE_INVALID", "Extracted bytes do not start with a DOS MZ header")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off < 0x40 or pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ExtractionError("PE_INVALID", "Extracted bytes do not contain a valid PE signature")
    machine, sections, _timestamp, _sym, _symbols, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    optional_off = pe_off + 24
    if optional_off + optional_size > len(data) or optional_size < 2:
        raise ExtractionError("PE_INVALID", "PE optional header is truncated")
    optional_magic = struct.unpack_from("<H", data, optional_off)[0]
    section_table = optional_off + optional_size
    if section_table + sections * 40 > len(data):
        raise ExtractionError("PE_INVALID", "PE section table is truncated")
    for index in range(sections):
        section_off = section_table + index * 40
        raw_size, raw_pointer = struct.unpack_from("<II", data, section_off + 16)
        if raw_size and (raw_pointer > len(data) or raw_pointer + raw_size > len(data)):
            raise ExtractionError("PE_INVALID", f"PE section {index} raw data is outside the extracted file")
    if require_amd64 and (machine != 0x8664 or optional_magic != 0x20B):
        raise ExtractionError("PE_WRONG_ARCH", f"JNIC Windows payload is not x64 PE32+ (machine=0x{machine:04x}, magic=0x{optional_magic:04x})")
    if not (characteristics & 0x2000):
        raise ExtractionError("PE_NOT_DLL", "Extracted PE image is not marked as a DLL")
    return {
        "machine": f"0x{machine:04x}",
        "architecture": {0x8664: "x86_64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, "unknown"),
        "pe_format": "PE32+" if optional_magic == 0x20B else "PE32" if optional_magic == 0x10B else f"0x{optional_magic:04x}",
        "sections": sections,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    if path.exists():
        raise ExtractionError("OUTPUT_EXISTS", f"Output file already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _write_manifest(out_dir: Path, result: Dict[str, Any]) -> None:
    path = out_dir / "extraction.json"
    if path.exists():
        raise ExtractionError("OUTPUT_EXISTS", f"Output manifest already exists: {path}")
    payload = (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    _atomic_write(path, payload)


def _standard_extract(zf: zipfile.ZipFile, infos: List[zipfile.ZipInfo], out_dir: Path) -> Dict[str, Any]:
    dlls = [info for info in infos if not info.is_dir() and info.filename.lower().endswith(".dll")]
    if not dlls:
        raise ExtractionError("DLL_NOT_FOUND", "No .dll entry was found in the JAR")
    if len(dlls) != 1:
        names = ", ".join(info.filename for info in dlls[:10])
        raise ExtractionError("DLL_AMBIGUOUS", f"Expected exactly one .dll entry, found {len(dlls)}: {names}")
    info = dlls[0]
    data = _read_entry(zf, info)
    pe = _pe_info(data, require_amd64=False)
    output = out_dir / Path(PurePosixPath(info.filename).name)
    _atomic_write(output, data)
    return {"source_entry": info.filename, "output_file": str(output.resolve()), "offset": 0, "size": len(data), "pe": pe}


def _jnic_extract(zf: zipfile.ZipFile, infos: List[zipfile.ZipInfo], out_dir: Path) -> Dict[str, Any]:
    by_name = {info.filename.replace("\\", "/"): info for info in infos}
    dat_infos = [info for info in infos if not info.is_dir() and info.filename.lower().endswith(".dat")]
    if not dat_infos:
        raise ExtractionError("JNIC_DAT_NOT_FOUND", "No .dat payload was found in the JAR")
    class_infos = [info for info in infos if not info.is_dir() and info.filename.endswith(".class")]
    candidates: List[Tuple[_ClassFile, str]] = []
    parse_errors: List[str] = []
    for info in class_infos:
        if info.file_size > MAX_CLASS_SIZE:
            parse_errors.append(f"{info.filename}: class exceeds {MAX_CLASS_SIZE} byte safety limit")
            continue
        try:
            parsed = _parse_class_file(_read_entry(zf, info))
        except Exception as exc:
            parse_errors.append(f"{info.filename}: {exc}")
            continue
        strings = _class_strings(parsed)
        dat_paths = [s.lstrip("/") for s in strings if isinstance(s, str) and s.lower().endswith(".dat")]
        markers = {"os.name", "os.arch"}
        if markers.issubset(set(strings)):
            for dat_path in dat_paths:
                if dat_path in by_name:
                    candidates.append((parsed, dat_path))
    unique = {(item[0].name, item[1]): item for item in candidates}
    if not unique:
        detail = f" Parsed class errors: {'; '.join(parse_errors[:3])}" if parse_errors else ""
        raise ExtractionError("JNIC_LOADER_NOT_FOUND", "No class links os.name/os.arch platform selection to an existing .dat resource." + detail)
    if len(unique) != 1:
        found = ", ".join(f"{name} -> {dat}" for name, dat in sorted(unique))
        raise ExtractionError("JNIC_LOADER_AMBIGUOUS", f"Multiple JNIC loader candidates found: {found}")
    parsed, dat_path = next(iter(unique.values()))
    offset, size, evidence = _infer_windows_x64_range(parsed)
    info = by_name[dat_path]
    if offset < 0 or size <= 0 or offset + size > MAX_ENTRY_SIZE:
        raise ExtractionError("JNIC_RANGE_INVALID", f"Loader range [{offset}, {offset + size}) is outside the safety limit")
    dat = _read_entry(zf, info)
    decoded, transform = _decode_jnic_payload(dat, parsed, offset + size)
    payload = decoded[offset : offset + size]
    pe = _pe_info(payload, require_amd64=True)
    output = out_dir / "win-x64.dll"
    _atomic_write(output, payload)
    return {
        "source_entry": dat_path,
        "loader_class": parsed.name.replace("/", "."),
        "range_evidence": evidence,
        "transform": transform,
        "output_file": str(output.resolve()),
        "offset": offset,
        "size": size,
        "pe": pe,
    }


def extract_native_library(*, jar_path: Path, out_dir: Path, mode: str) -> Dict[str, Any]:
    jar = Path(jar_path).expanduser()
    output = Path(out_dir).expanduser()
    selected_mode = str(mode or "").strip().lower()
    if selected_mode not in {"standard", "jnic"}:
        raise ExtractionError("MODE_INVALID", "Mode must be 'standard' or 'jnic'")
    if not jar.is_file():
        raise ExtractionError("JAR_NOT_FOUND", f"JAR file not found: {jar}")
    if output.exists() and not output.is_dir():
        raise ExtractionError("OUTPUT_INVALID", f"Output path is not a directory: {output}")
    manifest_path = output / "extraction.json"
    if manifest_path.exists():
        raise ExtractionError("OUTPUT_EXISTS", f"Output manifest already exists: {manifest_path}")
    try:
        with zipfile.ZipFile(jar, "r") as zf:
            infos = _validate_zip(zf)
            details = _standard_extract(zf, infos, output) if selected_mode == "standard" else _jnic_extract(zf, infos, output)
    except ExtractionError:
        raise
    except zipfile.BadZipFile as exc:
        raise ExtractionError("JAR_INVALID", f"Invalid or corrupted JAR: {exc}") from exc
    except OSError as exc:
        raise ExtractionError("IO_ERROR", str(exc)) from exc
    result: Dict[str, Any] = {
        "status": "OK",
        "mode": selected_mode,
        "jar": str(jar.resolve()),
        "output_dir": str(output.resolve()),
        **details,
    }
    output_file = Path(str(result["output_file"]))
    result["sha256"] = hashlib.sha256(output_file.read_bytes()).hexdigest()
    _write_manifest(output, result)
    return result
