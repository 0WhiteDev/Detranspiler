import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    import lief
except Exception:
    lief = None

def _pe_rva_to_file_offset(data: bytes, rva: int) -> Optional[int]:
    if len(data) < 256 or data[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, 60)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return None
    file_hdr_off = e_lfanew + 4
    number_of_sections = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
    size_of_optional_header = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
    opt_off = file_hdr_off + 20
    sect_off = opt_off + size_of_optional_header
    if sect_off <= 0 or sect_off > len(data):
        return None
    for i in range(number_of_sections):
        sh = sect_off + i * 40
        if sh + 40 > len(data):
            return None
        virtual_size = struct.unpack_from('<I', data, sh + 8)[0]
        virtual_address = struct.unpack_from('<I', data, sh + 12)[0]
        size_of_raw_data = struct.unpack_from('<I', data, sh + 16)[0]
        pointer_to_raw_data = struct.unpack_from('<I', data, sh + 20)[0]
        span = max(virtual_size, size_of_raw_data)
        if span == 0:
            continue
        if virtual_address <= rva < virtual_address + span:
            off = pointer_to_raw_data + (rva - virtual_address)
            if 0 <= off < len(data):
                return off
    return None

def _pe_image_base(data: bytes) -> int:
    if len(data) < 256 or data[:2] != b'MZ':
        return 0
    try:
        e_lfanew = struct.unpack_from('<I', data, 60)[0]
        opt_off = e_lfanew + 4 + 20
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic == 523:
            return struct.unpack_from('<Q', data, opt_off + 24)[0]
        if magic == 267:
            return struct.unpack_from('<I', data, opt_off + 28)[0]
    except Exception:
        pass
    return 0

def _pe_pointer_size(data: bytes) -> int:
    if len(data) < 256 or data[:2] != b'MZ':
        return 8
    try:
        e_lfanew = struct.unpack_from('<I', data, 60)[0]
        magic = struct.unpack_from('<H', data, e_lfanew + 4 + 20)[0]
        return 4 if magic == 267 else 8
    except Exception:
        return 8

def _elf_va_to_offset(data: bytes, va: int) -> Optional[int]:
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    try:
        is64 = data[4] == 2
        if is64:
            e_phoff = struct.unpack_from('<Q', data, 32)[0]
            e_phentsize = struct.unpack_from('<H', data, 54)[0]
            e_phnum = struct.unpack_from('<H', data, 56)[0]
            for i in range(e_phnum):
                ph = e_phoff + i * e_phentsize
                if ph + 56 > len(data):
                    break
                p_type = struct.unpack_from('<I', data, ph)[0]
                if p_type != 1:
                    continue
                p_offset = struct.unpack_from('<Q', data, ph + 8)[0]
                p_vaddr = struct.unpack_from('<Q', data, ph + 16)[0]
                p_filesz = struct.unpack_from('<Q', data, ph + 32)[0]
                if p_vaddr <= va < p_vaddr + p_filesz:
                    return p_offset + (va - p_vaddr)
        else:
            e_phoff = struct.unpack_from('<I', data, 28)[0]
            e_phentsize = struct.unpack_from('<H', data, 42)[0]
            e_phnum = struct.unpack_from('<H', data, 44)[0]
            for i in range(e_phnum):
                ph = e_phoff + i * e_phentsize
                if ph + 32 > len(data):
                    break
                p_type = struct.unpack_from('<I', data, ph)[0]
                if p_type != 1:
                    continue
                p_offset = struct.unpack_from('<I', data, ph + 4)[0]
                p_vaddr = struct.unpack_from('<I', data, ph + 8)[0]
                p_filesz = struct.unpack_from('<I', data, ph + 16)[0]
                if p_vaddr <= va < p_vaddr + p_filesz:
                    return p_offset + (va - p_vaddr)
    except Exception:
        return None
    return None

def _macho_va_to_offset(data: bytes, va: int) -> Optional[int]:
    if len(data) < 32:
        return None
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic not in (4277009103, 3489328638, 4277009102, 3472551422):
        return None
    try:
        is64 = magic in (4277009103, 3489328638)
        ncmds = struct.unpack_from('<I', data, 16)[0]
        off = 32 if is64 else 28
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from('<II', data, off)
            if cmd in (25, 1073741849):
                if is64:
                    segname = data[off + 8:off + 24]
                    vmaddr = struct.unpack_from('<Q', data, off + 24)[0]
                    vmsize = struct.unpack_from('<Q', data, off + 32)[0]
                    fileoff = struct.unpack_from('<Q', data, off + 40)[0]
                else:
                    vmaddr = struct.unpack_from('<I', data, off + 24)[0]
                    vmsize = struct.unpack_from('<I', data, off + 28)[0]
                    fileoff = struct.unpack_from('<I', data, off + 32)[0]
                if vmaddr <= va < vmaddr + vmsize:
                    return fileoff + (va - vmaddr)
            off += cmdsize
    except Exception:
        return None
    return None

class BinaryReader:

    def __init__(self, data: bytes, *, fmt: str='PE', image_base: int=0) -> None:
        self._data = data
        self._fmt = fmt.upper()
        if image_base > 0:
            self._image_base = image_base
        elif self._fmt == 'PE':
            self._image_base = _pe_image_base(data)
        else:
            self._image_base = image_base

    @classmethod
    def from_path(cls, path: Path, *, fmt: Optional[str]=None, image_base: int=0) -> 'BinaryReader':
        data = path.read_bytes()
        if fmt is None:
            if data[:2] == b'MZ':
                fmt = 'PE'
            elif data[:4] == b'\x7fELF':
                fmt = 'ELF'
            else:
                fmt = 'UNKNOWN'
        return cls(data, fmt=fmt, image_base=image_base)

    @property
    def image_base(self) -> int:
        return self._image_base

    @property
    def pointer_size(self) -> int:
        if self._fmt == 'PE':
            return _pe_pointer_size(self._data)
        return 8

    def va_to_offset(self, va: int) -> Optional[int]:
        if 0 < self._image_base <= va:
            rva_or_va = va - self._image_base if self._fmt == 'PE' else va
        else:
            rva_or_va = va
        if self._fmt == 'PE':
            if 0 < self._image_base <= va:
                return _pe_rva_to_file_offset(self._data, va - self._image_base)
            return _pe_rva_to_file_offset(self._data, va)
        if self._fmt == 'ELF':
            return _elf_va_to_offset(self._data, rva_or_va if self._image_base else va)
        if self._fmt == 'MACHO':
            return _macho_va_to_offset(self._data, va)
        return None

    def read_bytes(self, va: int, size: int) -> Optional[bytes]:
        off = self.va_to_offset(va)
        if off is None or off + size > len(self._data):
            return None
        return self._data[off:off + size]

    def read_c_string(self, va: int, *, max_len: int=512) -> Optional[str]:
        off = self.va_to_offset(va)
        if off is None:
            return None
        end = min(len(self._data), off + max_len)
        raw = self._data[off:end]
        nul = raw.find(b'\x00')
        if nul != -1:
            raw = raw[:nul]
        if not raw:
            return None
        try:
            s = raw.decode('utf-8', errors='ignore')
        except Exception:
            s = raw.decode('ascii', errors='ignore')
        s = s.strip()
        if not s:
            return None
        printable = sum((1 for ch in s if 32 <= ord(ch) <= 126 or ch in '\t\n\r'))
        if printable < max(1, len(s) // 2):
            return None
        return s

    def read_u64(self, va: int) -> Optional[int]:
        raw = self.read_bytes(va, 8)
        if raw is None:
            return None
        try:
            return struct.unpack('<Q', raw)[0]
        except Exception:
            return None

    def read_ptr(self, va: int) -> Optional[int]:
        ps = self.pointer_size
        raw = self.read_bytes(va, ps)
        if raw is None:
            return None
        try:
            if ps == 4:
                return struct.unpack('<I', raw)[0]
            return struct.unpack('<Q', raw)[0]
        except Exception:
            return None

def read_c_string_at(binary_data: bytes, *, va: int, image_base: int, fmt: str='PE', max_len: int=512) -> Optional[str]:
    return BinaryReader(binary_data, fmt=fmt, image_base=image_base).read_c_string(va, max_len=max_len)
