"""
GA-safe contiguous code cave allocator.

This module is a *behavior-preserving refactor* of the user's original allocator.
Key guarantee: **no semantic change** versus the original logic.

Design principles (intentionally preserved):
- Single contiguous disk-only cave
- Cave is NOT conceptually owned by a section
- Section SizeOfRawData semantics preserved exactly as in the original
- Raw-pointer shifting done structurally (struct.pack_into)
- Security & Debug directories shifted when present

Additions:
- Clean class-based API
- GA-friendly cave abstraction
- Deterministic resize via re-allocation (no in-place semantic drift)
"""

import struct
import pefile
from typing import Tuple, Optional

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def align(val: int, to: int) -> int:
    if val % to == 0:
        return val
    return val + (to - (val % to))


# ------------------------------------------------------------
# Cave Abstractions (GA-friendly)
# ------------------------------------------------------------

class CodeCave:
    """Represents a single contiguous disk-only code cave."""
    __slots__ = ("offset", "size")

    def __init__(self, offset: int, size: int):
        self.offset = offset          # File offset
        self.size = size              # FileAlignment-aligned size

    def __repr__(self):
        return f"<CodeCave offset=0x{self.offset:x} size={self.size}>"


class CavePlan:
    """
    GA-facing abstraction.

    - Owns only *where* bytes may be written
    - Never touches PE layout directly
    - Can be resized by reallocation (paper-faithful)
    """

    def __init__(self, cave: CodeCave):
        self.cave = cave

    @property
    def chromosome_length(self) -> int:
        return self.cave.size

    def write_chromosome(self, pe_bytes: bytes, chromosome: bytes) -> bytes:
        if len(chromosome) != self.cave.size:
            raise ValueError("Chromosome length must equal cave size")

        data = bytearray(pe_bytes)
        off = self.cave.offset
        data[off:off + self.cave.size] = chromosome
        return bytes(data)


# ------------------------------------------------------------
# Allocator (behavior-preserving refactor)
# ------------------------------------------------------------

class ContiguousCodeCaveAllocator:
    """
    Behavior-preserving refactor of the original allocator.

    IMPORTANT:
    - Does NOT conceptually assign the cave to any section
    - Only patches what the original code patched
    - No pe.write() normalization
    """

    def __init__(self, pe_bytes: bytes):
        self._src = pe_bytes
        self._pe = pefile.PE(data=pe_bytes, fast_load=False)

    # ------------------------------------------------------------
    # Allocation (exact behavior)
    # ------------------------------------------------------------

    def allocate(self, payload_len: int, *, target_section_index: int = 0) -> Tuple[bytes, CavePlan]:
        pe = self._pe
        file_align = pe.OPTIONAL_HEADER.FileAlignment

        padded_len = align(payload_len, file_align)

        target = pe.sections[target_section_index]
        injection_offset = target.PointerToRawData + target.SizeOfRawData

        data = bytearray(self._src)

        # --- Insert disk-only payload region ---
        data[injection_offset:injection_offset] = b"\x00" * padded_len

        # --- Patch SizeOfRawData of *target section only* (exact original behavior) ---
        section_table_offset = (
            pe.DOS_HEADER.e_lfanew + 4 + 20 + pe.FILE_HEADER.SizeOfOptionalHeader
        )

        first_sec_off = section_table_offset + (target_section_index * 40)
        original_raw_size = struct.unpack_from('<I', data, first_sec_off + 16)[0]
        struct.pack_into('<I', data, first_sec_off + 16, original_raw_size + padded_len)

        # --- Shift PointerToRawData of downstream sections ---
        for i in range(pe.FILE_HEADER.NumberOfSections):
            sec_off = section_table_offset + (i * 40)
            raw_ptr = struct.unpack_from('<I', data, sec_off + 20)[0]
            if raw_ptr >= injection_offset:
                struct.pack_into('<I', data, sec_off + 20, raw_ptr + padded_len)

        # --- Patch Debug Directory (if present) ---
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    if debug.struct.PointerToRawData > injection_offset:
                        debug_file_offset = debug.struct.get_file_offset()
                        current_ptr = debug.struct.PointerToRawData
                        struct.pack_into('<I', data, debug_file_offset + 20, current_ptr + padded_len)
        except Exception:
            pass

        # --- Patch Security Directory (file-offset based) ---
        try:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            ]
            if sec_dir.VirtualAddress > injection_offset:
                sec_dir_file_offset = sec_dir.struct.get_file_offset()
                struct.pack_into('<I', data, sec_dir_file_offset, sec_dir.VirtualAddress + padded_len)
        except Exception:
            pass

        cave = CodeCave(offset=injection_offset, size=padded_len)
        return bytes(data), CavePlan(cave)

    # ------------------------------------------------------------
    # Resizing (paper-faithful: reallocate, do not mutate in-place)
    # ------------------------------------------------------------

    def reallocate(self, new_payload_len: int, *, target_section_index: int = 0) -> Tuple[bytes, CavePlan]:
        """
        Resize by *re-running the allocator*.
        This preserves malware semantics and matches the paper's
        "increase size and retry" loop.
        """
        return self.allocate(new_payload_len, target_section_index=target_section_index)
