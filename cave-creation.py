import pefile
import struct
import shutil
import sys

sha256 = sys.argv[1]

FILE_IN = f"malwares/{sha256}.exe"
FILE_OUT = f"patched/{sha256}.exe"

def align(val, to):
    if val % to == 0: return val
    return val + (to - (val % to))

def manual_header_injection(src_file, dst_file, new_sect_name, payload_data):
    try:
        pe = pefile.PE(src_file)
    except FileNotFoundError:
        print(f"[!] File {src_file} not found.")
        return

    print(f"[*] Analyzing {src_file} (Manual Mode)")

    # 1. Gather Offsets & Sizes
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    num_sections = pe.FILE_HEADER.NumberOfSections

    # Calculate where the Section Table CURRENTLY ends
    section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 +
                            20 + pe.FILE_HEADER.SizeOfOptionalHeader)

    current_table_end = section_table_offset + (num_sections * 40)

    # Check slack space
    first_section_raw = pe.sections[0].PointerToRawData
    if current_table_end + 40 > first_section_raw:
        print("[!] Error: Not enough slack space in headers.")
        return

    print(f"[*] Header Space OK. Table ends: 0x{current_table_end:X}, Data starts: 0x{first_section_raw:X}")

    # 2. Prepare Payload
    payload_len = len(payload_data)
    padded_payload_len = align(payload_len, file_align)
    payload_padded = payload_data + b'\x00' * (padded_payload_len - payload_len)

    # 3. Determine Injection Parameters
    target_section = pe.sections[0]
    injection_offset = target_section.PointerToRawData + target_section.SizeOfRawData

    # New Virtual Address (End of image)
    last_virtual_section = max(pe.sections, key=lambda s: s.VirtualAddress)
    new_virtual_address = align(last_virtual_section.VirtualAddress + last_virtual_section.Misc_VirtualSize, sect_align)
    new_size_of_image = align(new_virtual_address + payload_len, sect_align)

    print(f"[*] New Section: VA=0x{new_virtual_address:X}, Raw=0x{injection_offset:X}")

    # 4. Construct New Section Header (40 Bytes)
    name_bytes = new_sect_name.encode()[:8].ljust(8, b'\x00')
    header_bytes = struct.pack('<8sIIIIIIHHI',
                               name_bytes,              # Name
                               payload_len,             # VirtualSize
                               new_virtual_address,     # VirtualAddress
                               padded_payload_len,      # SizeOfRawData
                               injection_offset,        # PointerToRawData
                               0, 0, 0, 0,              # Reloc/Lines
                               0x40000040)              # Characteristics (Read | Initialized)

    # 5. Read Full File
    with open(src_file, 'rb') as f:
        data = bytearray(f.read())

    # 6. Apply Patches

    # A. Inject Section Header
    data[current_table_end : current_table_end + 40] = header_bytes

    # B. Update NumberOfSections
    num_sec_offset = pe.DOS_HEADER.e_lfanew + 4 + 2
    struct.pack_into('<H', data, num_sec_offset, num_sections + 1)

    # C. Update SizeOfImage (Check 32 vs 64 bit for offset)
    # Magic: 0x10B (32-bit), 0x20B (64-bit)
    if pe.OPTIONAL_HEADER.Magic == 0x20B:
        size_of_image_offset = pe.DOS_HEADER.e_lfanew + 24 + 56
    else:
        size_of_image_offset = pe.DOS_HEADER.e_lfanew + 24 + 56 # Actually typically same offset relative to OptionalHeader start for this field

    # To be safe, let's use pefile's offset if possible, or trust standard offset
    # PE32+ SizeOfImage is at offset 56 decimal from start of Optional Header
    # PE32  SizeOfImage is at offset 56 decimal from start of Optional Header
    struct.pack_into('<I', data, size_of_image_offset, new_size_of_image)

    # 7. Physical Injection (The Shift)

    # A. Shift Section Pointers
    for i in range(num_sections):
        sec_offset = section_table_offset + (i * 40)
        raw_ptr = struct.unpack_from('<I', data, sec_offset + 20)[0]

        if raw_ptr >= injection_offset:
            struct.pack_into('<I', data, sec_offset + 20, raw_ptr + padded_payload_len)
            # print(f"    -> Shifted Section {i} Pointer")

    # B. Fix Debug Directory (Raw Pointer)
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for debug in pe.DIRECTORY_ENTRY_DEBUG:
                if debug.struct.PointerToRawData > injection_offset:
                     debug_struct_offset = debug.struct.get_file_offset()
                     current_ptr = debug.struct.PointerToRawData
                     struct.pack_into('<I', data, debug_struct_offset + 20, current_ptr + padded_payload_len)
                     print(f"    -> Fixed Debug Directory Pointer")
    except Exception as e:
        print(f"[!] Warning: Could not patch Debug Directory: {e}")

    # C. Fix Security Directory (Certificate Table)
    # ROBUST FIX: Handle missing attribute error
    try:
        # 1. Get the list of directories safely
        data_dirs = None
        if hasattr(pe.OPTIONAL_HEADER, 'DataDirectory'):
            data_dirs = pe.OPTIONAL_HEADER.DataDirectory
        elif hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            data_dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

        # 2. Check Security Directory (Index 4)
        if data_dirs and len(data_dirs) > 4:
            sec_dir_entry = data_dirs[4]

            # 3. Patch if needed
            if sec_dir_entry.VirtualAddress > injection_offset:
                # Calculate file offset of this directory entry manually to be safe
                # Optional Header Start + Fixed Fields size + (Index * 8)
                # Fixed Fields: 112 (64-bit) or 96 (32-bit)
                opt_header_start = pe.DOS_HEADER.e_lfanew + 24
                if pe.OPTIONAL_HEADER.Magic == 0x20B: # 64-bit
                    base_offset = 112
                else:
                    base_offset = 96

                sec_dir_file_offset = opt_header_start + base_offset + (4 * 8)

                # Update the pointer in the raw bytearray
                struct.pack_into('<I', data, sec_dir_file_offset, sec_dir_entry.VirtualAddress + padded_payload_len)
                print("    -> Fixed Security Directory Pointer (Manual Patch)")
        else:
            print("[*] No Security Directory found or list unavailable (Safe to ignore).")

    except Exception as e:
        print(f"[!] Warning: Security Directory patch skipped: {e}")


    # 8. Construct Final Block
    final_data = data[:injection_offset] + payload_padded + data[injection_offset:]

    # 9. Write to Disk
    with open(dst_file, 'wb') as f:
        f.write(final_data)

    print(f"[*] Success! Saved to {dst_file}")

# Run
payload = b"SECRET_PAYLOAD"
manual_header_injection(FILE_IN, FILE_OUT, ".secret", payload)