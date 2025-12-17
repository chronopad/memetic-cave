import pefile
import struct
import sys

def align(val, to):
    if val % to == 0: return val
    return val + (to - (val % to))

def allocate_code_cave(source, payload):
    try: 
        pe = pefile.PE(source)
    except FileNotFoundError:
        print(f"[!] File {source} not found.")
        return

    file_align = pe.OPTIONAL_HEADER.FileAlignment
    section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 + 20 + pe.FILE_HEADER.SizeOfOptionalHeader)
    
    payload_len = len(payload)
    padded_payload_len = align(payload_len, file_align)
    padded_payload = payload + b'\x00' * (padded_payload_len - payload_len)

    # IMPROVE: Multiple sections targetting feature
    target_section = pe.sections[0]
    injection_offset = target_section.PointerToRawData + target_section.SizeOfRawData

    with open(source, "rb") as f:
        data = bytearray(f.read())

    first_header_offset = section_table_offset
    original_raw_size = struct.unpack_from('<I', data, first_header_offset + 16)[0]
    new_raw_size = original_raw_size + padded_payload_len
    struct.pack_into('<I', data, first_header_offset + 16, new_raw_size)

    for i in range(pe.FILE_HEADER.NumberOfSections):
        sec_offset = section_table_offset + (i * 40)
        raw_ptr = struct.unpack_from('<I', data, sec_offset + 20)[0]

        if raw_ptr >= injection_offset:
            struct.pack_into('<I', data, sec_offset + 20, raw_ptr + padded_payload_len)

    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for debug in pe.DIRECTORY_ENTRY_DEBUG:
                if debug.struct.PointerToRawData > injection_offset:
                    debug_file_offset = debug.struct.get_file_offset()
                    current_ptr = debug.struct.PointerToRawData
                    struct.pack_into('<I', data, debug_file_offset + 20, current_ptr + padded_payload_len)
    except Exception as e:
        print(f"[!] Warning: Debug Directory patch skipped: {e}")

    try:
        data_dirs = None
        if hasattr(pe.OPTIONAL_HEADER, 'DataDirectory'):
            data_dirs = pe.OPTIONAL_HEADER.DataDirectory
        elif hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            data_dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

        if data_dirs and len(data_dirs) > 4:
            sec_dir_entry = data_dirs[4]
            if sec_dir_entry.VirtualAddress > injection_offset:
                sec_dir_file_offset = sec_dir_entry.struct.get_file_offset()
                struct.pack_into('<I', data, sec_dir_file_offset, sec_dir_entry.VirtualAddress + padded_payload_len)
    except Exception as e:
        print(f"[!] Warning: Security Directory patch skipped: {e}")

    final_data = data[:injection_offset] + padded_payload + data[injection_offset:]
    return final_data, injection_offset, padded_payload_len

sha256 = sys.argv[1]
FILE_IN = f"malwares/{sha256}.exe"
FILE_OUT = f"patched/{sha256}_out.exe"
payload = b"SECRET_PAYLOAD"

# Caller
sourceArmor, injectionOffset, caveSize = allocate_code_cave(FILE_IN, payload)
with open(f"patched/{sha256}.exe", "wb") as f:
    f.write(sourceArmor)
print(f"Patch process done.")
