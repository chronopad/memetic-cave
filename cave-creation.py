import pefile
import struct
import sys

def align(val, to):
  if val % to == 0: return val
  return val + (to - (val % to))

def blind_injection_extend(src_file, dst_file, payload_data):
  try:
    pe = pefile.PE(src_file)
  except FileNotFoundError:
    print(f"[!] File {src_file} not found.")
    return

  print(f"[*] Analyzing {src_file} (Section Extension Mode)")

  # Gather Offsets & Sizes
  file_align = pe.OPTIONAL_HEADER.FileAlignment

  # Calculate Section Table Start
  section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 + 20 + pe.FILE_HEADER.SizeOfOptionalHeader)

  # Prepare Payload
  payload_len = len(payload_data)
  padded_payload_len = align(payload_len, file_align)
  payload_padded = payload_data + b'\x00' * (padded_payload_len - payload_len)

  print(f"[*] Payload Size: {payload_len} bytes (Aligned to {padded_payload_len})")

  # Determine Injection Parameters
  # Note: This currently hardcodes the first section (pe.sections[0]) for extension.
  # If you intend to extend a different section, this line would need modification.
  target_section = pe.sections[0]
  injection_offset = target_section.PointerToRawData + target_section.SizeOfRawData

  print(f"[*] Injection Point (Raw): 0x{injection_offset:X}")

  # Read FILE_IN
  with open(src_file, 'rb') as f:
    data = bytearray(f.read())

  # Update Target Section Size
  first_header_offset = section_table_offset
  original_raw_size = struct.unpack_from('<I', data, first_header_offset + 16)[0]
  new_raw_size = original_raw_size + padded_payload_len

  struct.pack_into('<I', data, first_header_offset + 16, new_raw_size)
  print(f"[*] Updated Section 0 SizeOfRawData: 0x{original_raw_size:X} -> 0x{new_raw_size:X}")

  # Shift Subsequent Sections
  print("[*] Shifting subsequent sections...")
  for i in range(pe.FILE_HEADER.NumberOfSections):
    sec_offset = section_table_offset + (i * 40)
    raw_ptr = struct.unpack_from('<I', data, sec_offset + 20)[0]

    # Shift sections that exist AFTER our injection point
    if raw_ptr >= injection_offset:
      struct.pack_into('<I', data, sec_offset + 20, raw_ptr + padded_payload_len)

  # Fix Debug Directory (MinGW Fix)
  try:
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
      for debug in pe.DIRECTORY_ENTRY_DEBUG:
        if debug.struct.PointerToRawData > injection_offset:
          debug_file_offset = debug.struct.get_file_offset()
          current_ptr = debug.struct.PointerToRawData
          struct.pack_into('<I', data, debug_file_offset + 20, current_ptr + padded_payload_len)
          print(f"    -> Fixed Debug Directory Pointer")
  except Exception as e:
    print(f"[!] Warning: Debug Directory patch skipped: {e}")

  # Fix Security Directory (Certificate Table)
  try:
    data_dirs = None
    if hasattr(pe.OPTIONAL_HEADER, 'DataDirectory'):
      data_dirs = pe.OPTIONAL_HEADER.DataDirectory
    elif hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
      data_dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

    if data_dirs and len(data_dirs) > 4:
      sec_dir_entry = data_dirs[4]
      # For the security directory, VirtualAddress typically represents the file offset (PointerToRawData)
      if sec_dir_entry.VirtualAddress > injection_offset:
        sec_dir_file_offset = sec_dir_entry.struct.get_file_offset()
        struct.pack_into('<I', data, sec_dir_file_offset, sec_dir_entry.VirtualAddress + padded_payload_len)
        print("    -> Fixed Security Directory Pointer")
  except Exception as e:
    print(f"[!] Warning: Security Directory patch skipped: {e}")

  # Write Final File
  final_data = data[:injection_offset] + payload_padded + data[injection_offset:]
  with open(dst_file, 'wb') as f:
    f.write(final_data)

  print(f"[*] Success! Saved to {dst_file}")

sha256 = sys.argv[1]
FILE_IN = f"malwares/{sha256}.exe"
FILE_OUT = f"patched/{sha256}_out.exe"
payload = b"SECRET_PAYLOAD"

# Caller
blind_injection_extend(FILE_IN, FILE_OUT, payload)
