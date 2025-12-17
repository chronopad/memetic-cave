# Imports (optimizer, code caver, blackbox interface)
import random
import copy
import os
from tqdm import tqdm

import pefile
import struct
import sys

import ember
import lightgbm as lgb


from contiguous_code_cave_allocator import ContiguousCodeCaveAllocator

sha256 = sys.argv[1]
FILE_INPUT = f"malwares/{sha256}.exe"
FILE_OUTPUT = f"patched/{sha256}.exe"

with open(FILE_INPUT, "rb") as f:
    pe_bytes = f.read()

allocator = ContiguousCodeCaveAllocator(pe_bytes)
patched, cave_plan = allocator.allocate(
    payload_len=4096,          # e.g. 4 KB cave
    target_section_index=0     # same behavior as your original allocator
)

with open(FILE_OUTPUT, "wb") as f:
    f.write(patched)

print("Patched binary written.")
print("Allocated cave:", cave_plan.cave)

patched, cave_plan = allocator.reallocate(
    new_payload_len=4096 * 2,
    target_section_index=0
)

with open(f"patched/_{sha256}.exe", "wb") as f:
    f.write(patched)

print("Patched binary written.")
print("Allocated cave:", cave_plan.cave)