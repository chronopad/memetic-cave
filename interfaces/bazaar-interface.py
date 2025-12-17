import requests
import os 
import subprocess
from tqdm import trange
import sys

TYPE = "exe"
DOWNLOAD_LIMIT = 10
API_URL = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY = "8b9303cac813de92ba2ca1606aa79a14090bea5f95811b00"
HASH_FILE = f"{TYPE}.hash"
MAX_SIZE = 2 * 1024 * 700
BLACKLIST = { "UPX", "upx-dec", "packed" }
OUTPUT_DIR = "malwares"

def get_hashes():
    payload = {
        "query": "get_file_type",
        "file_type": TYPE,
        "limit": DOWNLOAD_LIMIT*10
    }

    r = requests.post(API_URL, data=payload, headers={
        "Auth-Key": AUTH_KEY
    })
    data = r.json()

    hashes = []
    for entry in data.get("data", []):
        sha256 = entry.get("sha256_hash")
        file_size = entry.get("file_size")
        tags = set(entry.get("tags", []))

        if not tags.isdisjoint(BLACKLIST):
            continue

        if sha256 and file_size is not None and file_size <= MAX_SIZE and len(hashes) < DOWNLOAD_LIMIT:
            hashes.append(sha256)

    return hashes

def download_sample(sha256):
    payload = {
        "query": "get_file",
        "sha256_hash": sha256
    }

    with requests.post(API_URL, data=payload, stream=True, headers={
        "Auth-Key": AUTH_KEY
    }) as r:
        with open(sha256, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

def extract_sample(sha256):
    subprocess.run(
        ["7z", "e", sha256, "-pinfected", f"-o{OUTPUT_DIR}", "-aoa"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

if sys.argv[1]:
    DOWNLOAD_LIMIT = int(sys.argv[1])

hashes = get_hashes()
print("Found hashes!")
print(hashes)
with open(HASH_FILE, "w") as f:
    for h in hashes:
        f.write(h + "\n")
print(f"Wrote hashes to {HASH_FILE}")

for i in trange(len(hashes)):
    download_sample(hashes[i])
    extract_sample(hashes[i])
    os.remove(hashes[i])

os.remove(HASH_FILE)