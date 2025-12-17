import requests
import os 
import subprocess
import sys

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

OUTPUT_DIR = "malwares"
API_URL = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY = "8b9303cac813de92ba2ca1606aa79a14090bea5f95811b00"

sha256 = sys.argv[1]

download_sample(sha256)
extract_sample(sha256)
os.remove(sha256)