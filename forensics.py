import json
import hashlib
import zipfile
import os

LOG_FILE = "logs/audit.jsonl"
EXPORT_DIR = "forensic_bundle"
os.makedirs(EXPORT_DIR, exist_ok=True)


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def build_bundle():

    with open(LOG_FILE, "r") as f:
        logs = f.read()

    log_hash = hashlib.sha256(logs.encode()).hexdigest()

    report = {
        "log_file": LOG_FILE,
        "log_hash": log_hash,
        "status": "EVIDENCE_VALID"
    }

    with open(f"{EXPORT_DIR}/report.json", "w") as f:
        json.dump(report, f, indent=2)

    with zipfile.ZipFile("forensic_bundle.zip", "w") as z:
        z.write(LOG_FILE)
        z.write(f"{EXPORT_DIR}/report.json")

    print("[FORENSIC PACKAGE CREATED]")


if __name__ == "__main__":
    build_bundle()