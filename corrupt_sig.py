import json
with open("outputs/portable_attestation.json", "r") as f:
    data = json.load(f)
data["attestation"]["attestation_signature"] = "BAD_SIGNATURE==="
with open("outputs/portable_attestation.json", "w") as f:
    json.dump(data, f)
