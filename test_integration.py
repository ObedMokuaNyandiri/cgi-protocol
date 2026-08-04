import json
import urllib.error
import urllib.request

API_KEY = "5d3e723cd0ab90a581e179f8d2cd13ec6af7ea3e6c26c3c56d36c1af22a52ded"

url = "http://localhost:8000/v1/infer"
data = {
    "prompt": "Summarize the patient's symptoms: headache, nausea, and elevated troponin.",
    "data_classification": "CONFIDENTIAL",
    "purpose_of_use": "GENERAL",
    "max_tokens": 50,
    "temperature": 0.2
}
headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY
}

req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")

try:
    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode())
        print("Integration Test OK!")
        print("Verdict:", result["payload"]["verification_verdict"]["status"])
        print("Assurance Level:", result["payload"]["verification_verdict"]["assurance_level"])
except urllib.error.HTTPError as e:
    print(f"HTTP Error: {e.code}")
    print(e.read().decode())
except Exception as e:
    print(f"Error: {e}")
