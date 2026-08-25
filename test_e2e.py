import urllib.request
import json
import ssl

def run():
    url = "http://127.0.0.1:8000/v1/infer"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": "6d8e184ed6985dcd8901d419d82af963b4701909f3e6e990ee27bfb9134b17af"
    }
    data = {
        "prompt": "What is zero-knowledge?"
    }
    
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
    
    # Bypass SSL verification if any
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Sending request to {url}...")
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            result = json.loads(response.read().decode("utf-8"))
            print("\nSUCCESS! Gateway responded:")
            print(json.dumps(result, indent=2))
    except urllib.error.HTTPError as e:
        print(f"\nHTTP Error {e.code}:")
        print(e.read().decode("utf-8"))
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    run()
