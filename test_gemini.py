import urllib.request
import json

api_key = "AQ.Ab8RN6KCwMHTU90lesJa_YdiUzjTPkS8TCMmj1y63XgJGMWjHA"
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"

try:
    with urllib.request.urlopen(url) as response:
        models = json.loads(response.read().decode())
        for model in models.get("models", []):
            if "gemini-3" in model["name"]:
                print(model["name"])
except Exception as e:
    print(e)
