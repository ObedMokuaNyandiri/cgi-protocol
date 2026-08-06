$env:AI_BACKEND_TYPE="openai_compatible"
$env:AI_ENDPOINT_URL="http://127.0.0.1:8001/v1"
$env:LICENSE_ENFORCEMENT="DISABLED"
$env:AI_API_KEY="mock"
$env:MODEL_ID="qwen_0_5b"
python api_gateway.py
