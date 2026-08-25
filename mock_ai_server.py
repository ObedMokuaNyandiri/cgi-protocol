import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class MockAIOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/chat/completions':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-mock",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Zero-knowledge proofs are useful for privacy because they allow a party to prove that a statement is true without revealing any information beyond the validity of the statement itself."
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 30,
                    "total_tokens": 40
                }
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/models':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"data": [{"id": "gpt-mock"}]}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass # Silence logs

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8001), MockAIOpenAIHandler)
    print("Mock AI Server running on http://127.0.0.1:8001")
    server.serve_forever()
