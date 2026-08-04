import json
import logging
import os
import subprocess
import sys
from typing import Tuple
from config import settings
from adapters import BaseAdapter

logger = logging.getLogger("cgi.adapters.hf")
BASE_DIR = settings.BASE_DIR

class HuggingFaceLocalAdapter(BaseAdapter):
    def generate(self, prompt: str, max_tokens: int, execution_id: str, seed: int) -> Tuple[str, str, int]:
        worker_path = os.path.join(BASE_DIR, "adapters", "hf_worker.py")
        stdin_payload = json.dumps({
            "payload": prompt,
            "execution_id": execution_id,
        })

        try:
            process = subprocess.run(
                [
                    sys.executable,
                    worker_path,
                    str(max_tokens),
                    str(max_tokens),
                    str(seed),
                ],
                input=stdin_payload,
                capture_output=True,
                text=True,
                cwd=BASE_DIR,
                timeout=settings.WORKER_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            logger.error("WORKER_TIMEOUT | exec_id=%s", execution_id)
            raise RuntimeError(f"Worker timed out after {settings.WORKER_TIMEOUT_SECONDS}s")

        if process.returncode != 0:
            logger.error("WORKER_FAILURE | exec_id=%s code=%d stderr=%s", 
                         execution_id, process.returncode, process.stderr[-500:])
            raise RuntimeError(f"Worker failed with code {process.returncode}")

        generated_text, stop_reason, token_count = self._parse_worker_output(process.stdout)
        
        if not generated_text.strip():
            logger.error("WORKER_EMPTY_OUTPUT | exec_id=%s stderr=%s", 
                         execution_id, process.stderr[-300:])
            raise RuntimeError("Worker produced empty output")
            
        return generated_text, stop_reason, token_count

    def _parse_worker_output(self, stdout: str) -> Tuple[str, str, int]:
        """
        Deterministic parser for hf_worker.py stdout protocol.
        """
        generated_text = ""
        stop_reason = "limit_reached"
        token_count = 0

        for raw_line in stdout.split("\n"):
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("[TOKEN]"):
                try:
                    text_marker = "text="
                    text_pos = line.find(text_marker)
                    if text_pos == -1:
                        continue
                    token_repr = line[text_pos + len(text_marker):]
                    token_text = token_repr.encode("utf-8").decode("unicode_escape")
                    if len(token_text) >= 2 and token_text[0] in ("'", '"') and token_text[-1] == token_text[0]:
                        token_text = token_text[1:-1]
                    generated_text += token_text
                    token_count += 1
                except Exception:
                    continue

            elif line.startswith("[WORKER_STOP]"):
                try:
                    stop_reason = line.split("reason=", 1)[1].strip()
                except IndexError:
                    stop_reason = "unknown"

        return generated_text, stop_reason, token_count
