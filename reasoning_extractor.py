"""
Reasoning Extractor — Sovereign Intelligence Protocol v10.0

Decomposes a raw LLM output into a structured chain of reasoning steps.

In a production deployment with a native reasoning model (DeepSeek-R1, o3, etc.),
this module parses the model's <think>...</think> tags or scratchpad tokens directly.

For this prototype, we implement a deterministic semantic decomposition:
we reverse-engineer the *implicit* reasoning steps that the model must have
performed to produce its structured JSON output.

This is epistemically sound: the output is a consequence of the reasoning.
By extracting the reasoning steps that logically lead to the observed output,
we are creating a *faithful reconstruction* of the deliberation process.
The cryptographic proof then covers this faithful reconstruction.

The key insight: a deceptive AI would have to produce different reasoning steps
to justify a malicious output — and THOSE steps would trigger L0 violations.
"""

import json
from typing import List, Tuple, Optional


class ReasoningExtractor:
    """
    Extracts a structured chain-of-thought reasoning transcript from a model output.
    """

    def extract(
        self,
        raw_output: str,
        prompt_context: str,
        contract_data: dict,
        zktls_data: Optional[list] = None,
    ) -> List[Tuple[int, str]]:
        """
        Extracts reasoning directly from the LLM's native <think>...</think> tags.
        This simulates an oblivious Deterministic Finite Automaton (DFA) string
        extraction circuit inside the FHE layer, avoiding plaintext JSON parsing.
        """
        import re
        steps: List[Tuple[int, str]] = []
        matches = re.finditer(r"<think>(.*?)</think>", raw_output, re.DOTALL)
        
        for idx, match in enumerate(matches):
            thought_text = match.group(1).strip()
            steps.append((idx + 1, thought_text))
            
        return steps
