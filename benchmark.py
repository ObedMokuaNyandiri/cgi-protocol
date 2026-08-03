import subprocess
import time

PROMPTS = [
    "Explain secure systems.",
    "What is encryption?",
    "Describe authentication systems."
]

results = []

start = time.time()

for p in PROMPTS:

    t0 = time.time()

    proc = subprocess.run(
        ["python", "runtime.py"],
        input=p,
        text=True,
        capture_output=True
    )

    t1 = time.time()

    results.append(t1 - t0)

end = time.time()

print("\n=== BENCHMARK REPORT ===")
print("Runs:", len(PROMPTS))
print("Avg time:", sum(results)/len(results))
print("Total time:", end - start)