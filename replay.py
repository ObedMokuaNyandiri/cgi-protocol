import json
import os
from worker import run_epoch

LOG_FILE = "logs/audit.jsonl"

# =========================================================
# LOAD AUDIT STREAM
# =========================================================
def load_events():
    if not os.path.exists(LOG_FILE):
        raise FileNotFoundError(f"Missing log file: {LOG_FILE}")

    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return events

# =========================================================
# RECONSTRUCT MISSION MEMORY SNAPSHOT
# =========================================================
def extract_mission_memory(events):
    mission = {}

    for e in events:
        if e["event"] == "SYSTEM_BOOT":
            mission = e["data"].get("mission", {})
        elif e["event"] == "MISSION_UPDATE":
            mission.update(e["data"])

    return mission

# =========================================================
# GROUP EVENTS INTO EPOCHS
# =========================================================
def group_epochs(events):
    epochs = []
    current = None

    for e in events:
        if e["event"] == "EPOCH_START":
            current = {
                "prompt": e["data"]["prompt"],
                "seed": e["data"].get("seed", 42),
                "events": []
            }

        if current is not None:
            current["events"].append(e)

        if e["event"] == "EPOCH_END":
            epochs.append(current)
            current = None

    return epochs

# =========================================================
# REPLAY ENGINE
# =========================================================
def replay():
    events = load_events()

    mission_memory = extract_mission_memory(events)
    epochs = group_epochs(events)

    print("===================================")
    print("CGI REPLAY ENGINE STARTED")
    print(f"Loaded epochs: {len(epochs)}")
    print("===================================")

    # =====================================================
    # REPLAY EACH EPOCH (ISOLATED EXECUTION)
    # =====================================================
    for i, epoch in enumerate(epochs):

        prompt = epoch["prompt"]
        seed = epoch["seed"]

        print("\n-----------------------------------")
        print(f"[REPLAY EPOCH {i}]")
        print(f"PROMPT: {prompt}")
        print(f"SEED: {seed}")
        print(f"MISSION STATE: {mission_memory}")
        print("-----------------------------------\n")

        # =================================================
        # CRITICAL: isolate each run (no cross contamination)
        # =================================================
        try:
            run_epoch(
                prompt=prompt,
                seed=seed
            )
        except Exception as e:
            print(f"[REPLAY ERROR] epoch={i} error={e}")

    print("\n===================================")
    print("CGI REPLAY FINISHED")
    print("===================================")

# =========================================================
# ENTRYPOINT
# =========================================================
if __name__ == "__main__":
    replay()