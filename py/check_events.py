import json
from collections import Counter
from pathlib import Path


EV_FILE = Path("events.json")


def load(path):
    if not path.exists():
        raise RuntimeError(f"event file not found: {path}")

    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def main():
    evs = load(EV_FILE)
    ids = Counter(ev.get("event_id") for ev in evs)

    print(f"total events: {len(evs)}")
    print("--------------------------------")
    print("first event:")
    print(evs[0] if evs else "no events found.")
    print("\nevent id summary:")
    print(dict(ids))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        print(f"error: {err}")
        raise SystemExit(1)
