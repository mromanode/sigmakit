import os
import sys
from pathlib import Path

import yaml

from common import baseline_sha, changed_rule_paths

RULES = Path("rules/sigma")


def status_of_source(source):
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError:
        return None
    return data.get("status") if isinstance(data, dict) else None


def main() -> int:
    event = os.environ.get("GITHUB_EVENT_NAME", "push")
    ref = os.environ.get("GITHUB_REF_NAME", "")

    if event == "workflow_dispatch":
        print("workflow_dispatch: skipping status check")
        return 0
    if event == "push" and ref != "main":
        print(f"push to '{ref}': skipping status check (enforced on pull requests)")
        return 0

    base = baseline_sha()
    if not base:
        print("no baseline commit, skipping status check")
        return 0

    ok = True
    for status, rel in changed_rule_paths(base, RULES):
        path = RULES / rel

        if status == "D":
            continue

        new_status = status_of_source(path.read_text(encoding="utf-8"))
        if new_status is None:
            print(f"{path}: could not parse status")
            ok = False
            continue

        if status in ("A", "C") or status.startswith("R"):
            if new_status != "experimental":
                print(f"{path}: new rule must be status 'experimental', got '{new_status}'")
                ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
