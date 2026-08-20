import os
import subprocess
import sys
from pathlib import Path

import yaml

RULES = Path("rules/sigma")
PROMOTION = {"test", "stable"}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def status_of_source(source):
    try:
        return yaml.safe_load(source).get("status")
    except Exception:
        return None


def main() -> int:
    event = os.environ.get("GITHUB_EVENT_NAME", "push")
    ok = True

    if event == "workflow_dispatch":
        print("workflow_dispatch: skipping status check")
        return 0

    if event == "pull_request":
        base = os.environ.get("GITHUB_BASE_SHA") or "origin/main"
        base = run(["git", "merge-base", base, "HEAD"]).stdout.strip()
        if not base:
            print("no merge-base found for PR, skipping status check")
            return 0
    else:
        prev = run(["git", "rev-parse", "HEAD^"])
        if prev.returncode != 0:
            print("no previous commit, skipping status check")
            return 0
        base = prev.stdout.strip()

    diff = run(["git", "diff", "--name-status", base, "HEAD", "--", RULES.as_posix()])

    for line in diff.stdout.splitlines():
        parts = line.split("\t")
        status = parts[0]
        path = Path(parts[-1])
        old_path = Path(parts[1]) if status.startswith("R") else path

        if status == "D":
            continue

        new_status = status_of_source(path.read_text())
        if new_status is None:
            print(f"{path}: could not parse status")
            ok = False
            continue

        if status in ("A", "C") or status.startswith("R"):
            if new_status != "experimental":
                print(f"{path}: new rule must be status 'experimental', got '{new_status}'")
                ok = False
            continue

        if event in ("push", "merge_group"):
            old = run(["git", "show", f"{base}:{old_path.as_posix()}"]).stdout
            old_status = status_of_source(old)
            if old_status == "experimental" and new_status in PROMOTION:
                print(
                    f"{path}: status promotion '{old_status}' -> '{new_status}' must go through a pull request"
                )
                ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())