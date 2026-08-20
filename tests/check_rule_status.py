import os
import subprocess
import sys
from pathlib import Path

import yaml

RULES = Path("rules/sigma")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def status_of_source(source):
    try:
        return yaml.safe_load(source).get("status")
    except Exception:
        return None


def baseline_sha() -> str:
    merge_base = run(["git", "merge-base", "origin/main", "HEAD"])
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        return merge_base.stdout.strip()
    prev = run(["git", "rev-parse", "HEAD^"])
    return prev.stdout.strip() if prev.returncode == 0 else ""


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
    diff = run(["git", "diff", "--name-status", base, "HEAD", "--", RULES.as_posix()])

    for line in diff.stdout.splitlines():
        parts = line.split("\t")
        status = parts[0]
        path = Path(parts[-1])

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

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())