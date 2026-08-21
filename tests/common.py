import os
import subprocess
from pathlib import Path


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def baseline_sha() -> str:
    merge_base = run(["git", "merge-base", "origin/main", "HEAD"])
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        return merge_base.stdout.strip()
    prev = run(["git", "rev-parse", "HEAD^"])
    return prev.stdout.strip() if prev.returncode == 0 else ""


def changed_rule_paths(base: str, rules_root: Path):
    diff = run(
        ["git", "diff", "--name-status", "--diff-filter=ACMRT", base, "HEAD", "--", rules_root.as_posix()]
    )
    for line in diff.stdout.splitlines():
        parts = line.split("\t")
        status = parts[0]
        path = Path(parts[-1])
        try:
            rel = path.relative_to(rules_root)
        except ValueError:
            rel = Path(os.path.relpath(path, rules_root))
        yield status, rel
