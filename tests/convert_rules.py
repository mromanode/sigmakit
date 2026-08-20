import argparse
import re
import subprocess
import sys
from pathlib import Path

_ATOM = re.compile(r'(?:#[A-Za-z0-9_]+|"[^"]*"|[A-Za-z0-9_.\-]+)=/(?:\\.|[^/\\])*/[ims]*')


def parenthesize_or_groups(query: str) -> str:
    matches = list(_ATOM.finditer(query))
    if not matches:
        return query
    depth = 0
    depths = []
    pos = 0
    for m in matches:
        seg = query[pos:m.start()]
        depth += seg.count("(") - seg.count(")")
        depths.append(depth)
        pos = m.end()
    runs = []
    start = 0
    for i in range(len(matches) - 1):
        sep = query[matches[i].end():matches[i + 1].start()]
        if re.fullmatch(r"\s+or\s+", sep):
            continue
        if depths[start] == 0 and i - start + 1 >= 2:
            runs.append((matches[start].start(), matches[i].end()))
        start = i + 1
    if depths[start] == 0 and len(matches) - start >= 2:
        runs.append((matches[start].start(), matches[-1].end()))
    for a, b in reversed(runs):
        query = query[:a] + "(" + query[a:b] + ")" + query[b:]
    return query


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--pipeline", required=True)
    parser.add_argument("--suffix", required=True)
    args = parser.parse_args()

    rules_root = Path(args.rules)
    out_root = Path(args.out)
    ok = True

    current = {p for p in rules_root.rglob("*.yml")}

    merge_base = subprocess.run(
        ["git", "merge-base", "origin/main", "HEAD"], capture_output=True, text=True
    )
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        base = merge_base.stdout.strip()
    else:
        prev = subprocess.run(["git", "rev-parse", "HEAD^"], capture_output=True, text=True)
        base = prev.stdout.strip() if prev.returncode == 0 else ""

    if not base:
        to_convert = list(current)
    else:
        diff = subprocess.run(
            ["git", "diff", "--name-status", "--diff-filter=ACMRTD", base, "HEAD", "--", rules_root.as_posix()],
            capture_output=True, text=True,
        )
        to_convert = []
        for line in diff.stdout.splitlines():
            parts = line.split("\t")
            if parts[0] != "D":
                to_convert.append(Path(parts[-1]).relative_to(rules_root))

    for rel in to_convert:
        rule = rules_root / rel
        out = out_root / rel.with_suffix(args.suffix)
        out.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            ["sigma", "convert", "-t", args.target, "-p", args.pipeline, str(rule), "-o", str(out)],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            print(res.stderr or res.stdout)
            ok = False
        else:
            if args.target == "log_scale":
                out.write_text(parenthesize_or_groups(out.read_text()))
            print(f"converted {rule} -> {out}")

    expected = {out_root / p.relative_to(rules_root).with_suffix(args.suffix) for p in current}
    for out_file in out_root.rglob("*" + args.suffix):
        if out_file not in expected:
            out_file.unlink()
            print(f"removed stale {out_file}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())