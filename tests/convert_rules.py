import argparse
import hashlib
import re
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from common import baseline_sha, changed_rule_paths

_ATOM = re.compile(r'(?:#[A-Za-z0-9_.\-@%]+|"[^"]*"|[A-Za-z0-9_.\-@%]+)=/(?:\\.|[^/\\])*/[ims]*')
_STAMP_NAME = ".conversion-stamp"
_TRACKED_PACKAGES = (
    "sigma-cli",
    "pySigma",
    "pySigma-validators-sigmahq",
    "pysigma-backend-splunk",
    "pysigma-backend-crowdstrike",
)


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
        if re.fullmatch(r"\s+or\s+", sep, re.IGNORECASE):
            continue
        if depths[start] == 0 and i - start + 1 >= 2:
            runs.append((matches[start].start(), matches[i].end()))
        start = i + 1
    if depths[start] == 0 and len(matches) - start >= 2:
        runs.append((matches[start].start(), matches[-1].end()))
    for a, b in reversed(runs):
        query = query[:a] + "(" + query[a:b] + ")" + query[b:]
    return query


def conversion_fingerprint(pipeline: Path) -> str:
    h = hashlib.sha256()
    if pipeline.is_file():
        h.update(pipeline.read_bytes())
    else:
        h.update(f"builtin:{pipeline}".encode())
    for dist in _TRACKED_PACKAGES:
        try:
            h.update(version(dist).encode())
        except PackageNotFoundError:
            pass
    return h.hexdigest()


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
    pipeline = Path(args.pipeline)
    ok = True

    current = {p for p in rules_root.rglob("*.yml")}

    base = baseline_sha()
    stamp_file = out_root / _STAMP_NAME
    fingerprint = conversion_fingerprint(pipeline)

    if not base:
        to_convert = sorted(current)
    elif stamp_file.is_file() and stamp_file.read_text(encoding="utf-8").strip() == fingerprint:
        to_convert = [rules_root / rel for _, rel in changed_rule_paths(base, rules_root)]
    else:
        print(f"{out_root}: pipeline or backend versions changed, converting all rules")
        to_convert = sorted(current)

    for rule in to_convert:
        out = out_root / rule.relative_to(rules_root).with_suffix(args.suffix)
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            res = subprocess.run(
                ["sigma", "convert", "-t", args.target, "-p", args.pipeline, str(rule), "-o", str(out)],
                capture_output=True, text=True,
            )
        except FileNotFoundError:
            print("error: 'sigma' CLI not found; install sigma-cli and the backend packages", file=sys.stderr)
            return 1
        if res.returncode != 0:
            print(res.stderr or res.stdout, file=sys.stderr)
            ok = False
        else:
            if args.target == "log_scale":
                out.write_text(parenthesize_or_groups(out.read_text(encoding="utf-8")), encoding="utf-8")
            print(f"converted {rule} -> {out}")

    expected = {out_root / p.relative_to(rules_root).with_suffix(args.suffix) for p in current}
    for out_file in out_root.rglob("*" + args.suffix):
        if out_file not in expected:
            out_file.unlink()
            print(f"removed stale {out_file}")

    if ok:
        out_root.mkdir(parents=True, exist_ok=True)
        stamp_file.write_text(fingerprint + "\n", encoding="utf-8")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
