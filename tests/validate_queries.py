import re
import sys
from pathlib import Path


def check_cql_regex_literals(path: Path) -> bool:
    ok = True
    pattern = re.compile(r"/((?:[^/\\]|\\.)*)/[im\s]*")
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        for match in pattern.finditer(line):
            if match.group(1) == "":
                print(f"{path}:{lineno}: empty regex literal - unescaped '/' inside pattern")
                ok = False
    return ok


def check_spl_index_sourcetype(path: Path) -> bool:
    ok = True
    for blockno, block in enumerate(path.read_text().split("\n\n"), 1):
        if not block.strip():
            continue
        if "index=" not in block:
            print(f"{path}: block {blockno}: missing index=")
            ok = False
        if "sourcetype=" not in block:
            print(f"{path}: block {blockno}: missing sourcetype=")
            ok = False
    return ok


def main() -> int:
    trans_root = Path(sys.argv[1])
    rules_root = Path(sys.argv[2])
    ok = True

    rules = sorted(rules_root.rglob("*.yml"))
    if not rules:
        print(f"{rules_root}: no Sigma rules found")
        return 1
    for rule in rules:
        if not rule.read_text().strip():
            print(f"{rule}: empty Sigma rule file")
            ok = False

    expected_files = set()
    for trans_dir, suffix in (("splunk-spl", ".spl"), ("crowdstrike-logscale", ".cql")):
        for rule in rules:
            counterpart = trans_root / trans_dir / rule.relative_to(rules_root).with_suffix(suffix)
            expected_files.add(counterpart)
            if not counterpart.is_file():
                print(f"{counterpart}: missing converted query for rule {rule.relative_to(rules_root)}")
                ok = False

    files = sorted(trans_root.rglob("*.cql")) + sorted(trans_root.rglob("*.spl"))
    if not files:
        print(f"{trans_root}: no converted query files found")
        return 1
    for path in files:
        if path not in expected_files:
            print(f"{path}: orphaned converted query (no matching rule)")
            ok = False
        if not path.read_text().strip():
            print(f"{path}: empty output file")
            ok = False
        if path.suffix == ".cql" and not check_cql_regex_literals(path):
            ok = False
        if path.suffix == ".spl" and not check_spl_index_sourcetype(path):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())