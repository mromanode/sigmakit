import argparse
import sys
from pathlib import Path


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)


def check_cql_regex_literals(path: Path) -> bool:
    ok = True
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        i = 0
        n = len(line)
        while i < n:
            c = line[i]
            if c == '"':
                i += 1
                while i < n and line[i] != '"':
                    i += 2 if line[i] == "\\" else 1
                i += 1
            elif c == "/":
                j = i + 1
                while j < n and line[j] != "/":
                    j += 2 if line[j] == "\\" else 1
                if j >= n:
                    fail(f"{path}:{lineno}: unterminated regex literal at column {i + 1} - unescaped '/' inside pattern")
                    ok = False
                    break
                content = line[i + 1:j]
                k = j + 1
                while k < n and line[k] in "ims":
                    k += 1
                if content == "":
                    fail(f"{path}:{lineno}: empty regex literal - unescaped '/' inside pattern")
                    ok = False
                i = k
            else:
                i += 1
    return ok


def check_spl_index_sourcetype(path: Path) -> bool:
    ok = True
    for blockno, block in enumerate(path.read_text(encoding="utf-8").split("\n\n"), 1):
        if not block.strip():
            continue
        if "index=" not in block:
            fail(f"{path}: block {blockno}: missing index=")
            ok = False
        if "sourcetype=" not in block:
            fail(f"{path}: block {blockno}: missing sourcetype=")
            ok = False
    return ok


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("translations", help="path to platform-translations/")
    parser.add_argument("rules", help="path to rules/sigma/")
    args = parser.parse_args()

    trans_root = Path(args.translations)
    rules_root = Path(args.rules)
    ok = True

    rules = sorted(rules_root.rglob("*.yml"))
    if not rules:
        fail(f"{rules_root}: no Sigma rules found")
        return 1
    for rule in rules:
        if not rule.read_text(encoding="utf-8").strip():
            fail(f"{rule}: empty Sigma rule file")
            ok = False

    expected_files = set()
    for trans_dir, suffix in (("splunk-spl", ".spl"), ("crowdstrike-logscale", ".cql")):
        for rule in rules:
            counterpart = trans_root / trans_dir / rule.relative_to(rules_root).with_suffix(suffix)
            expected_files.add(counterpart)
            if not counterpart.is_file():
                fail(f"{counterpart}: missing converted query for rule {rule.relative_to(rules_root)}")
                ok = False

    files = sorted(trans_root.rglob("*.cql")) + sorted(trans_root.rglob("*.spl"))
    if not files:
        fail(f"{trans_root}: no converted query files found")
        return 1
    for path in files:
        if path not in expected_files:
            fail(f"{path}: orphaned converted query (no matching rule)")
            ok = False
        if not path.read_text(encoding="utf-8").strip():
            fail(f"{path}: empty output file")
            ok = False
        if path.suffix == ".cql" and not check_cql_regex_literals(path):
            ok = False
        if path.suffix == ".spl" and not check_spl_index_sourcetype(path):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
