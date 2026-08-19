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
    root = Path(sys.argv[1])
    ok = True
    files = list(root.rglob("*.cql")) + list(root.rglob("*.spl"))
    if not files:
        print(f"{root}: no converted query files found")
        return 1
    for path in files:
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