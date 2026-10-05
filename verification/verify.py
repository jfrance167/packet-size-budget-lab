"""Repeat owned local checks: python verification/verify.py from any directory.

Inputs: frozen-contract.json, own source/tests/examples. Outputs: logs, Bandit JSON,
receipt.json, latest-run.json. Requires installed Python/Bandit; no installation.
Mutations restore exact source in finally; run without concurrent source edits.
Adapted from Jake's verified MIT framing-lab verifier; no sibling runtime import.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess  # nosec B404: fixed installed Python/owned checks, no shell.
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "verification"
SOURCE = ROOT / "packet_budget.py"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name, args):
    child = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                           timeout=60)  # nosec B603: fixed owned scripts, no shell/foreign code.
    (OUT / (name + ".log")).write_bytes(child.stdout + child.stderr)
    return child


def clear_cache():
    for optimization in (None, "1", "2"):
        # Only this module's generated cache files; no directory/source deletion.
        Path(importlib.util.cache_from_source(str(SOURCE), optimization=optimization)).unlink(missing_ok=True)


def verify():
    frozen = json.loads((OUT / "frozen-contract.json").read_text(encoding="utf-8-sig"))
    for name, expected in frozen["sha256"].items():
        if sha(ROOT / name) != expected:
            raise RuntimeError("frozen contract/oracle mismatch")
    original = SOURCE.read_bytes()
    results = {}
    test_args = ["-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    try:
        mutations = (("ipv6-base-counted", b"else extensions + transport_unit", b"else extensions + transport_unit + base"),
                     ("mtu-equality-rejected", b'compared <= case["carrier_mtu_bytes"]', b'compared < case["carrier_mtu_bytes"]'))
        for name, old, new in mutations:
            if original.count(old) != 1:
                raise RuntimeError("mutation target must occur exactly once")
            SOURCE.write_bytes(original.replace(old, new))
            clear_cache()
            child = run("mutation-" + name, test_args)
            text = (child.stdout + child.stderr).decode("utf-8", errors="replace")
            assertions = len(re.findall(r"^FAIL: ", text, re.MULTILINE))
            results[name] = {"exit": child.returncode, "assertion_failures": assertions}
            if child.returncode == 0 or assertions == 0:
                raise RuntimeError("mutation not detected by an assertion failure")
            SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
        clear_cache()
    for name, args in (("normal", test_args), ("optimized", ["-O", *test_args]),
                       ("compile", ["-m", "compileall", "-q", "packet_budget.py", "tests", "verification/verify.py"]),
                       ("bandit", ["-m", "bandit", "-q", "-r", "packet_budget.py", "tests", "verification/verify.py",
                                   "-f", "json", "-o", str(OUT / "bandit.json")])):
        child = run(name, args)
        results[name] = {"exit": child.returncode}
        if child.returncode:
            raise RuntimeError(name + " failed; see log")
    demos = {}
    for path in sorted((ROOT / "examples").glob("*.json")):
        expected = {"budgets": 0, "empty": 0, "mixed": 3, "invalid-late": 2}[path.stem]
        child = run("demo-" + path.stem, [str(SOURCE), str(path)])
        if child.returncode != expected:
            raise RuntimeError("demo status mismatch")
        value = json.loads(child.stdout) if expected != 2 else None
        if expected == 2 and child.stdout:
            raise RuntimeError("invalid demo emitted report")
        demos[path.name] = {"exit": child.returncode, "rows": len(value["rows"]) if value else None,
                            "status": value["status"] if value else None}
    paths = [SOURCE, ROOT / "tests/test_packet_budget.py", Path(__file__).resolve(), ROOT / "SCHEMA.md",
             ROOT / "tests/hand-oracles.json", OUT / "frozen-contract.json", *sorted((ROOT / "examples").glob("*.json"))]
    receipt = {"python": sys.version, "checks": results, "demos": demos, "frozen_verified": True,
               "source_restored": SOURCE.read_bytes() == original,
               "sha256": {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in paths}}
    (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


def main():
    status = OUT / "latest-run.json"
    status.write_text('{"status":"running"}\n', encoding="utf-8")
    try:
        verify()
    except Exception:
        status.write_text('{"status":"failed","prior_receipt_is_historical":true}\n', encoding="utf-8")
        raise
    status.write_text('{"status":"passed"}\n', encoding="utf-8")


if __name__ == "__main__":
    main()
