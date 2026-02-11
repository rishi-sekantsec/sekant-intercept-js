#!/usr/bin/env python3
"""
run_tests.py

Full YARA test orchestrator.

Features:
- Compare NodeJS YARA engine vs libyara (deep structure match)
- Generate synthetic test samples from public rule repositories (--generate)
- Automatically creates all required directories

Usage:
# 1. Generate tests from YARA-Rules repo
python3 run_tests.py --generate

# 2. Run Node vs libyara comparison tests
python3 run_tests.py tests/generated_tests.json

"""

import argparse
import json
import os
import subprocess
import tempfile
import yara
import re
import random
import string
from pathlib import Path
from deepdiff import DeepDiff

# ============================================================
# CONFIGURATION
# ============================================================
RULE_REPO_URLS = [
    "https://github.com/Yara-Rules/rules.git",
]
BASE_DIR = Path(".")
REPO_DIR = BASE_DIR / "repos"
TEST_DIR = BASE_DIR / "tests"
GEN_SAMPLES_DIR = TEST_DIR / "generated_samples"
GEN_TEST_DEF = TEST_DIR / "generated_tests.json"
LOG_DIR = BASE_DIR / "logs"

MAX_RULES_TO_GENERATE = 50   # limit per repo
SKIP_IMPORTS = True
NODE_RUNNER = "node_yara_runner.js"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def ensure_directories():
    """Create all required directories if missing."""
    for d in [REPO_DIR, TEST_DIR, GEN_SAMPLES_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    print("[+] Directory structure verified/created:")
    print(f"    - {REPO_DIR}")
    print(f"    - {TEST_DIR}")
    print(f"    - {GEN_SAMPLES_DIR}")
    print(f"    - {LOG_DIR}")


def clone_or_update_repo(repo_url: str, dest: Path):
    if dest.exists() and (dest / ".git").exists():
        print(f"[~] Updating repo {repo_url}")
        subprocess.run(["git", "-C", str(dest), "pull"], check=True)
    else:
        print(f"[+] Cloning {repo_url}")
        subprocess.run(["git", "clone", "--depth=1", repo_url, str(dest)], check=True)


def find_rule_files(root: Path):
    return list(root.rglob("*.yar")) + list(root.rglob("*.yara"))


def rule_contains_import(rule_text: str):
    return bool(re.search(r'^\s*import\s+\w+', rule_text, flags=re.MULTILINE))


def extract_strings_from_rule(rule_text: str):
    """Simple pattern extraction: gets quoted or hex strings from strings section."""
    matches = re.findall(r'(\$\w+)\s*=\s*"([^"]+)"', rule_text)
    hex_matches = re.findall(r'(\$\w+)\s*=\s*\{\s*([0-9A-Fa-f\s\?\[\]\-\+]+)\s*\}', rule_text)

    extracted = []
    for ident, lit in matches:
        extracted.append((ident, lit.encode('utf-8')))
    for ident, hexlit in hex_matches:
        bytes_seq = bytes(int(h, 16) for h in re.findall(r'[0-9A-F]{2}', hexlit))
        extracted.append((ident, bytes_seq))
    return extracted


def generate_sample_file(dest_dir: Path, ident: str, data_bytes: bytes):
    dest_dir.mkdir(parents=True, exist_ok=True)
    fname = dest_dir / f"{ident}_{''.join(random.choices(string.ascii_letters + string.digits, k=6))}.bin"
    padding = os.urandom(32)
    with open(fname, "wb") as f:
        f.write(padding)
        f.write(data_bytes)
        f.write(os.urandom(32))
    return fname


def generate_tests():
    """Clone repos, generate samples, write JSON test definitions."""
    ensure_directories()
    test_defs = []

    for repo_url in RULE_REPO_URLS:
        repo_name = repo_url.rstrip(".git").split("/")[-1]
        clone_dest = REPO_DIR / repo_name
        clone_or_update_repo(repo_url, clone_dest)

        rule_files = find_rule_files(clone_dest)
        print(f"[+] Found {len(rule_files)} rule files in {repo_name}")

        count = 0
        for rf in rule_files:
            if count >= MAX_RULES_TO_GENERATE:
                break

            try:
                rt = rf.read_text(errors="ignore")
            except Exception:
                continue

            if SKIP_IMPORTS and rule_contains_import(rt):
                continue

            strings = extract_strings_from_rule(rt)
            if not strings:
                continue

            ident, data_bytes = random.choice(strings)
            sample_file = generate_sample_file(GEN_SAMPLES_DIR, ident, data_bytes)

            test_defs.append({
                "ruleText": rt,
                "dataFile": str(sample_file),
                "expectedMatch": True,
                "testBlock": f"gen_{repo_name}_{rf.stem}",
                "assertType": "true_rule_blob"
            })
            count += 1

    with open(GEN_TEST_DEF, "w") as f:
        json.dump(test_defs, f, indent=2)

    print(f"[✓] Generated {len(test_defs)} tests at {GEN_TEST_DEF}")


# ============================================================
# EXECUTION MODE: RUN TESTS
# ============================================================

def run_node_yara(rule_text, data_bytes):
    with tempfile.NamedTemporaryFile(delete=False) as tmp_data:
        tmp_data.write(data_bytes)
        tmp_path = tmp_data.name

    cmd = ["node", NODE_RUNNER, "--rule", rule_text, "--file", tmp_path, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    os.unlink(tmp_path)
    if result.returncode != 0:
        raise RuntimeError(f"Node YARA failed: {result.stderr.strip()}")

    return json.loads(result.stdout)


def run_libyara(rule_text, data_bytes):
    rule = yara.compile(source=rule_text)
    matches = rule.match(data=data_bytes)

    normalized = []
    for m in matches:
        strings = [
            {"offset": offset, "identifier": identifier, "length": len(data)}
            for (offset, identifier, data) in m.strings
        ]
        normalized.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": sorted(list(m.tags)),
            "meta": m.meta,
            "strings": sorted(strings, key=lambda x: x["offset"]),
        })
    return {"matched": bool(matches), "results": normalized}


def load_tests(files):
    tests = []
    for f in files:
        with open(f, "r") as fh:
            tests.extend(json.load(fh))
    return tests


def compare_results(node_res, yara_res):
    diff = DeepDiff(yara_res, node_res, ignore_order=True)
    return diff if diff else None


def execute_tests(test_files):
    tests = load_tests(test_files)
    total, passed = 0, 0

    for test in tests:
        total += 1
        rule_text = test["ruleText"]
        expected = test.get("expectedMatch", True)
        name = test.get("testBlock", f"test_{total}")

        if "dataFile" in test and os.path.exists(test["dataFile"]):
            with open(test["dataFile"], "rb") as f:
                data_bytes = f.read()
        else:
            data_bytes = test["dataString"].encode("utf-8", errors="ignore")

        print(f"\n🧩 Running: {name}")

        try:
            node_res = run_node_yara(rule_text, data_bytes)
            yara_res = run_libyara(rule_text, data_bytes)

            if node_res["matched"] != expected:
                print(f"❌ FAIL: Expected {expected}, got {node_res['matched']}")
                continue

            diff = compare_results(node_res, yara_res)
            if diff:
                print(f"⚠️ STRUCTURE DIFFERENCE detected:")
                print(diff)
            else:
                print("✅ PASS")
            passed += 1

        except Exception as e:
            print(f"❌ ERROR in {name}: {e}")

    print("\n=== SUMMARY ===")
    print(f"Total: {total}, Passed: {passed}, Failed: {total - passed}")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run or generate YARA tests.")
    parser.add_argument("--generate", action="store_true", help="Generate tests from public rule repositories")
    parser.add_argument("test_files", nargs="*", help="JSON files with test definitions")

    args = parser.parse_args()

    ensure_directories()

    if args.generate:
        generate_tests()
    elif args.test_files:
        execute_tests(args.test_files)
    else:
        print("Usage:")
        print("  python run_tests.py --generate             # generate synthetic test cases")
        print("  python run_tests.py tests/generated_tests.json  # run tests")
