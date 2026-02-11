#!/usr/bin/env python3
"""
yara_test_harness_with_html.py

Enhanced harness:
 - generates a curated safe rule set (no imports)
 - runs libyara (optional) and your Node engine (via NODE_SCAN_CMD_TEMPLATE)
 - compares results and writes JSON + HTML report
 - optionally writes libyara baseline file "expected_outputs.json"

Config at top. Safe defaults (no malware downloads). Carefully read warnings before enabling malware features.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from jinja2 import Template
from tqdm import tqdm

# === CONFIG ===
WORKDIR = Path("yara_test_workspace")
CURATED_RULES_DIR = WORKDIR / "curated_rules"
TEST_FILES_DIR = WORKDIR / "test_files"
RULES_DIR = WORKDIR / "rules"
CONCAT_RULES_PATH = WORKDIR / "concat_rules.yar"
USE_LIBYARA = True              # set False if yara-python isn't installed
USE_MALWARE_DOWNLOAD = False    # do NOT enable unless in sandbox
MALWARE_DIR = WORKDIR / "malware_samples"
NODE_SCAN_CMD_TEMPLATE = "node node_yara_cli.js --rules {rules} --file {file} --json"
OUTPUT_JSON = WORKDIR / "yara_test_report.json"
OUTPUT_HTML = WORKDIR / "yara_test_report.html"
PRODUCE_LIBYARA_BASELINE = True  # writes expected_outputs.json using libyara (if available)
# === END CONFIG ===

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: str, cwd: Optional[Path]=None, timeout: Optional[int]=300) -> Tuple[int,str,str]:
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, text=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return -1, out, err + "\n[Timeout]"
    return proc.returncode, out, err

def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# -------------------------
# Curated rule generation
# -------------------------
# Generate a set of safe rules (no 'import'). These cover many YARA features.
def generate_curated_rules(outdir: Path):
    ensure_dir(outdir)
    rules = []

    # small helper to create rule strings
    def add(name, body):
        rules.append((name, body))

    # 1. Basic string rules
    add("rule_basic_simple",
r'''
rule basic_simple
{
    meta:
        author = "curated"
    strings:
        $a = "HelloWorld"
        $b = "dummy_imports"
    condition:
        $a or $b
}
''')

    add("rule_fullword_nocase",
r'''
rule fullword_nocase
{
    strings:
        $a = "Hello" nocase fullword
    condition:
        $a
}
''')

    # 2. Hex string with wildcard and jump
    add("rule_hex_wild_jump",
r'''
rule hex_wild_jump
{
    strings:
        $h = { 90 90 ?? DE AD BE EF [2-6] 90 }
    condition:
        $h
}
''')

    # 3. Wide/base64-like and base64wide (simulate)
    add("rule_wide_and_base64like",
r'''
rule wide_and_base64like
{
    strings:
        $s1 = "HelloWorld" wide
        $s2 = "SGVsbG9Xb3JsZA==" nocase
    condition:
        $s1 or $s2
}
''')

    # 4. Regex examples
    add("rule_regex_examples",
r'''
rule regex_examples
{
    strings:
        $r1 = /T[aeiou]st\w+/
        $r2 = /foo(bar)?/
    condition:
        $r1 or $r2
}
''')

    # 5. Occurrence indexing and counts (1-based)
    add("rule_occurrence_indexing",
r'''
rule occurrence_indexing
{
    strings:
        $a = "dup"
    condition:
        #a >= 2 and @a[1] < @a[2]
}
''')

    # 6. int8/16/32 checks (file offset)
    add("rule_int_checks",
r'''
rule int_checks_example
{
    strings:
        $magic = "MZ"
    condition:
        for any i in (0..10) : ( uint16(i) == 0x5A4D )  // checks 'MZ' as little-endian
}
''')

    # 7. Loop & arithmetic with indexing (demonstrates i+1 for @a)
    add("rule_loop_and_index",
r'''
rule loop_and_index
{
    strings:
        $x = "A" wide
        $y = "B"
    condition:
        for i in (0..#x - 1) : ( @x[i + 1] < filesize )
}
''')

    # 8. hex-range edge conditions
    add("rule_hex_ranges",
r'''
rule hex_ranges
{
    strings:
        $h = { 00 [1-3] 11 22 33 }
    condition:
        $h
}
''')

    # 9. fullword vs partial tests
    add("rule_fullword_edge",
r'''
rule fullword_edge
{
    strings:
        $a = "test" fullword
        $b = "teste"
    condition:
        $a and not $b
}
''')

    # 10. combine boolean & regex
    add("rule_boolean_regex",
r'''
rule boolean_regex
{
    strings:
        $r = /bad\w+/
        $s = "marker"
    condition:
        ($r and $s) or 1 == 0
}
''')

    # 11. tags & metadata heavy
    add("rule_meta_tags",
r'''
rule meta_tags
{
    meta:
        desc = "metadata heavy"
        severity = "low"
    strings:
        $m = "dummy_meta_marker"
    condition:
        $m
}
''')

    # 12. multiple matches & ordering
    add("rule_multiple_strings",
r'''
rule multiple_strings
{
    strings:
        $a = "Alpha"
        $b = "Beta"
        $c = "Gamma"
    condition:
        all of them
}
''')

    # 13. file size checks
    add("rule_filesize_checks",
r'''
rule filesize_checks
{
    condition:
        filesize < 1MB
}
''')

    # 14. XOR-like byte sequence (useful test for hex rules)
    add("rule_xor_like",
r'''
rule xor_like_pattern
{
    strings:
        $p = { AA BB CC DD EE }
    condition:
        $p
}
''')

    # 15. nested for and numeric comparisons
    add("rule_nested_loops",
r'''
rule nested_loops
{
    strings:
        $a = "dup"
    condition:
        for i in (1..#a) : ( for j in (1..#a) : ( @a[i] != @a[j] => i == j ) )
}
''')

    # 16. anchors (begin/end of file)
    add("rule_anchors",
r'''
rule anchors
{
    strings:
        $h = "HEAD" at 0
        $t = "TAIL" at (filesize - 4)
    condition:
        $h or $t
}
''')

    # 17. negative tests and not
    add("rule_negative_test",
r'''
rule negative_test
{
    strings:
        $bad = "malicious_signature"
    condition:
        not $bad
}
''')

    # 18. tag combinators and tags
    add("rule_tag_combo",
r'''
rule tag_combo
{
    tags: test curated
    strings:
        $t = "tagged_marker"
    condition:
        $t
}
''')

    # 19. hashed string sample (string data used to check hashes)
    add("rule_hash_like_string",
r'''
rule hash_like_string
{
    strings:
        $h = "SHA256_MARKER"
    condition:
        $h
}
''')

    # 20. hex with repeats
    add("rule_hex_repeats",
r'''
rule hex_repeats
{
    strings:
        $r = { 90{4} }
    condition:
        $r
}
''')

    # 21. unicode / wide tests
    add("rule_unicode_wide",
r'''
rule unicode_wide
{
    strings:
        $u = "こんにちは" wide
    condition:
        $u
}
''')

    # 22. time/math-like numeric check (simulate math module)
    add("rule_math_time_sim",
r'''
rule math_time_sim
{
    condition:
        ( 2 * 3 + 4 ) == 10
}
''')

    # 23. long hex substring
    add("rule_long_hex",
r'''
rule long_hex
{
    strings:
        $l = { 01 02 03 04 05 06 07 08 09 0A 0B 0C }
    condition:
        $l
}
''')

    # 24. regex with flags (if engine supports)
    add("rule_regex_flags",
r'''
rule regex_flags
{
    strings:
        $r = /hello.*world/ wide
    condition:
        $r
}
''')

    # 25. overlapping matches test
    add("rule_overlap",
r'''
rule overlap
{
    strings:
        $a = "aaa"
    condition:
        #a > 1
}
''')

    # 26. literal hex edge-case
    add("rule_literal_hex_edge",
r'''
rule literal_hex_edge
{
    strings:
        $h = { 0A 0B 0C ?? 0F }
    condition:
        $h
}
''')

    # 27. expression precedence
    add("rule_expr_precedence",
r'''
rule expr_precedence
{
    strings:
        $x = "X"
    condition:
        (1 + 2) * 3 == 9 and $x
}
''')

    # 28. constant equality & booleans
    add("rule_constants",
r'''
rule constants
{
    condition:
        true and not false
}
''')

    # 29. string modifiers combined
    add("rule_modifiers_combo",
r'''
rule modifiers_combo
{
    strings:
        $a = "AbCd" nocase wide
    condition:
        $a
}
''')

    # 30. condition using filesize / filemodtime (if supported)
    add("rule_filesize_time",
r'''
rule filesize_time
{
    condition:
        filesize >= 0
}
''')

    # 31. anchored hex at offset
    add("rule_hex_at_offset",
r'''
rule hex_at_offset
{
    strings:
        $h = { DE AD BE EF } at 100
    condition:
        $h
}
''')

    # 32. dynamic string concatenation (synthetic)
    add("rule_dynamic_string",
r'''
rule dynamic_string
{
    strings:
        $a = "dyn"
        $b = "amic"
    condition:
        $a and $b
}
''')

    # 33. condition using all of / any of with ranges
    add("rule_all_any",
r'''
rule all_any
{
    strings:
        $a1 = "one"
        $a2 = "two"
        $a3 = "three"
    condition:
        any of ($a*)
}
''')

    # 34. test hex wildcard at end
    add("rule_hex_wild_end",
r'''
rule hex_wild_end
{
    strings:
        $e = { AA BB ?? }
    condition:
        $e
}
''')

    # 35. complex boolean combos
    add("rule_complex_booleans",
r'''
rule complex_booleans
{
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        ($a and not $b) or (filesize < 10000)
}
''')

    # 36. simulated module tests (PE/ELF fields embedded in dummy files)
    add("rule_pe_string_probe",
r'''
rule pe_string_probe
{
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz and $pe
}
''')

    add("rule_elf_string_probe",
r'''
rule elf_string_probe
{
    strings:
        $elf = { 7F 45 4C 46 }  // "\x7fELF"
    condition:
        $elf
}
''')

    # 37. numeric and bitwise
    add("rule_bitwise",
r'''
rule bitwise
{
    condition:
        (0xFF & 0x0F) == 0x0F
}
''')

    # 38. small fuzz-safety rules
    add("rule_fuzz_safety",
r'''
rule fuzz_safety
{
    strings:
        $a = "zzzzzz"
    condition:
        $a
}
''')

    # 39. hex with alternation (simulated using multiple hex strings)
    add("rule_hex_alts",
r'''
rule hex_alts
{
    strings:
        $h1 = { DE AD }
        $h2 = { BE EF }
    condition:
        $h1 or $h2
}
''')

    # 40. long ASCII string
    add("rule_long_ascii",
r'''
rule long_ascii
{
    strings:
        $l = "This program cannot be run in DOS mode"
    condition:
        $l
}
''')

    # 41-70: generate many minor variants to reach a larger curated set
    for i in range(41, 71):
        add(f"rule_variant_{i}",
f'''
rule variant_{i}
{{
    strings:
        $s = "variant_marker_{i}"
        $p = {{ {i:02X} {i+1:02X} {i+2:02X} }}
    condition:
        $s or $p
}}
''')

    # Write each rule into a separate .yar file
    for idx, (name, body) in enumerate(rules):
        fn = outdir / f"{idx:03d}_{name}.yar"
        fn.write_text(body.strip() + "\n")
    print(f"Generated {len(rules)} curated rules into {outdir}")

# -------------------------
# Test file generation
# -------------------------
def create_safe_test_files(outdir: Path):
    ensure_dir(outdir)
    (outdir / "eicar.txt").write_bytes(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    (outdir / "hello.txt").write_text("HelloWorld\nThis is a test file.\n")
    (outdir / "hello_hello.txt").write_text("HelloWorldHelloWorldHello")
    (outdir / "marker.bin").write_bytes(b"\x90\x90\xDE\xAD\xBE\xEF\x90\x90")
    (outdir / "pe_dummy.exe").write_bytes(b"MZ" + b"\x00" * 128 + b"PE" + b"dummy_marker_variant_45")
    (outdir / "elf_dummy").write_bytes(b"\x7fELF" + b"\x00" * 128 + b"variant_marker_50")
    # Additional files to exercise variants
    for i in range(41, 71):
        fname = outdir / f"file_variant_{i}.bin"
        content = (f"variant_marker_{i}\n").encode("utf-8") + bytes([i, i+1, i+2]) * 3
        fname.write_bytes(content)
    print(f"Created safe test files under {outdir}")

# -------------------------
# YARA/libyara wrapper (if available)
# -------------------------
def try_import_yara():
    try:
        import yara
        return yara
    except Exception as e:
        print("yara-python import failed:", e)
        return None

def compile_and_scan_with_libyara(rules_path: Path, file_path: Path) -> Dict:
    yara_mod = try_import_yara()
    if yara_mod is None:
        raise RuntimeError("yara-python not available")
    rules = yara_mod.compile(str(rules_path))
    matches = []
    def on_match(m):
        items = {
            "rule": m.rule,
            "meta": dict(m.meta) if hasattr(m, "meta") else {},
            "strings": [],
            "tags": list(getattr(m, "tags", []))
        }
        for s in m.strings:
            items["strings"].append({
                "offset": int(s[0]),
                "id": s[1].decode("utf-8") if isinstance(s[1], bytes) else str(s[1]),
                "data": s[2].hex()[:300]
            })
        matches.append(items)
        return yara_mod.CALLBACK_CONTINUE
    rules.scan(str(file_path), callback=on_match)
    return {"file": str(file_path), "matches": matches}

# -------------------------
# Node runner wrapper
# -------------------------
def run_node_scan(cmd_template: str, rules_path: Path, file_path: Path) -> Dict:
    cmd = cmd_template.format(rules=str(rules_path), file=str(file_path))
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        return {"file": str(file_path), "error": f"exit {rc}", "stdout": out, "stderr": err}
    try:
        return json.loads(out)
    except Exception as e:
        return {"file": str(file_path), "error": f"json_parse_error: {e}", "stdout": out, "stderr": err}

# -------------------------
# Comparison & normalization
# -------------------------
def normalize_match_set(match_struct: Dict) -> Dict:
    norm = {"file": match_struct.get("file")}
    if "error" in match_struct:
        norm["error"] = match_struct["error"]
        return norm
    matches = match_struct.get("matches", [])
    rules_map = {}
    for m in matches:
        rname = m.get("rule")
        strings = m.get("strings", [])
        strings_sorted = sorted(strings, key=lambda s: (s.get("id"), int(s.get("offset", 0))))
        rules_map[rname] = {
            "meta": m.get("meta", {}),
            "strings": strings_sorted,
            "tags": sorted(m.get("tags", []))
        }
    norm["matches"] = rules_map
    return norm

def compare_results(ref: Dict, subject: Dict) -> Dict:
    r = normalize_match_set(ref)
    s = normalize_match_set(subject)
    out = {"file": r.get("file"), "only_in_ref": [], "only_in_subject": [], "mismatches": []}
    if "error" in r or "error" in s:
        out["error_ref"] = r.get("error")
        out["error_subject"] = s.get("error")
        return out
    ref_rules = set(r["matches"].keys())
    subj_rules = set(s["matches"].keys())
    for rr in sorted(ref_rules - subj_rules):
        out["only_in_ref"].append(rr)
    for rr in sorted(subj_rules - ref_rules):
        out["only_in_subject"].append(rr)
    for rr in sorted(ref_rules & subj_rules):
        a = r["matches"][rr]
        b = s["matches"][rr]
        astrs = [(st["id"], int(st["offset"])) for st in a["strings"]]
        bstrs = [(st["id"], int(st["offset"])) for st in b["strings"]]
        if astrs != bstrs:
            out["mismatches"].append({
                "rule": rr,
                "ref_strings": astrs,
                "subject_strings": bstrs
            })
    return out

# -------------------------
# HTML report generation (simple templating)
# -------------------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>YARA Test Report</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 20px; }
    .summary { margin-bottom: 1.5rem; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1rem; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f4f4f4; }
    .pass { background: #e6ffed; }
    .fail { background: #ffe6e6; }
    pre { white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
  <h1>YARA Test Report</h1>
  <div class="summary">
    <strong>Generated:</strong> {{ generated_at }}<br>
    <strong>Total files:</strong> {{ total }} &nbsp; <strong>Passed:</strong> {{ passed }} &nbsp; <strong>Diffs:</strong> {{ diffs }}
  </div>

  <h2>Per-file results</h2>
  <table>
    <tr><th>File</th><th>SHA256</th><th>Result</th><th>Details</th></tr>
    {% for f in files %}
    <tr class="{{ 'pass' if f.ok else 'fail' }}">
      <td>{{ f.short }}</td>
      <td><code>{{ f.sha }}</code></td>
      <td>{{ 'PASS' if f.ok else 'DIFF' }}</td>
      <td>
        {% if f.comp.error_ref or f.comp.error_subject %}
          <strong>Errors:</strong><br>
          ref: {{ f.comp.error_ref }}<br>
          subj: {{ f.comp.error_subject }}
        {% else %}
          {% if f.comp.only_in_ref %}
            <strong>Only in ref:</strong> {{ f.comp.only_in_ref }}<br>
          {% endif %}
          {% if f.comp.only_in_subject %}
            <strong>Only in subject:</strong> {{ f.comp.only_in_subject }}<br>
          {% endif %}
          {% if f.comp.mismatches %}
            <strong>Mismatches:</strong>
            <ul>
            {% for m in f.comp.mismatches %}
              <li><strong>{{ m.rule }}</strong>
                  <div><small>ref_strings: {{ m.ref_strings }}</small></div>
                  <div><small>subject_strings: {{ m.subject_strings }}</small></div>
              </li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </table>

  <h2>Raw JSON report</h2>
  <pre>{{ raw_json }}</pre>
</body>
</html>
"""

# -------------------------
# Main harness
# -------------------------
def main():
    print("Starting enhanced YARA test harness")
    ensure_dir(WORKDIR)
    ensure_dir(CURATED_RULES_DIR)
    ensure_dir(TEST_FILES_DIR)
    ensure_dir(RULES_DIR)

    # 1) generate curated rules
    generate_curated_rules(CURATED_RULES_DIR)

    # 2) concatenate curated rules into single file (skip none, they're all import-free)
    all_rules = sorted(CURATED_RULES_DIR.glob("*.yar"))
    concat_text = []
    for p in all_rules:
        concat_text.append(f"// {p.name}\n")
        concat_text.append(p.read_text())
        concat_text.append("\n")
    CONCAT_RULES_PATH.write_text("\n".join(concat_text))
    print(f"Wrote concatenated rules to {CONCAT_RULES_PATH}")

    # 3) create safe test files
    create_safe_test_files(TEST_FILES_DIR)

    # 4) build test file list
    test_files = sorted([p for p in TEST_FILES_DIR.iterdir() if p.is_file()])
    print(f"Test files: {len(test_files)}")

    # 5) run libyara baseline if available and requested
    baseline_results = {}
    if USE_LIBYARA and PRODUCE_LIBYARA_BASELINE:
        yara_mod = try_import_yara()
        if yara_mod:
            print("Running libyara baseline scans...")
            for f in tqdm(test_files):
                try:
                    r = compile_and_scan_with_libyara(CONCAT_RULES_PATH, f)
                    baseline_results[str(f)] = r
                except Exception as e:
                    baseline_results[str(f)] = {"file": str(f), "error": str(e)}
            # save baseline
            baseline_path = WORKDIR / "expected_outputs.json"
            baseline_path.write_text(json.dumps(baseline_results, indent=2))
            print(f"Wrote libyara baseline to {baseline_path}")
        else:
            print("libyara not available; skipping baseline.")
    else:
        print("Skipping libyara baseline (disabled or not requested).")

    # 6) run node scans
    subject_results = {}
    print("Running Node engine scans...")
    for f in tqdm(test_files):
        res = run_node_scan(NODE_SCAN_CMD_TEMPLATE, CONCAT_RULES_PATH, f)
        subject_results[str(f)] = res

    # 7) compare (if baseline exists) else write subject-only report
    report = {"generated_at": datetime.utcnow().isoformat() + "Z", "file_results": []}
    total = 0
    passed = 0
    diffs = 0
    for f in sorted([str(p) for p in test_files]):
        total += 1
        ref = baseline_results.get(f, {"file": f, "error": "no_reference"}) if baseline_results else {"file": f, "error": "no_reference"}
        subj = subject_results.get(f, {"file": f, "error": "no_subject"})
        comp = compare_results(ref, subj)
        sha = compute_sha256(Path(f))
        ok = False
        if comp.get("error_ref") or comp.get("error_subject"):
            ok = False
            diffs += 1
        elif comp["only_in_ref"] or comp["only_in_subject"] or comp["mismatches"]:
            ok = False
            diffs += 1
        else:
            ok = True
            passed += 1
        report["file_results"].append({
            "file": f,
            "sha256": sha,
            "ref_raw": ref,
            "subject_raw": subj,
            "comparison": comp,
            "ok": ok
        })
    report["summary"] = {"total": total, "passed": passed, "diffs": diffs}
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2))
    print(f"Wrote JSON report to {OUTPUT_JSON}")

    # 8) write HTML report
    t = Template(HTML_TEMPLATE)
    files_for_html = []
    for entry in report["file_results"]:
        short = Path(entry["file"]).name
        files_for_html.append({
            "short": short,
            "sha": entry["sha256"],
            "ok": entry["ok"],
            "comp": entry["comparison"]
        })
    html = t.render(generated_at=report["generated_at"], total=total, passed=passed, diffs=diffs, files=files_for_html, raw_json=json.dumps(report, indent=2))
    OUTPUT_HTML.write_text(html)
    print(f"Wrote HTML report to {OUTPUT_HTML}")

    print(f"Summary: {passed}/{total} passed, {diffs} diffs")

if __name__ == "__main__":
    main()

