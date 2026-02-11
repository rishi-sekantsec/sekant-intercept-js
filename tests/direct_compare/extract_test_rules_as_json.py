#!/usr/bin/env python3
"""
Full-featured YARA rule test extractor

✅ Expands macros (TEXT_0063_BYTES, TEXT_1024_BYTES, etc.)
✅ Handles C string concatenation ("abc" TEXT_1024_BYTES)
✅ Extracts variables that use TEXT_* macros (e.g., blob[], multi_blob)
✅ Substitutes those variables when used in asserts
✅ Supports all assert variants:
     assert_true_rule(_blob/_file)
     assert_false_rule(_blob/_file)
✅ Outputs JSON [{ ruleText, dataString, expectedMatch, testBlock, assertType }]

Sample output:
[
  {
    "ruleText": "rule test { condition: true }",
    "dataString": "001[ 987654321 ... 004[...] ]\n---- a\0b\0c\0",
    "expectedMatch": true,
    "testBlock": "test_blob",
    "assertType": "true_rule_blob"
  }
]
"""

import re
import json
from pathlib import Path

# --------------------------------------------------------------------
# Macro definitions (from test-rules.c)
# --------------------------------------------------------------------
TEXT_0063_BYTES = "[ 987654321 987654321 987654321 987654321 987654321 987654321 ]"
TEXT_0256_BYTES_001 = "001" + TEXT_0063_BYTES * 4 + "\n"
TEXT_0256_BYTES_002 = "002" + TEXT_0063_BYTES * 4 + "\n"
TEXT_0256_BYTES_003 = "003" + TEXT_0063_BYTES * 4 + "\n"
TEXT_0256_BYTES_004 = "004" + TEXT_0063_BYTES * 4 + "\n"
TEXT_1024_BYTES = (
    TEXT_0256_BYTES_001
    + TEXT_0256_BYTES_002
    + TEXT_0256_BYTES_003
    + TEXT_0256_BYTES_004
)

MACROS = {
    "TEXT_0063_BYTES": TEXT_0063_BYTES,
    "TEXT_0256_BYTES_001": TEXT_0256_BYTES_001,
    "TEXT_0256_BYTES_002": TEXT_0256_BYTES_002,
    "TEXT_0256_BYTES_003": TEXT_0256_BYTES_003,
    "TEXT_0256_BYTES_004": TEXT_0256_BYTES_004,
    "TEXT_1024_BYTES": TEXT_1024_BYTES,
}

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def read_file(path):
    return Path(path).read_text(encoding="utf-8")

def remove_backslash_continuations(text):
    return re.sub(r"\\\s*\n\s*", "", text)

def unescape_c_string(s):
    """Convert C escape sequences like \n, \0, \\."""
    return bytes(s, "utf-8").decode("unicode_escape")

def expand_c_concatenation(expr: str, variables: dict = None) -> str:
    """Expand concatenated macros, strings, and variable references."""
    if variables is None:
        variables = {}

    token_re = re.compile(
        r'"(?:\\.|[^"\\])*"'      # string literal
        r"|[A-Za-z_][A-Za-z0-9_]*" # macro or identifier
        r"|\s+"
    )

    result = ""
    for tok in token_re.findall(expr):
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith('"') and tok.endswith('"'):
            inner = tok[1:-1]
            result += unescape_c_string(inner)
        elif tok in MACROS:
            result += MACROS[tok]
        elif tok in variables:
            result += variables[tok]
        elif tok == "NULL":
            continue
        else:
            result += tok
    return result

# --------------------------------------------------------------------
# Function & variable extraction
# --------------------------------------------------------------------
def extract_functions(text):
    """Find test_xxx() blocks."""
    funcs = []
    for m in re.finditer(r"static\s+void\s+(test_[A-Za-z0-9_]+)\s*\(\)\s*{", text):
        name = m.group(1)
        start = m.end()
        depth, i = 1, start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start:i - 1]
        funcs.append((name, body))
    return funcs

def extract_variables(body):
    """
    Extract variables defined with TEXT_* macros.
    e.g. uint8_t blob[] = TEXT_1024_BYTES "abc";
    """
    var_re = re.compile(
        r'\b(?:uint8_t|char|const\s+char)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*\])?\s*=\s*(.*?);',
        re.DOTALL,
    )
    variables = {}
    for m in var_re.finditer(body):
        name, expr = m.group(1), m.group(2).strip()
        if any(k in expr for k in MACROS):
            expanded = expand_c_concatenation(expr, variables)
            variables[name] = expanded
    return variables

# --------------------------------------------------------------------
# Assert extraction
# --------------------------------------------------------------------
def parse_asserts(body, func_name, variables):
    """
    Parse all assert_*_rule(_blob/_file)() calls in the test body.
    """
    pattern = re.compile(
        r'assert_(true_rule|false_rule)(?:_(blob|file))?\s*\(\s*(.*?)\s*,\s*(.*?)\s*\)',
        re.DOTALL
    )

    cases = []
    for m in pattern.finditer(body):
        base_type, subtype, rule_expr, data_expr = m.groups()
        expected = base_type.startswith("true")
        assert_type = f"{base_type}_{subtype}" if subtype else base_type

        rule_expr = rule_expr.strip()
        data_expr = data_expr.strip().rstrip(";")

        rule_text = expand_c_concatenation(rule_expr, variables)
        data_string = expand_c_concatenation(data_expr, variables)

        # If the data_expr is just a variable name, replace with its full expanded value
        if data_expr in variables:
            data_string = variables[data_expr]

        cases.append({
            "ruleText": rule_text,
            "dataString": data_string,
            "expectedMatch": expected,
            "testBlock": func_name,
            "assertType": assert_type
        })
    return cases

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    input_path = Path("test-rules.c")
    output_path = Path("yara_rule_tests_full.json")

    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    text = remove_backslash_continuations(read_file(input_path))
    all_cases = []

    for func_name, body in extract_functions(text):
        variables = extract_variables(body)
        cases = parse_asserts(body, func_name, variables)
        all_cases.extend(cases)

    output_path.write_text(json.dumps(all_cases, indent=2, ensure_ascii=False))
    print(f"Extracted {len(all_cases)} test cases → {output_path}")

if __name__ == "__main__":
    main()

