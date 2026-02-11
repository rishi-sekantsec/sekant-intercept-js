#!/bin/bash
# Compare Node.js and Python YARA implementations
# Usage: ./compare_runners.sh <rulefile> <testfile>

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <rulefile> <testfile>"
    echo "Example: $0 rules/basic.yar test_files/basic.txt"
    exit 1
fi

RULEFILE=$1
TESTFILE=$2

echo "========================================="
echo "YARA Implementation Comparison"
echo "========================================="
echo "Rule: $RULEFILE"
echo "File: $TESTFILE"
echo ""

echo "--- Simple Output (MATCH/NO MATCH) ---"
echo ""
echo "Node.js Implementation:"
node tests/direct_compare/node_yara_runner.js --rulefile "$RULEFILE" --file "$TESTFILE"
echo ""
echo "Python Implementation:"
python3 tests/direct_compare/py_yara_runner.py --rulefile "$RULEFILE" --file "$TESTFILE"
echo ""

echo "========================================="
echo "JSON Output Comparison"
echo "========================================="
echo ""
echo "--- Node.js JSON Output ---"
node tests/direct_compare/node_yara_runner.js --rulefile "$RULEFILE" --file "$TESTFILE" --json > /tmp/node_output.json
cat /tmp/node_output.json | python3 -m json.tool | head -50
echo "... (truncated)"
echo ""

echo "--- Python JSON Output ---"
python3 tests/direct_compare/py_yara_runner.py --rulefile "$RULEFILE" --file "$TESTFILE" --json > /tmp/python_output.json
cat /tmp/python_output.json | python3 -m json.tool | head -50
echo "... (truncated)"
echo ""

echo "========================================="
echo "Match Count Comparison"
echo "========================================="
echo ""
echo "Node.js match counts:"
cat /tmp/node_output.json | python3 -c "import sys, json; data=json.load(sys.stdin); [print(f\"  {k}: {v['count']} matches\") for match in data['matches'] for k,v in match['strings'].items()]"
echo ""
echo "Python match counts:"
cat /tmp/python_output.json | python3 -c "import sys, json; data=json.load(sys.stdin); [print(f\"  {k}: {v['count']} matches\") for match in data['matches'] for k,v in match['strings'].items()]"
echo ""

echo "========================================="
echo "Done!"
echo "Full outputs saved to:"
echo "  /tmp/node_output.json"
echo "  /tmp/python_output.json"
echo "========================================="
