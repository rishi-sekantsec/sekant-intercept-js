#!/usr/bin/env node
/**
 * Compare Node.js and Python YARA implementations
 * Compares actual JSON structure, not string formatting
 */

import { spawn } from "child_process";
import { argv, exit } from "process";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function parseArgs() {
  if (argv.length < 4) {
    console.error("Usage: node compare_implementations.mjs <rulefile> <testfile>");
    console.error("Example: node compare_implementations.mjs rules/basic.yar test_files/basic.txt");
    exit(1);
  }
  return {
    rulefile: argv[2],
    testfile: argv[3],
  };
}

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args);
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`Command failed with code ${code}: ${stderr}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

async function runNodeImplementation(rulefile, testfile) {
  const runnerPath = join(__dirname, 'node_yara_runner.js');
  const output = await runCommand("node", [runnerPath, "--rulefile", rulefile, "--file", testfile, "--json"]);
  return JSON.parse(output);
}

async function runPythonImplementation(rulefile, testfile) {
  const runnerPath = join(__dirname, 'py_yara_runner.py');
  const output = await runCommand("python3", [runnerPath, "--rulefile", rulefile, "--file", testfile, "--json"]);
  return JSON.parse(output);
}

function compareStringMatches(nodeStr, pyStr, stringId) {
  const differences = [];

  // Compare matched status
  const nodeMatch = nodeStr?.matched ?? false;
  const pyMatch = pyStr?.matched ?? false;
  if (nodeMatch !== pyMatch) {
    differences.push(`  ${stringId}: matched status differs (Node: ${nodeMatch}, Python: ${pyMatch})`);
  }

  // Compare count
  const nodeCount = nodeStr?.count ?? 0;
  const pyCount = pyStr?.count ?? 0;
  if (nodeCount !== pyCount) {
    differences.push(`  ${stringId}: count differs (Node: ${nodeCount}, Python: ${pyCount})`);
  }

  // Compare offsets
  const nodeOffsets = nodeMatch ? nodeStr.offsets.sort((a, b) => a - b) : [];
  const pyOffsets = pyMatch ? pyStr.offsets.sort((a, b) => a - b) : [];
  const nodeOffsetsSet = new Set(nodeOffsets);
  const pyOffsetsSet = new Set(pyOffsets);
  if (nodeOffsets.length !== pyOffsets.length || ![...nodeOffsetsSet].every((x) => pyOffsetsSet.has(x))) {
    differences.push(`  ${stringId}: offsets differ (Showing first 100)`);
    differences.push(
      `    Node offsets: [${nodeOffsets
        .filter((n) => !pyOffsetsSet.has(n))
        .slice(0, 100)
        .join(", ")}]`
    );
    differences.push(
      `    Python offsets: [${pyOffsets
        .filter((p) => !nodeOffsetsSet.has(p))
        .slice(0, 100)
        .join(", ")}]`
    );
  }

  // Compare match details
  const nodeMatchLength = nodeStr?.matches?.length ?? 0;
  const pyMatchLength = pyStr?.matches?.length ?? 0;
  if (nodeMatchLength !== pyMatchLength) {
    differences.push(`  ${stringId}: number of match details differs (Node: ${nodeMatchLength}, Python: ${pyMatchLength})`);
  }
  const nMatches = new Set(
    nodeStr?.matches?.map((m) => {
      return `${m.offset}:${m.length}:${m.isWide ?? false}`;
    }) ?? []
  );
  const pMatches = new Set(
    pyStr?.matches?.map((m) => {
      return `${m.offset}:${m.length}:${m.isWide ?? false}`;
    }) ?? []
  );
  //   for (const n of nMatches) {
  //     if (!pMatches.has(n)) {
  //       differences.push(`  ${stringId}: node differs (offset:length:isWide): ${n}`);
  //     }
  //   }
  //   for (const p of pMatches) {
  //     if (!nMatches.has(p)) {
  //       differences.push(`  ${stringId}: python differs (offset:length:isWide): ${p}`);
  //     }
  //   }

  return differences;
}

function compareResults(nodeResult, pyResult) {
  console.log("=========================================");
  console.log("YARA Implementation Comparison");
  console.log("=========================================\n");

  const differences = [];

  // Compare number of matches
  if (nodeResult.matches.length !== pyResult.matches.length) {
    differences.push(`Number of rule matches differs (Node: ${nodeResult.matches.length}, Python: ${pyResult.matches.length})`);
    console.log(`❌ MISMATCH: Different number of rule matches (Node: ${nodeResult.matches.length}, Python: ${pyResult.matches.length})\n`);
    const allMatchedRules = new Set();
    nodeResult.matches.forEach((v) => allMatchedRules.add(v.rule));
    pyResult.matches.forEach((v) => allMatchedRules.add(v.rule));
    for (const ruleName of allMatchedRules) {
      const nodeMatch = nodeResult.matches.find((m) => m.rule === ruleName);
      const pyMatch = pyResult.matches.find((m) => m.rule === ruleName);

      if (!nodeMatch) {
        differences.push(`Rule ${ruleName} missing in Node.js implementation`);
        console.log(`❌ MISMATCH: Rule ${ruleName} missing in Node.js implementation\n`);
        continue;
      }
      if (!pyMatch) {
        differences.push(`Rule ${ruleName} missing in Python implementation`);
        console.log(`❌ MISMATCH: Rule ${ruleName} missing in Python implementation\n`);
        continue;
      }
    }
    return false;
  }

  // Convert array to JSON
  const nodeResultMap = {},
    pyResultMap = {};
  nodeResult.matches.forEach((v) => (nodeResultMap[v.rule] = v));
  pyResult.matches.forEach((v) => (pyResultMap[v.rule] = v));

  // Compare each match
  for (const ruleName in nodeResultMap) {
    const nodeMatch = nodeResultMap[ruleName];
    const pyMatch = pyResultMap[ruleName];

    console.log(`Rule: ${nodeMatch.rule}`);
    console.log("-----------------------------------------");

    if (!(nodeMatch && pyMatch)) {
      differences.push(`Rule ${ruleName} missing in ${nodeMatch ? "" : "node"} ${pyMatch ? "" : "python"} implementation(s)`);
      console.log(`❌ MISMATCH: Rule ${ruleName} missing in ${nodeMatch ? "" : "node"} ${pyMatch ? "" : "python"} implementation(s)\n`);
      continue;
    }

    // Compare rule name
    if (nodeMatch.rule !== pyMatch.rule) {
      differences.push(`Rule name differs (Node: ${nodeMatch.rule}, Python: ${pyMatch.rule})`);
    }

    // Compare namespace
    if (nodeMatch.namespace !== pyMatch.namespace) {
      differences.push(`Namespace differs (Node: ${nodeMatch.namespace}, Python: ${pyMatch.namespace})`);
    }

    // Compare metadata
    if (JSON.stringify(nodeMatch.metadata) !== JSON.stringify(pyMatch.metadata)) {
      differences.push("Metadata differs");
      differences.push(`  Node: ${JSON.stringify(nodeMatch.metadata)}`);
      differences.push(`  Python: ${JSON.stringify(pyMatch.metadata)}`);
    }

    // Compare strings
    const nodeStrings = Object.keys(nodeMatch.strings).sort();
    const pyStrings = Object.keys(pyMatch.strings).sort();

    // Note: Python yara doesn't include non-matching strings in output
    // Filter to only matched strings for fair comparison
    const nodeMatchedStrings = nodeStrings.filter((id) => nodeMatch.strings[id].matched);
    const pyMatchedStrings = pyStrings.filter((id) => pyMatch.strings[id].matched);
    const matchedInNodeNotPy = nodeMatchedStrings.filter((id) => !pyMatch.strings[id]?.matched);
    const matchedInPyNotNode = pyMatchedStrings.filter((id) => !nodeMatch.strings[id]?.matched);

    if (matchedInNodeNotPy.length > 0 || matchedInPyNotNode.length > 0) {
      differences.push(`Matched string identifiers differ`);
      if (matchedInNodeNotPy.length > 0) differences.push(`  Node: [${matchedInNodeNotPy.join(", ")}]`);
      if (matchedInPyNotNode.length > 0) differences.push(`  Python: [${matchedInPyNotNode.join(", ")}]`);
    }

    // Note about non-matching strings
    // const nodeNonMatchedStrings = nodeStrings.filter((id) => !nodeMatch.strings[id].matched);
    // const pyNonMatchedStrings = pyStrings.filter((id) => !pyMatch.strings[id].matched);
    // const nonMatchedInNodeNotPy = nodeNonMatchedStrings.filter((id) => (pyMatch.strings[id]?.matched));
    // const nonMatchedInPyNotNode = pyNonMatchedStrings.filter((id) => (nodeMatch.strings[id]?.matched));
    // if (nonMatchedInNodeNotPy.length > 0 || nonMatchedInPyNotNode.length > 0) {
    //   console.log(`  ℹ️  Node.js includes ${nodeNonMatched.length} non-matching string(s): ${nodeNonMatched.join(", ")}`);
    //   console.log(`     (Python yara doesn't include non-matching strings in output)`);
    // }

    // Compare each string's matches
    const allMatchedString = Array.from(new Set([...nodeStrings, ...pyStrings]));
    for (const stringId of allMatchedString.toSorted()) {
      const stringDiffs = compareStringMatches(nodeMatch.strings[stringId], pyMatch.strings[stringId], stringId);
      differences.push(...stringDiffs);

      // Print summary for this string
      const nodeStr = nodeMatch.strings[stringId];
      const pyStr = pyMatch.strings[stringId];
      const matchStatus = (nodeStr?.matched ?? false) === (pyStr?.matched ?? false) && (nodeStr?.count ?? 0) === (pyStr?.count ?? 0) ? "✓" : "✗";

      console.log(`  ${matchStatus} ${stringId}: Node=${nodeStr?.count ?? 0} matches, Python=${pyStr?.count ?? 0} matches`);
    }

    console.log();
  }

  // Print overall results
  console.log("=========================================");
  console.log("Summary");
  console.log("=========================================");

  if (differences.length === 0) {
    console.log("✅ PERFECT MATCH: Both implementations produce identical results!\n");

    // Print detailed match summary
    console.log("Match Details:");
    for (const match of nodeResult.matches) {
      console.log(`  Rule "${match.rule}":`);
      const matchedStrings = Object.keys(match.strings).filter((id) => match.strings[id].matched);
      for (const stringId of matchedStrings) {
        const str = match.strings[stringId];
        console.log(`    ${stringId}: ${str.count} matches at offsets [${str.offsets.join(", ")}]`);
      }
    }
    console.log();

    return true;
  } else {
    console.log(`❌ DIFFERENCES FOUND: ${differences.length} difference(s)\n`);
    console.log("Differences:");
    differences.forEach((diff) => console.log(diff));
    console.log();
    return false;
  }
}

async function main() {
  const args = parseArgs();

  console.log(`Comparing implementations for:`);
  console.log(`  Rule: ${args.rulefile}`);
  console.log(`  File: ${args.testfile}\n`);

  try {
    console.log("Running Node.js implementation...");
    const nodeStartTime = performance.now();
    const nodeResult = await runNodeImplementation(args.rulefile, args.testfile);
    const nodeEndTime = performance.now();
    const nodeRuntime = nodeEndTime - nodeStartTime;
    console.log(`  Completed in ${nodeRuntime.toFixed(2)}ms\n`);

    console.log("Running Python implementation...");
    const pyStartTime = performance.now();
    const pyResult = await runPythonImplementation(args.rulefile, args.testfile);
    const pyEndTime = performance.now();
    const pyRuntime = pyEndTime - pyStartTime;
    console.log(`  Completed in ${pyRuntime.toFixed(2)}ms\n`);

    console.log("Runtime Comparison:");
    console.log(`  Node.js: ${nodeRuntime.toFixed(2)}ms`);
    console.log(`  Python:  ${pyRuntime.toFixed(2)}ms`);
    const faster = nodeRuntime < pyRuntime ? "Node.js" : "Python";
    const speedup = nodeRuntime < pyRuntime ? (pyRuntime / nodeRuntime).toFixed(2) : (nodeRuntime / pyRuntime).toFixed(2);
    console.log(`  ${faster} is ${speedup}x faster\n`);

    console.log("Comparing results...\n");

    const match = compareResults(nodeResult, pyResult);

    // console.log(JSON.stringify(nodeResult, null, 2));
    // console.log(JSON.stringify(pyResult, null, 2));

    exit(match ? 0 : 1);
  } catch (error) {
    console.trace(error);
    exit(1);
  }
}

main();
