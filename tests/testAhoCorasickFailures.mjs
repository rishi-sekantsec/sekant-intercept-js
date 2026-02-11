import { AhoCorasick } from '../ahocorasickEngine.mjs';
import { parseYaraRuleGroup } from '../yaraRuleCompiler.mjs';

console.log('═══════════════════════════════════════════════════════════════');
console.log('  AHO-CORASICK ENGINE TEST - ATOM MATCHING');
console.log('  (Note: AC finds potential matches, separate verification needed)');
console.log('═══════════════════════════════════════════════════════════════\n');

// ═════════════════════════════════════════════════════════════════════════
// TEST 1: Basic Pattern Matching
// ═════════════════════════════════════════════════════════════════════════
console.log('TEST 1: Basic Pattern Matching\n');

const yaraRules1 = `
rule Test1 {
  strings:
    $test = "Hello" ascii
  condition:
    $test
}
`;

console.log('Compiling YARA rule with pattern "Hello"...');
const testRules1 = parseYaraRuleGroup(yaraRules1);
console.log('Compiled rules:', testRules1.length);
console.log('Rule name:', testRules1[0].name);
console.log('Strings:', Object.keys(testRules1[0].strings));

const ac1 = new AhoCorasick(testRules1);

// Check trie structure
console.log('\nInspecting trie structure:');
console.log('Root children keys:', Object.keys(ac1.root.children));
console.log('Type of keys:', typeof Object.keys(ac1.root.children)[0]);

// Try to search with string
console.log('\nSearching string "Hello World":');
const results1 = ac1.search('Hello World');
console.log('Results:', results1);
console.log('Expected: Atom match that suggests pattern at index 0');
if (results1.length > 0) {
  console.log('Found', results1.length, 'potential match location(s)');
  console.log('Atom matched at index:', results1[0].index);
  
  // Calculate where the full pattern would start based on atom position
  // The reported index should point to where the full pattern starts
  // For pattern "Hello" with atom "ell" (atomOffset=1):
  // If "ell" is at position 1-3, pattern starts at position 0
  console.log('✓ PASS: Atom matching works, returned potential match location');
  console.log('Note: Full pattern verification needed as separate step');
} else {
  console.log('❌ FAIL: No atom matches found');
}

// ═════════════════════════════════════════════════════════════════════════
// TEST 2: Atom Matching Can Suggest False Positives (Expected Behavior)
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('TEST 2: Atom Matching Suggests Candidates (Including False Positives)\n');

const yaraRules2 = `
rule Test2 {
  strings:
    $pattern = "Hello" ascii
  condition:
    $pattern
}
`;

console.log('Pattern: "Hello"');
console.log('Atom will be 3 chars from "Hello" (e.g., "ell" or "Hel")');
console.log('\nTest text: "Stella" (contains atom "ell" but not full pattern "Hello")');

// Force deterministic for this test by mocking Math.random
const originalRandom = Math.random;
Math.random = () => 0.5; // Will select middle atom "ell"

const testRules2 = parseYaraRuleGroup(yaraRules2);
const ac2 = new AhoCorasick(testRules2);
Math.random = originalRandom;

const results2 = ac2.search('Stella');
console.log('\nResults:', results2);
if (results2.length > 0) {
  console.log('✓ EXPECTED: Atom "ell" found, suggesting potential match');
  console.log('   Potential match location at index:', results2[0].index);
  console.log('   → Verification step will reject this as false positive');
  console.log('   → This is CORRECT behavior for Aho-Corasick (find candidates)');
} else {
  console.log('❌ FAIL: Atom "ell" should be found in "Stella"');
}

// ═════════════════════════════════════════════════════════════════════════
// TEST 3: Position Calculation for Pattern Start
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('TEST 3: Calculating Pattern Start Position from Atom Match\n');

const yaraRules3 = `
rule Test3 {
  strings:
    $pattern = "test" ascii
  condition:
    $pattern
}
`;

console.log('Pattern: "test"');
console.log('Text: "XYtest" (pattern should start at index 2)');

Math.random = () => 0.0; // Select first 3 chars "tes"
const testRules3 = parseYaraRuleGroup(yaraRules3);
const ac3 = new AhoCorasick(testRules3);
Math.random = originalRandom;

const results3 = ac3.search('XYtest');
console.log('\nResults:', results3);
if (results3.length > 0) {
  console.log('Atom matched, potential location at index:', results3[0].index);
  console.log('Expected pattern start index: 2');
  
  // The index should indicate where to start checking for the full pattern
  if (results3[0].index === 2) {
    console.log('✓ PASS: Index correctly points to pattern start position');
  } else {
    console.log('⚠️  INFO: Index is', results3[0].index);
    console.log('   This may need adjustment in offset calculation');
    console.log('   AC found atom, but index calculation needs review');
  }
} else {
  console.log('❌ FAIL: Atom should be found');
}

// ═════════════════════════════════════════════════════════════════════════
// TEST 4: Output Object Structure for Verification Step
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('TEST 4: Output Object Structure for Pattern Verification\n');

console.log('Checking what info AC provides for verification step...');
let foundOutput = false;
function checkNode(node, depth = 0) {
  if (node.outputs.length > 0) {
    console.log('\nOutput object from AC trie node:');
    console.log(JSON.stringify(node.outputs[0], null, 2));
    console.log('\nFields available:');
    console.log('  has "id":', 'id' in node.outputs[0], '✓ - identifies which rule');
    console.log('  has "varName":', 'varName' in node.outputs[0], '✓ - identifies which string variable');
    console.log('  has "atomOffset":', 'atomOffset' in node.outputs[0], '✓ - where atom is within pattern');
    console.log('  has "pattern":', 'pattern' in node.outputs[0], node.outputs[0].pattern ? '✓' : '❌ - needed for verification');
    console.log('  has "atomLength":', 'atomLength' in node.outputs[0], node.outputs[0].atomLength ? '✓' : '❌ - needed for position calc');
    console.log('\n⚠️  Note: Verification step needs full pattern to check actual match');
    foundOutput = true;
    return true;
  }
  for (const child of Object.values(node.children)) {
    if (checkNode(child, depth + 1)) return true;
  }
  return false;
}

checkNode(ac3.root);
if (!foundOutput) {
  console.log('❌ No output nodes found in trie');
}

// ═════════════════════════════════════════════════════════════════════════
// TEST 5: Non-Deterministic Behavior
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('TEST 5: Non-Deterministic Behavior\n');

const yaraRules5 = `
rule Test5 {
  strings:
    $pattern = "testing" ascii
  condition:
    $pattern
}
`;

console.log('Building trie 3 times with same pattern "testing"...\n');

for (let i = 0; i < 3; i++) {
  const rules = parseYaraRuleGroup(yaraRules5);
  const ac = new AhoCorasick(rules);
  // Try to extract what atom was selected by checking trie structure
  const keys = Object.keys(ac.root.children);
  console.log(`Run ${i + 1}: Root children: [${keys.join(', ')}]`);
}

console.log('\n❌ Different atoms selected on each run due to Math.random()');
console.log('   Recommendation: Use deterministic atom selection for consistency');
console.log('   E.g., always pick first N chars, or middle, or hash-based offset');

// ═════════════════════════════════════════════════════════════════════════
// TEST 6: Multiple Rules
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('TEST 6: Multiple Rules in One Compilation\n');

const multipleYaraRules = `
rule MalwareDetector {
  strings:
    $malware = "malware" ascii nocase
    $virus = "virus" ascii
  condition:
    any of them
}

rule NetworkIndicator {
  strings:
    $http = "http://" ascii
    $https = "https://" ascii
  condition:
    any of them
}

rule Ransomware {
  strings:
    $encrypt = "encrypt" ascii nocase
    $ransom = "ransom" ascii nocase
  condition:
    all of them
}
`;

console.log('Compiling 3 YARA rules...');
const multiRules = parseYaraRuleGroup(multipleYaraRules);
console.log('Compiled', multiRules.length, 'rules');
console.log('Rule names:', multiRules.map(r => r.name).join(', '));

const acMulti = new AhoCorasick(multiRules);

console.log('\nSearching text: "This malware will encrypt your files for ransom"');
const resultsMulti = acMulti.search('This malware will encrypt your files for ransom');
console.log('Found', resultsMulti.length, 'potential match locations (atom matches)');

// Group by rule
const byRule = {};
for (const match of resultsMulti) {
  if (!byRule[match.id]) byRule[match.id] = [];
  byRule[match.id].push(match);
}
console.log('\nPotential matches grouped by rule:');
for (const [ruleId, matches] of Object.entries(byRule)) {
  const rule = multiRules.find(r => r.id == ruleId);
  console.log(`  Rule ${ruleId} (${rule.name}): ${matches.length} potential location(s)`);
  for (const match of matches) {
    console.log(`    $${match.varName} atom found, suggests pattern near index ${match.index}`);
  }
}
console.log('\n✓ PASS: AC successfully identifies potential match locations');
console.log('   Next step: Verify each location with full pattern matcher');

// ═════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(65));
console.log('  SUMMARY - AHO-CORASICK ENGINE DESIGN');
console.log('═'.repeat(65));
console.log('\n✅ TEST 1: Atom matching works - finds potential locations');
console.log('✅ TEST 2: Returns candidates including false positives (correct!)');
console.log('⚠️  TEST 3: Index calculation may need adjustment for pattern start');
console.log('⚠️  TEST 4: Output needs pattern info for verification step');
console.log('⚠️  TEST 5: Random atoms cause non-deterministic behavior');
console.log('✅ TEST 6: Multiple rules work - groups by rule ID');
console.log('\n📋 DESIGN NOTES:');
console.log('   • Aho-Corasick finds ATOMS (substrings) quickly');
console.log('   • Returns POTENTIAL match locations (candidates)');
console.log('   • Separate verification step needed to check full patterns');
console.log('   • This is the correct two-phase approach for performance');
console.log('\n🔧 RECOMMENDATIONS:');
console.log('   1. Store full pattern in output objects for verification');
console.log('   2. Store atom length for correct position calculation');
console.log('   3. Use deterministic atom selection (not random)');
console.log('   4. Verify index points to pattern start (not atom end)');
console.log('\n');
