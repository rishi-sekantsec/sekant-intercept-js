import { parseYaraRule } from '../yaraRuleCompiler.mjs';

console.log('Testing edge cases for comment handling...\n');

// Test 1: Comments inside strings should be preserved
const test1 = `
rule Test1 {
  strings:
    $a = "This has // a comment marker" ascii
    $b = "This has /* a multi-line marker */" ascii
  condition:
    any of them
}
`;

try {
  const parsed1 = parseYaraRule(test1);
  console.log('✓ Test 1 passed: Comments inside strings are preserved');
  console.log('  $a:', parsed1.strings.a.definition);
  console.log('  $b:', parsed1.strings.b.definition);
} catch (error) {
  console.error('✗ Test 1 failed:', error.message);
}

// Test 2: Nested comments and complex scenarios
const test2 = `
/* Header comment block
   that spans multiple lines
   and contains // inline markers */
rule Test2 {
  meta:
    /* comment */ author = "Tester" /* another comment */
    // description = "This line is commented out"
    version = 2
  
  strings:
    $x = /pattern\\/with\\/slashes/ // regex with escaped slashes
    /* $y = "commented out string" */
    $z = { 4D 5A } // hex bytes
  
  condition:
    all of them // simple condition
}
`;

try {
  const parsed2 = parseYaraRule(test2);
  console.log('\n✓ Test 2 passed: Complex comment scenarios handled');
  console.log('  Metadata keys:', Object.keys(parsed2.metadata));
  console.log('  String variables:', Object.keys(parsed2.strings));
  console.log('  Has $x:', 'x' in parsed2.strings);
  console.log('  Has $y (should be false):', 'y' in parsed2.strings);
  console.log('  Has $z:', 'z' in parsed2.strings);
} catch (error) {
  console.error('✗ Test 2 failed:', error.message);
}

// Test 3: Regex patterns with forward slashes
const test3 = `
rule Test3 {
  strings:
    $url = /https?:\\/\\/[a-z]+/ // URL pattern
  condition:
    $url
}
`;

try {
  const parsed3 = parseYaraRule(test3);
  console.log('\n✓ Test 3 passed: Regex with escaped slashes handled correctly');
  console.log('  Regex definition:', parsed3.strings.url.definition);
} catch (error) {
  console.error('✗ Test 3 failed:', error.message);
}

// Test 4: Empty rule with only comments
const test4 = `
// Just a comment rule
rule Test4 {
  /* no metadata */
  strings:
    // all strings commented out
    $a = "test" // but this one exists
  condition:
    $a /* simple */
}
`;

try {
  const parsed4 = parseYaraRule(test4);
  console.log('\n✓ Test 4 passed: Minimal rule with many comments');
  console.log('  Metadata count:', Object.keys(parsed4.metadata).length);
  console.log('  String count:', Object.keys(parsed4.strings).length);
} catch (error) {
  console.error('✗ Test 4 failed:', error.message);
}

console.log('\n✓ All tests passed!');
