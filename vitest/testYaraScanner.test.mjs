/**
 * End-to-End YARA Scanner Tests
 * 
 * Tests the complete scanner pipeline:
 * 1. Rule compilation
 * 2. String pattern matching
 * 3. Aho-Corasick candidate detection
 * 4. Candidate verification
 * 5. Condition evaluation
 * 6. Final result generation
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { createMathModule } from '../src/mathModule.mjs';
import { 
  numberedTest as test,
  assertEquals,
  assertTrue,
  assertArrayLength,
  assertContains,
  printSummary
} from './testingFramework.mjs';

// ============================================================================
// Main Test Execution
// ============================================================================

async function runTests() {
  // ============================================================================
  // Section 1: Basic Scanner Functionality
  // ============================================================================

  console.log('\n=== Section 1: Basic Scanner Functionality ===\n');

  await test('Scanner initialization', async () => {
  const scanner = new InterceptScanner();
  assertTrue(scanner !== null);
  const stats = scanner.getStats();
  assertEquals(stats.totalRules, 0);
});

await test('Add simple rule', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule TestRule {
      strings:
        $a = "hello"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  const stats = scanner.getStats();
  assertEquals(stats.totalRules, 1);
});

await test('Add multiple rules', async () => {
  const scanner = new InterceptScanner();
  const rules = `
    rule Rule1 {
      strings:
        $a = "test1"
      condition:
        $a
    }
    
    rule Rule2 {
      strings:
        $b = "test2"
      condition:
        $b
    }
  `;
  scanner.addRules(rules);
  const stats = scanner.getStats();
  assertEquals(stats.totalRules, 2);
});

await test('Clear scanner', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules('rule Test { strings: $a = "x" condition: $a }');
  scanner.clear();
  const stats = scanner.getStats();
  assertEquals(stats.totalRules, 0);
});

// ============================================================================
// Section 2: Simple String Matching
// ============================================================================

console.log('\n=== Section 2: Simple String Matching ===\n');

await test('Match simple text string', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule SimpleMatch {
      strings:
        $a = "hello"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('This is hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1, 'Should match one rule');
  assertEquals(results[0].rule, 'SimpleMatch');
});

await test('No match when string not present', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule NoMatch {
      strings:
        $a = "missing"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('This is hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 0, 'Should match zero rules');
});

await test('Match multiple strings', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule MultiString {
      strings:
        $a = "hello"
        $b = "world"
      condition:
        $a and $b
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'MultiString');
});

await test('Case-insensitive matching with nocase', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule CaseInsensitive {
      strings:
        $a = "HELLO" nocase
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'CaseInsensitive');
});

// ============================================================================
// Section 3: Quantifier Conditions
// ============================================================================

console.log('\n=== Section 3: Quantifier Conditions ===\n');

await test('any of them - at least one match', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule AnyOfThem {
      strings:
        $a = "foo"
        $b = "bar"
        $c = "baz"
      condition:
        any of them
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('This has bar in it');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'AnyOfThem');
});

await test('all of them - all must match', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule AllOfThem {
      strings:
        $a = "foo"
        $b = "bar"
      condition:
        all of them
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('foo bar');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'AllOfThem');
});

await test('all of them - fails when not all match', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule AllRequired {
      strings:
        $a = "foo"
        $b = "missing"
      condition:
        all of them
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('foo bar');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 0);
});

await test('N of them - exactly N strings', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule TwoOfThem {
      strings:
        $a = "one"
        $b = "two"
        $c = "three"
      condition:
        2 of them
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('one two');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'TwoOfThem');
});

// ============================================================================
// Section 4: Logical Operators
// ============================================================================

console.log('\n=== Section 4: Logical Operators ===\n');

await test('AND operator - both conditions required', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule AndCondition {
      strings:
        $a = "alpha"
        $b = "beta"
      condition:
        $a and $b
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('alpha beta gamma');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
});

await test('OR operator - either condition sufficient', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule OrCondition {
      strings:
        $a = "alpha"
        $b = "missing"
      condition:
        $a or $b
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('alpha gamma');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
});

await test('NOT operator - negates condition', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule NotCondition {
      strings:
        $a = "present"
        $b = "absent"
      condition:
        $a and not $b
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('present here');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
});

// ============================================================================
// Section 5: Multiple Rules
// ============================================================================

console.log('\n=== Section 5: Multiple Rules ===\n');

await test('Multiple rules - different matches', async () => {
  const scanner = new InterceptScanner();
  const rules = `
    rule Rule1 {
      strings:
        $a = "foo"
      condition:
        $a
    }
    
    rule Rule2 {
      strings:
        $b = "bar"
      condition:
        $b
    }
  `;
  scanner.addRules(rules);
  
  const data = new TextEncoder().encode('foo bar');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 2);
  const ruleNames = results.map(r => r.rule).sort();
  assertContains(ruleNames, 'Rule1');
  assertContains(ruleNames, 'Rule2');
});

await test('Multiple rules - selective matching', async () => {
  const scanner = new InterceptScanner();
  const rules = `
    rule MatchThis {
      strings:
        $a = "present"
      condition:
        $a
    }
    
    rule NotThis {
      strings:
        $b = "absent"
      condition:
        $b
    }
  `;
  scanner.addRules(rules);
  
  const data = new TextEncoder().encode('present here');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'MatchThis');
});

// ============================================================================
// Section 6: Hex Patterns
// ============================================================================

console.log('\n=== Section 6: Hex Patterns ===\n');

await test('Match hex pattern', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule HexPattern {
      strings:
        $hex = { 48 65 6C 6C 6F }
      condition:
        $hex
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('Hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'HexPattern');
});

await test('Match hex with wildcards', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule HexWildcard {
      strings:
        $hex = { 48 ?? 6C 6C 6F }
      condition:
        $hex
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('Hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
});

// ============================================================================
// Section 7: Regular Expressions
// ============================================================================

console.log('\n=== Section 7: Regular Expressions ===\n');

await test('Match regex pattern', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule RegexPattern {
      strings:
        $re = /[Hh]ello/
      condition:
        $re
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('Hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'RegexPattern');
});

await test('Regex case-insensitive flag', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule RegexNoCase {
      strings:
        $re = /HELLO/i
      condition:
        $re
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('hello world');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
});

// ============================================================================
// Section 8: Real-World PE Detection
// ============================================================================

console.log('\n=== Section 8: Real-World PE Detection ===\n');

await test('Detect PE file signature', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule IsPE {
      strings:
        $mz = { 4D 5A }
      condition:
        $mz
    }
  `;
  scanner.addRules(rule);
  
  const data = new Uint8Array(100);
  data[0] = 0x4D; // M
  data[1] = 0x5A; // Z
  
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'IsPE');
});

await test('PE with suspicious strings', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule SuspiciousPE {
      strings:
        $mz = { 4D 5A }
        $api1 = "CreateProcess"
        $api2 = "VirtualAlloc"
      condition:
        $mz and ($api1 or $api2)
    }
  `;
  scanner.addRules(rule);
  
  const data = new Uint8Array(200);
  data[0] = 0x4D;
  data[1] = 0x5A;
  const api = new TextEncoder().encode('CreateProcess');
  api.forEach((byte, i) => {
    data[100 + i] = byte;
  });
  
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'SuspiciousPE');
});

// ============================================================================
// Section 9: Module Integration
// ============================================================================

console.log('\n=== Section 9: Module Integration ===\n');

await test('Math module integration', async () => {
  const scanner = new InterceptScanner();
  
  // Create test data with high entropy section
  const data = new Uint8Array(2000);
  for (let i = 1000; i < 2000; i++) {
    data[i] = Math.floor(Math.random() * 256);
  }
  
  const mathModule = createMathModule(data);
  scanner.setModules({ math: mathModule });
  
  const rule = `
    rule HighEntropy {
      strings:
        $a = "test"
      condition:
        any of them or filesize > 0
    }
  `;
  scanner.addRules(rule);
  
  const results = await scanner.scan(data);
  
  // Just verify scanner works with modules set
  assertTrue(results !== null);
});

// ============================================================================
// Section 10: Performance & Edge Cases
// ============================================================================

console.log('\n=== Section 10: Performance & Edge Cases ===\n');

await test('Empty data', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule EmptyTest {
      strings:
        $a = "test"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  const data = new Uint8Array(0);
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 0);
});

await test('Large data scan', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule LargeDataTest {
      strings:
        $a = "needle"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  // Create 100KB of data with needle in the middle
  const data = new Uint8Array(100000);
  const needle = new TextEncoder().encode('needle');
  needle.forEach((byte, i) => {
    data[50000 + i] = byte;
  });
  
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'LargeDataTest');
});

await test('String input conversion', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule StringInput {
      strings:
        $a = "test"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  // Pass string instead of Uint8Array
  const results = await scanner.scan('this is a test');
  
  assertArrayLength(results, 1);
});

await test('Multiple occurrences of same string', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule MultiOccurrence {
      strings:
        $a = "foo"
      condition:
        $a
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('foo bar foo baz foo');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'MultiOccurrence');
  
  // Check that we captured multiple matches
  const matches = results[0].strings.$a;
  assertTrue(matches.count >= 3, 'Should find at least 3 occurrences');
});

await test('Overlapping patterns', async () => {
  const scanner = new InterceptScanner();
  const rules = `
    rule Pattern1 {
      strings:
        $a = "abc"
      condition:
        $a
    }
    
    rule Pattern2 {
      strings:
        $b = "bcd"
      condition:
        $b
    }
  `;
  scanner.addRules(rules);
  
  const data = new TextEncoder().encode('abcd');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 2, 'Both overlapping patterns should match');
});

// ============================================================================
// Section 11: Complex Malware Detection
// ============================================================================

console.log('\n=== Section 11: Complex Malware Detection ===\n');

await test('Ransomware indicators', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule Ransomware {
      strings:
        $encrypt = "CryptEncrypt"
        $ransom = "bitcoin"
        $ext1 = ".locked"
        $ext2 = ".encrypted"
      condition:
        $encrypt and $ransom and 1 of ($ext*)
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('CryptEncrypt function bitcoin payment .locked file');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'Ransomware');
});

await test('Backdoor detection', async () => {
  const scanner = new InterceptScanner();
  const rule = `
    rule Backdoor {
      strings:
        $net1 = "connect"
        $net2 = "socket"
        $cmd = "cmd.exe"
        $shell = "/bin/sh"
      condition:
        ($net1 or $net2) and ($cmd or $shell)
    }
  `;
  scanner.addRules(rule);
  
  const data = new TextEncoder().encode('socket connection to cmd.exe');
  const results = await scanner.scan(data);
  
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'Backdoor');
  });

  // ============================================================================
  // Summary
  // ============================================================================

  printSummary();
}

// Run all tests
runTests().catch(error => {
  console.error('Fatal error running tests:', error);
  printSummary();
});
