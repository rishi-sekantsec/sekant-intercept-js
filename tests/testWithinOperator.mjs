#!/usr/bin/env node
/**
 * Comprehensive Tests for YARA 'within' Operator
 * 
 * The 'within' operator checks if one string is within N bytes of another.
 * Syntax: $a within N of $b
 * Syntax: $a within N bytes of $b (bytes keyword is optional)
 * 
 * Returns true if any occurrence of $a is within N bytes of any occurrence of $b
 * (measured from start offset to start offset).
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { 
  test, 
  assertEquals, 
  assertTrue, 
  assertFalse, 
  printSummary 
} from './testingFramework.mjs';

console.log('🔍 YARA "within" Operator - Comprehensive Tests');
console.log('='.repeat(70));

/**
 * Create test data with known byte positions
 * @param {string} content - Content to encode
 * @returns {Uint8Array} Test data
 */
function createTestData(content) {
  const encoder = new TextEncoder();
  return encoder.encode(content);
}

// ============================================================================
// SECTION 1: Basic 'within' Operator Tests
// ============================================================================

console.log('\n📏 SECTION 1: Basic "within" Operator');
console.log('-'.repeat(70));

// Test 1.1: Strings within distance
await test('1.1 Strings within distance (exact)', async () => {
  // "AAAA" at 0, "BBBB" at 10 -> distance = 10
  const data = createTestData('AAAA......BBBB');
  const rule = `
    rule TestWithinExact {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - distance exactly 10');
});

// Test 1.2: Strings within distance (below threshold)
await test('1.2 Strings within distance (below threshold)', async () => {
  // "AAAA" at 0, "BBBB" at 5 -> distance = 5
  const data = createTestData('AAAA.BBBB');
  const rule = `
    rule TestWithinBelow {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - distance < threshold');
});

// Test 1.3: Strings NOT within distance (above threshold)
await test('1.3 Strings NOT within distance', async () => {
  // "AAAA" at 0, "BBBB" at 20 -> distance = 20
  const data = createTestData('AAAA................BBBB');
  const rule = `
    rule TestNotWithin {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 0, 'Should NOT match - distance > threshold');
});

// Test 1.4: Using "bytes" keyword (optional)
await test('1.4 Using "bytes" keyword (optional)', async () => {
  const data = createTestData('AAAA.....BBBB');
  const rule = `
    rule TestWithinBytes {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 15 bytes of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - "bytes" keyword works');
});

// Test 1.5: Zero distance (strings at same position)
await test('1.5 Zero distance (overlapping strings)', async () => {
  // Both strings start at position 0
  const data = createTestData('AAAABBBB');
  const rule = `
    rule TestZeroDistance {
      strings:
        $a = "AAAA"
        $b = "AAAA"
      condition:
        $a within 0 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - same string at same offset');
});

// ============================================================================
// SECTION 2: Multiple Occurrences
// ============================================================================

console.log('\n🔢 SECTION 2: Multiple Occurrences');
console.log('-'.repeat(70));

// Test 2.1: Multiple occurrences - any pair within distance
await test('2.1 Multiple occurrences - any within', async () => {
  // "test" at: 0, 50, 100
  // "data" at: 55
  // Distance 50->55 = 5 (within 10)
  const data = createTestData('test' + '.'.repeat(46) + 'test.....data' + '.'.repeat(40) + 'test');
  const rule = `
    rule TestMultipleAny {
      strings:
        $a = "test"
        $b = "data"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - one pair within distance');
});

// Test 2.2: Multiple occurrences - all pairs too far
await test('2.2 Multiple occurrences - none within', async () => {
  // "test" at: 0, 100
  // "data" at: 50
  // Closest: 50-0=50, 100-50=50 (both > 20)
  const data = createTestData('test' + '.'.repeat(46) + 'data' + '.'.repeat(46) + 'test');
  const rule = `
    rule TestMultipleNone {
      strings:
        $a = "test"
        $b = "data"
      condition:
        $a within 20 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 0, 'Should NOT match - all pairs too far');
});

// Test 2.3: Multiple occurrences of both strings
await test('2.3 Multiple occurrences of both strings', async () => {
  // "AAA" at: 0, 20
  // "BBB" at: 5, 25
  // Pairs within 10: 0-5 (dist=5), 20-25 (dist=5)
  const data = createTestData('AAA..BBB............AAA.....BBB');
  const rule = `
    rule TestMultipleBoth {
      strings:
        $a = "AAA"
        $b = "BBB"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - multiple valid pairs');
});

// Test 2.4: Overlapping matches
await test('2.4 Overlapping string matches', async () => {
  // Overlapping pattern matches
  const data = createTestData('ABCABCABC...XYZ');
  const rule = `
    rule TestOverlapping {
      strings:
        $a = /ABC/
        $b = "XYZ"
      condition:
        $a within 20 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match with overlapping patterns');
});

// ============================================================================
// SECTION 3: Direction Independence (Bidirectional)
// ============================================================================

console.log('\n↔️  SECTION 3: Direction Independence');
console.log('-'.repeat(70));

// Test 3.1: $a before $b
await test('3.1 Within works when $a before $b', async () => {
  // "AAAA" at 0, "BBBB" at 10
  const data = createTestData('AAAA......BBBB');
  const rule = `
    rule TestABeforeB {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 15 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - A before B');
});

// Test 3.2: $a after $b (reverse order)
await test('3.2 Within works when $a after $b', async () => {
  // "BBBB" at 0, "AAAA" at 10
  const data = createTestData('BBBB......AAAA');
  const rule = `
    rule TestAAfterB {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 15 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - A after B (bidirectional)');
});

// Test 3.3: Symmetric check (both directions)
await test('3.3 Symmetric bidirectional check', async () => {
  const data = createTestData('AAA........BBB');
  const rule = `
    rule TestSymmetric {
      strings:
        $a = "AAA"
        $b = "BBB"
      condition:
        ($a within 20 of $b) and ($b within 20 of $a)
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Both directions should match');
});

// ============================================================================
// SECTION 4: Complex Conditions
// ============================================================================

console.log('\n🔗 SECTION 4: Complex Conditions');
console.log('-'.repeat(70));

// Test 4.1: Combine with 'and'
await test('4.1 Combine within with and', async () => {
  const data = createTestData('AAA..BBB..CCC');
  const rule = `
    rule TestWithinAnd {
      strings:
        $a = "AAA"
        $b = "BBB"
        $c = "CCC"
      condition:
        $a within 10 of $b and $b within 10 of $c
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - chain of proximities');
});

// Test 4.2: Combine with 'or'
await test('4.2 Combine within with or', async () => {
  const data = createTestData('AAA' + '.'.repeat(100) + 'BBB');
  const rule = `
    rule TestWithinOr {
      strings:
        $a = "AAA"
        $b = "BBB"
        $c = "CCC"
      condition:
        ($a within 10 of $b) or ($a within 10 of $c)
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 0, 'Should NOT match - neither condition true');
});

// Test 4.3: Negation (not within)
await test('4.3 Negation - not within', async () => {
  const data = createTestData('AAA' + '.'.repeat(100) + 'BBB');
  const rule = `
    rule TestNotWithin {
      strings:
        $a = "AAA"
        $b = "BBB"
      condition:
        $a and $b and not ($a within 50 of $b)
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - NOT within distance');
});

// Test 4.4: Three-way proximity
await test('4.4 Three-way proximity check', async () => {
  // A, B, C all within 20 bytes of each other
  const data = createTestData('AAA.....BBB.....CCC');
  const rule = `
    rule TestThreeWay {
      strings:
        $a = "AAA"
        $b = "BBB"
        $c = "CCC"
      condition:
        $a within 20 of $b and $a within 20 of $c and $b within 20 of $c
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - triangular proximity');
});

// ============================================================================
// SECTION 5: Real-World Scenarios
// ============================================================================

console.log('\n🌍 SECTION 5: Real-World Scenarios');
console.log('-'.repeat(70));

// Test 5.1: API call clustering (malware detection)
await test('5.1 API call clustering', async () => {
  const data = createTestData('CreateProcess....WriteProcessMemory....VirtualAlloc');
  const rule = `
    rule APIClustering {
      strings:
        $api1 = "CreateProcess"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAlloc"
      condition:
        $api1 within 50 of $api2 and $api2 within 50 of $api3
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should detect clustered API calls');
});

// Test 5.2: Code injection pattern
await test('5.2 Code injection pattern detection', async () => {
  const data = createTestData('VirtualAlloc.....memcpy.....CreateThread');
  const rule = `
    rule CodeInjection {
      strings:
        $alloc = "VirtualAlloc"
        $copy = "memcpy"
        $thread = "CreateThread"
      condition:
        all of them and
        $alloc within 100 of $copy and
        $copy within 100 of $thread
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should detect code injection pattern');
});

// Test 5.3: Credential harvesting keywords
await test('5.3 Credential harvesting keywords proximity', async () => {
  const data = createTestData('password...login...credential');
  const rule = `
    rule CredentialHarvesting {
      strings:
        $cred1 = "password"
        $cred2 = "login"
        $cred3 = "credential"
      condition:
        2 of them and
        for any of ($cred*) : ($ within 30 of $cred1)
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should detect credential-related keywords');
});

// Test 5.4: Crypto algorithm indicators
await test('5.4 Crypto algorithm clustering', async () => {
  const data = createTestData('AES....encrypt....decrypt....key');
  const rule = `
    rule CryptoAlgorithm {
      strings:
        $algo = "AES"
        $enc = "encrypt"
        $dec = "decrypt"
        $key = "key"
      condition:
        3 of them and
        $algo within 50 of $enc and
        $enc within 50 of $dec
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should detect crypto clustering');
});

// Test 5.5: Network communication pattern
await test('5.5 Network communication pattern', async () => {
  const data = createTestData('socket..connect..send..recv');
  const rule = `
    rule NetworkComm {
      strings:
        $sock = "socket"
        $conn = "connect"
        $send = "send"
        $recv = "recv"
      condition:
        all of them and
        $sock within 40 of $conn and
        $conn within 40 of $send and
        $send within 40 of $recv
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should detect network pattern');
});

// ============================================================================
// SECTION 6: Edge Cases
// ============================================================================

console.log('\n⚠️  SECTION 6: Edge Cases');
console.log('-'.repeat(70));

// Test 6.1: String not found
await test('6.1 String not found - within fails', async () => {
  const data = createTestData('AAAA');
  const rule = `
    rule TestMissing {
      strings:
        $a = "AAAA"
        $b = "ZZZZ"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 0, 'Should NOT match - $b not found');
});

// Test 6.2: Both strings not found
await test('6.2 Both strings not found', async () => {
  const data = createTestData('XXXX');
  const rule = `
    rule TestBothMissing {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 0, 'Should NOT match - both strings missing');
});

// Test 6.3: Very large distance
await test('6.3 Very large distance threshold', async () => {
  const padding = '.'.repeat(10000);
  const data = createTestData('AAAA' + padding + 'BBBB');
  const rule = `
    rule TestLargeDistance {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 20000 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match with large distance');
});

// Test 6.4: Distance of 1 byte
await test('6.4 Distance of 1 byte', async () => {
  const data = createTestData('A.B');
  const rule = `
    rule TestOneByte {
      strings:
        $a = "A"
        $b = "B"
      condition:
        $a within 2 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - 1 byte apart');
});

// Test 6.5: Adjacent strings (touching)
await test('6.5 Adjacent strings (no gap)', async () => {
  const data = createTestData('AAAABBBB');
  const rule = `
    rule TestAdjacent {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 4 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - adjacent strings');
});

// Test 6.6: Same string as both operands
await test('6.6 Same string as both operands', async () => {
  const data = createTestData('test');
  const rule = `
    rule TestSameString {
      strings:
        $a = "test"
      condition:
        $a within 0 of $a
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should match - same string within 0 of itself');
});

// ============================================================================
// SECTION 7: Performance & Optimization
// ============================================================================

console.log('\n⚡ SECTION 7: Performance & Optimization');
console.log('-'.repeat(70));

// Test 7.1: Many occurrences (stress test)
await test('7.1 Many occurrences stress test', async () => {
  // Create data with many "A" and many "B"
  const data = createTestData('A.A.A.A.A.A.A.A.A.A.B.B.B.B.B.B.B.B.B.B');
  const rule = `
    rule TestManyOccurrences {
      strings:
        $a = "A"
        $b = "B"
      condition:
        $a within 30 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should handle many occurrences');
});

// Test 7.2: Regex patterns with within
await test('7.2 Regex patterns with within', async () => {
  const data = createTestData('func_123...call_456');
  const rule = `
    rule TestRegexWithin {
      strings:
        $func = /func_[0-9]{3}/
        $call = /call_[0-9]{3}/
      condition:
        $func within 20 of $call
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should work with regex patterns');
});

// Test 7.3: Hex patterns with within
await test('7.3 Hex patterns with within', async () => {
  const data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x50, 0x45, 0x00, 0x00]);
  const rule = `
    rule TestHexWithin {
      strings:
        $mz = { 4D 5A }
        $pe = { 50 45 }
      condition:
        $mz within 10 of $pe
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should work with hex patterns');
});

// ============================================================================
// SECTION 8: Combined with Other Operators
// ============================================================================

console.log('\n🔧 SECTION 8: Combined with Other Operators');
console.log('-'.repeat(70));

// Test 8.1: Within + at operator
await test('8.1 Combine within and at', async () => {
  const data = createTestData('MZ.....PE');
  const rule = `
    rule TestWithinAt {
      strings:
        $mz = "MZ"
        $pe = "PE"
      condition:
        $mz at 0 and $mz within 10 of $pe
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should combine within and at');
});

// Test 8.2: Within + in range
await test('8.2 Combine within and in', async () => {
  const data = createTestData('.....AAA..BBB');
  const rule = `
    rule TestWithinIn {
      strings:
        $a = "AAA"
        $b = "BBB"
      condition:
        $a in (0..10) and $a within 10 of $b
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should combine within and in');
});

// Test 8.3: Within + offset arithmetic
await test('8.3 Combine within and offset @', async () => {
  const data = createTestData('AAA.....BBB');
  const rule = `
    rule TestWithinOffset {
      strings:
        $a = "AAA"
        $b = "BBB"
      condition:
        $a within 20 of $b and (@b - @a) < 15
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should combine within and @ operator');
});

// Test 8.4: Within + length operator
await test('8.4 Combine within and length !', async () => {
  const data = createTestData('AAAA..BBBB');
  const rule = `
    rule TestWithinLength {
      strings:
        $a = "AAAA"
        $b = "BBBB"
      condition:
        $a within 10 of $b and !a == 4 and !b == 4
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should combine within and ! operator');
});

// Test 8.5: Within + for loop
await test('8.5 Combine within and for loop', async () => {
  const data = createTestData('A.B.C.X');
  const rule = `
    rule TestWithinFor {
      strings:
        $a = "A"
        $b = "B"
        $c = "C"
        $x = "X"
      condition:
        for any of ($a, $b, $c) : ($ within 10 of $x)
    }
  `;

  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  assertEquals(results.length, 1, 'Should combine within and for loops');
});

// ============================================================================
// Summary
// ============================================================================
printSummary();
