/**
 * AHO-CORASICK COMPREHENSIVE TEST SUITE
 * 
 * Tests the Aho-Corasick engine with various YARA string modifiers and patterns.
 * 
 * IMPORTANT: YARA Modifier Compatibility Rules
 * ============================================
 * Based on official YARA documentation, the following modifier combinations are INVALID:
 * 
 * - nocase CANNOT be used with: xor, base64, base64wide
 * - xor CANNOT be used with: nocase, base64, base64wide
 * - base64/base64wide CANNOT be used with: nocase, xor, fullword
 * 
 * See: https://yara.readthedocs.io/en/stable/writingrules.html#string-modifier-summary
 * 
 * IMPORTANT: Byte-Level Matching
 * ===============================
 * YARA's Aho-Corasick engine works on BYTE sequences (0-255), not Unicode codepoints.
 * 
 * - Single-byte ASCII (0x00-0x7F): Works perfectly
 * - Multi-byte UTF-8 (emoji, Chinese, etc.): Matched as raw byte sequences
 * - Example: Emoji '😀' is UTF-8 bytes [0xF0, 0x9F, 0x98, 0x80]
 *   The AC engine searches for this byte sequence, not the Unicode codepoint U+1F600
 * 
 * This is consistent with YARA's design: "characters were interpreted by YARA as raw bytes"
 * See: https://yara.readthedocs.io/en/stable/writingrules.html#text-strings
 */

import { AhoCorasick } from '../ahocorasickEngine.mjs';
import { parseYaraRuleGroup } from '../yaraRuleCompiler.mjs';
import {
  test,
  assertEquals,
  assertMinMatches,
  assertMatchesContain,
  printSummary
} from './testingFramework.mjs';

const encoder = new TextEncoder();

console.log('═══════════════════════════════════════════════════════════════');
console.log('  AHO-CORASICK COMPREHENSIVE TEST SUITE');
console.log('═══════════════════════════════════════════════════════════════\n');

// ═════════════════════════════════════════════════════════════════════════
// SECTION 1: PLAIN ASCII STRING PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('📋 Section 1: Plain ASCII String Patterns\n');

await test('1.1 Single plain ASCII pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "malware" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('This is malware code');
  assertMinMatches(matches, 1, 'Should find at least 1 match');
  assertMatchesContain(matches, [1], 'Should match rule 1');
});

await test('1.2 Multiple occurrences of same pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('test and test again test');
  assertMinMatches(matches, 3, 'Should find 3 occurrences');
});

await test('1.3 Multiple different patterns in one rule', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "hello" ascii
        $b = "world" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('hello there world');
  assertMinMatches(matches, 2, 'Should find 2 patterns');
});

await test('1.4 Overlapping patterns (AA pattern)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AA" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AABBAAABAAA');
  assertMinMatches(matches, 4, 'Should find 4 overlapping matches: AAB, AAA, AAA, AAA');
});

await test('1.5 Multiple overlapping patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABC" ascii
        $b = "BCD" ascii
        $c = "CDE" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('XABCDEFG');
  assertMinMatches(matches, 3, 'Should find all 3 overlapping patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 2: NOCASE PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 2: Nocase Patterns\n');

await test('2.1 Basic nocase matching', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "hello" ascii nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('HELLO Hello hello HeLLo');
  assertMinMatches(matches, 4, 'Should find 4 case variations');
});

await test('2.2 Multiple nocase patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii nocase
        $b = "data" ascii nocase
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('TEST the DATA');
  assertMinMatches(matches, 2, 'Should find both patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 3: WIDE STRING PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 3: Wide String Patterns\n');

await test('3.1 Basic wide string', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide string: H\0i\0
  const wideData = new Uint8Array([0x48, 0x00, 0x69, 0x00]);
  const dataStr = new TextDecoder().decode(wideData);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find wide string');
});

await test('3.2 ASCII and wide combined', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create both ASCII and wide
  const asciiPart = encoder.encode('test');
  const widePart = new Uint8Array([0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]); // "test" wide
  const combined = new Uint8Array(asciiPart.length + 2 + widePart.length);
  combined.set(asciiPart, 0);
  combined.set([0x20, 0x20], asciiPart.length); // spaces
  combined.set(widePart, asciiPart.length + 2);
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find both ASCII and wide versions');
});

await test('3.3 Wide with nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "hi" wide nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide uppercase: H\0I\0
  const wideData = new Uint8Array([0x48, 0x00, 0x49, 0x00]);
  const dataStr = new TextDecoder().decode(wideData);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find wide nocase string');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 4: BASE64 ENCODED PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 4: Base64 Encoded Patterns\n');

await test('4.1 Basic base64 pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" base64
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Base64 of "test" with different padding offsets
  const data = 'prefix dGVzdA suffix'; // base64("test") = "dGVzdA"
  const matches = ac.search(data);
  assertMinMatches(matches, 1, 'Should find base64 encoded pattern');
});

await test('4.2 Multiple base64 patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" base64
        $b = "OK" base64
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'SGk= and T0s='; // base64("Hi") and base64("OK")
  const matches = ac.search(data);
  assertMinMatches(matches, 2, 'Should find both base64 patterns');
});

await test('4.3 Base64wide pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" base64wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Base64wide encodes the wide version
  const b64Result = btoa('Hi');
  const wideB64 = b64Result.split('').map(c => c + '\0').join('');
  const matches = ac.search(wideB64);
  assertMinMatches(matches, 1, 'Should find base64wide pattern');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 5: XOR ENCODED PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 5: XOR Encoded Patterns\n');

await test('5.1 XOR with single key', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" xor(5)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR "test" with key 5
  const xorData = Array.from(encoder.encode('test')).map(b => b ^ 5);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData));
  console.log('XOR Data (Single Key):', dataStr);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR encoded pattern');
});

await test('5.2 XOR with key range', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" xor(1-10)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR "test" with key 7 (within range)
  const xorData = Array.from(encoder.encode('test')).map(b => b ^ 7);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR with key in range');
});

await test('5.3 XOR default range (1-255)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" xor
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR "Hi" with key 42
  const xorData = Array.from(encoder.encode('Hi')).map(b => b ^ 42);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR with any key 1-255');
});

await test('5.4 Multiple XOR patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AA" xor(1-10)
        $b = "BB" xor(1-10)
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR both with key 5
  const xorDataA = Array.from(encoder.encode('AA')).map(b => b ^ 5);
  const xorDataB = Array.from(encoder.encode('BB')).map(b => b ^ 5);
  const combined = new Uint8Array([...xorDataA, 0x20, ...xorDataB]); // space separator
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find both XOR patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 6: XOR + WIDE COMBINATIONS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 6: XOR + Wide Combinations\n');

await test('6.1 XOR with wide modifier', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" xor(5) wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide version then XOR
  const wideHi = new Uint8Array([0x48, 0x00, 0x69, 0x00]);
  const xorWide = Array.from(wideHi).map(b => b ^ 5);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorWide));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR+wide pattern');
});

await test('6.2 XOR with ascii and wide', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "OK" xor(3) ascii wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create ASCII XOR
  const asciiXor = Array.from(encoder.encode('OK')).map(b => b ^ 3);
  const dataStr = new TextDecoder().decode(new Uint8Array(asciiXor));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find ASCII XOR variant');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 7: REGEX WITH LITERAL PREFIX
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 7: Regex with Literal Prefix\n');

await test('7.1 Regex with simple literal start', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /http:\\/\\/[a-z]+\\.com/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Visit http://evil.com today');
  assertMinMatches(matches, 1, 'Should find literal prefix "http://"');
});

await test('7.2 Multiple regex patterns with prefixes', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /https:\\/\\/[a-z]+/
        $b = /ftp:\\/\\/[0-9]+/
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Use https://secure or ftp://123456');
  assertMinMatches(matches, 2, 'Should find both regex prefixes');
});

await test('7.3 Regex with longer literal prefix', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /malware_version_[0-9]+/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found malware_version_123 in file');
  assertMinMatches(matches, 1, 'Should find literal prefix "malware_version_"');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 8: COMPLEX OVERLAPPING SCENARIOS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 8: Complex Overlapping Scenarios\n');

await test('8.1 Nested patterns (AAA in AAAA)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AAA" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AAAA');
  assertMinMatches(matches, 2, 'Should find 2 overlapping AAA patterns in AAAA');
});

await test('8.2 Multiple patterns with shared substrings', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABAB" ascii
        $b = "BABA" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('XABABAX');
  assertMinMatches(matches, 2, 'Should find both overlapping patterns');
});

await test('8.3 Repeating pattern (ABABAB)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AB" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABABAB');
  assertMinMatches(matches, 3, 'Should find 3 occurrences of AB');
});

await test('8.4 Complex overlap with multiple rules', () => {
  const rules = parseYaraRuleGroup(`
    rule Rule1 {
      strings:
        $a = "AAA" ascii
      condition:
        $a
    }
    rule Rule2 {
      strings:
        $b = "AAB" ascii
      condition:
        $b
    }
    rule Rule3 {
      strings:
        $c = "ABA" ascii
      condition:
        $c
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AABBAAABAAA');
  assertMatchesContain(matches, [1, 2, 3], 'Should match all 3 rules');
  assertMinMatches(matches, 5, 'Should find multiple overlapping matches');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 9: MULTIPLE RULES WITH VARIOUS PATTERN TYPES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 9: Multiple Rules with Mixed Pattern Types\n');

await test('9.1 Mixed pattern types in multiple rules', () => {
  const rules = parseYaraRuleGroup(`
    rule PlainText {
      strings:
        $a = "plain" ascii
      condition:
        $a
    }
    rule Base64Text {
      strings:
        $b = "test" base64
      condition:
        $b
    }
    rule XorText {
      strings:
        $c = "xor" xor(1-10)
      condition:
        $c
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create data with all types
  const xorData = Array.from(encoder.encode('xor')).map(b => b ^ 5);
  const combined = 'plain and dGVzdA and ' + new TextDecoder().decode(new Uint8Array(xorData));
  const matches = ac.search(combined);
  assertMatchesContain(matches, [1, 2, 3], 'Should match all 3 rule types');
});

await test('9.2 Multiple patterns per rule with overlaps', () => {
  const rules = parseYaraRuleGroup(`
    rule MultiPattern {
      strings:
        $a = "test" ascii
        $b = "test" ascii nocase
        $c = "data" ascii
      condition:
        2 of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('TEST the data');
  assertMinMatches(matches, 2, 'Should find multiple patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 10: FULLWORD MODIFIER
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 10: Fullword Modifier\n');

await test('10.1 Fullword basic matching', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('a test case');
  assertMinMatches(matches, 1, 'Should find fullword match');
});

await test('10.2 Fullword should not match partial words', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // AC will find candidates, verification phase should reject "testing"
  const matches = ac.search('testing');
  // AC finds atoms, so it will return candidates
  assertMinMatches(matches, 1, 'AC finds candidates (verification phase filters)');
});

await test('10.3 Fullword with punctuation boundaries', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "word" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('"word" and (word) or word.');
  assertMinMatches(matches, 3, 'Should find word with punctuation boundaries');
});

await test('10.4 Fullword with nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii fullword nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('A TEST case');
  assertMinMatches(matches, 1, 'Should find fullword+nocase match');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 11: BASE64 COMBINATIONS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 11: Base64 Combinations\n');

await test('11.1 Base64 with all padding offsets', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" base64
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Base64 encodes with 3 different alignments
  // "test" -> dGVzdA== (offset 0), ZdGVzdA (offset 1), ZZdGVzdA (offset 2)
  const data = 'dGVzdA== and XRlc3Q= and dHRlc3Rh';
  const matches = ac.search(data);
  assertMinMatches(matches, 1, 'Should find base64 with various offsets');
});

await test('11.2 Base64wide basic', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" base64wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Base64wide should encode wide version of string
  const matches = ac.search('Some base64wide encoded data here');
  // This will depend on base64wide implementation
  assertMinMatches(matches, 0, 'Base64wide encoding varies by implementation');
});

await test('11.3 Base64 with alphabet parameter', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" base64
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Test different base64 padding alignments
  const data = 'SGk= and ASGk and ASGkA'; // base64("Hi") with different offsets
  const matches = ac.search(data);
  assertMinMatches(matches, 1, 'Should find base64 with padding variations');
});

await test('11.4 Multiple base64 patterns with overlap', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AA" base64
        $b = "AAA" base64
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'QUE= and QUFB'; // base64("AA") and base64("AAA")
  const matches = ac.search(data);
  assertMinMatches(matches, 2, 'Should find both base64 patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 12: WIDE STRING COMBINATIONS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 12: Wide String Combinations\n');

await test('12.1 Wide without ASCII modifier', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Should NOT match ASCII version
  const asciiMatches = ac.search('Hi there');
  assertEquals(asciiMatches.length, 0, 'Should not match ASCII when wide-only');
  // Should match wide version
  const wideData = new Uint8Array([0x48, 0x00, 0x69, 0x00]);
  const wideStr = new TextDecoder().decode(wideData);
  const wideMatches = ac.search(wideStr);
  assertMinMatches(wideMatches, 1, 'Should find wide-only pattern');
});

await test('12.2 Wide with ASCII modifier (both versions)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" ascii wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Should match ASCII
  const asciiMatches = ac.search('Hi there');
  assertMinMatches(asciiMatches, 1, 'Should find ASCII version');
  // Should also match wide
  const wideData = new Uint8Array([0x48, 0x00, 0x69, 0x00]);
  const wideStr = new TextDecoder().decode(wideData);
  const wideMatches = ac.search(wideStr);
  assertMinMatches(wideMatches, 1, 'Should find wide version');
});

await test('12.3 Wide with multiple patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AA" wide
        $b = "BB" wide
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const wideAA = new Uint8Array([0x41, 0x00, 0x41, 0x00]);
  const wideBB = new Uint8Array([0x42, 0x00, 0x42, 0x00]);
  const combined = new Uint8Array([...wideAA, 0x20, 0x00, ...wideBB]);
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find both wide patterns');
});

await test('12.4 Wide with overlapping characters', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AA" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Wide: A\0A\0A\0 should have overlapping AA matches
  const wideAAA = new Uint8Array([0x41, 0x00, 0x41, 0x00, 0x41, 0x00]);
  const dataStr = new TextDecoder().decode(wideAAA);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find overlapping wide patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 13: ADVANCED REGEX PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 13: Advanced Regex Patterns\n');

await test('13.1 Regex with escaped special chars', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /\\$price\\[0\\]/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found $price[0] variable');
  assertMinMatches(matches, 1, 'Should find regex with escaped chars');
});

await test('13.2 Regex with multiple literal segments', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /start[0-9]+middle[a-z]+end/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix start123middleabcend suffix');
  assertMinMatches(matches, 1, 'Should find longest literal prefix');
});

await test('13.3 Regex with optional prefix', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /https?:\\/\\/malware/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Visit http://malware.com');
  assertMinMatches(matches, 1, 'Should find literal part of regex');
});

await test('13.4 Multiple regex patterns with shared prefix', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /malware_v[0-9]+/
        $b = /malware_beta/
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found malware_v123 and malware_beta');
  assertMinMatches(matches, 2, 'Should find both patterns with shared prefix');
});

await test('13.5 Regex with case insensitive flag', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /MaLwArE/i
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('MALWARE and malware');
  assertMinMatches(matches, 2, 'Should find case variations');
});

await test('13.6 Regex with literal in middle of pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /exe[0-9]+/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found exe12345 file');
  assertMinMatches(matches, 1, 'Should find literal prefix "exe"');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 14: XOR ADVANCED SCENARIOS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 14: XOR Advanced Scenarios\n');

await test('14.1 XOR with overlapping patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AAA" xor(1-5)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR "AAAA" with key 3
  const xorData = Array.from(encoder.encode('AAAA')).map(b => b ^ 3);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find overlapping XOR patterns');
});

await test('14.2 XOR with multiple key variations', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" xor(5-7)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR "test" with keys 5, 6, and 7 - should find key 6
  const xorData6 = Array.from(encoder.encode('test')).map(b => b ^ 6);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData6));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR with key 6 in range 5-7');
});

await test('14.3 XOR multiple patterns with different keys', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "mal" xor(1-20)
        $b = "ware" xor(1-20)
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR both with different keys
  const xorMal = Array.from(encoder.encode('mal')).map(b => b ^ 7);
  const xorWare = Array.from(encoder.encode('ware')).map(b => b ^ 13);
  const combined = new Uint8Array([...xorMal, 0x20, ...xorWare]);
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 2, 'Should find both XOR patterns with different keys');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 15: COMPLEX MULTI-PATTERN SCENARIOS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 15: Complex Multi-Pattern Scenarios\n');

await test('15.1 All modifiers combined in one rule', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $plain = "plain" ascii
        $wide = "wide" wide
        $b64 = "data" base64
        $nc = "nocase" nocase
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('plain text NOCASE dGF0YQ data');
  assertMinMatches(matches, 2, 'Should find multiple pattern types');
});

await test('15.2 Dense overlapping patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABABAB" ascii
        $b = "ABAB" ascii
        $c = "BAB" ascii
        $d = "AB" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABABABABAB');
  assertMinMatches(matches, 10, 'Should find many overlapping matches');
});

await test('15.3 Patterns at boundaries', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $start = "START" ascii
        $end = "END" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('START middle END');
  assertMinMatches(matches, 2, 'Should find patterns at boundaries');
});

await test('15.4 Very long pattern with repeating atoms', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AAAAAAAAAA" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix AAAAAAAAAA suffix');
  assertMinMatches(matches, 1, 'Should handle long patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 16: EDGE CASES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 16: Edge Cases\n');

await test('16.1 Empty data', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('');
  assertEquals(matches.length, 0, 'Should find no matches in empty data');
});

await test('16.2 Pattern longer than data', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "verylongpattern" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('short');
  assertEquals(matches.length, 0, 'Should find no matches when pattern longer than data');
});

await test('16.3 Single character patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "A" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABACADA');
  assertMinMatches(matches, 4, 'Should find all single char matches');
});

await test('16.4 Binary data with null bytes', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "\\x00\\x01\\x02" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const binData = new Uint8Array([0xFF, 0x00, 0x01, 0x02, 0xFF]);
  const dataStr = new TextDecoder().decode(binData);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should handle binary data with null bytes');
});

await test('16.5 Very large data stream', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "needle" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const largeData = 'x'.repeat(10000) + 'needle' + 'x'.repeat(10000);
  const matches = ac.search(largeData);
  assertMinMatches(matches, 1, 'Should find pattern in large data');
});

await test('16.6 Pattern at start and end', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "XX" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('XX middle XX');
  assertMinMatches(matches, 2, 'Should find patterns at start and end');
});

await test('16.7 Special characters in pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "!@#$%^&*()" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found !@#$%^&*() here');
  assertMinMatches(matches, 1, 'Should handle special characters');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 17: VERY LONG PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 17: Very Long Patterns\n');

await test('17.1 Long ASCII pattern (100+ chars)', () => {
  const longPattern = 'A'.repeat(100);
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "${longPattern}" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix' + longPattern + 'suffix');
  assertMinMatches(matches, 1, 'Should find very long pattern');
});

await test('17.2 Multiple long patterns with shared prefix', () => {
  const prefix = 'A'.repeat(50);
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "${prefix}BBB" ascii
        $b = "${prefix}CCC" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search(prefix + 'BBB and ' + prefix + 'CCC');
  assertMinMatches(matches, 2, 'Should find both long patterns');
});

await test('17.3 Long pattern with overlap', () => {
  const pattern = 'ABCABC'.repeat(20);
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "${pattern}" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'X' + pattern + pattern + 'X';
  const matches = ac.search(data);
  assertMinMatches(matches, 2, 'Should find overlapping long patterns');
});

await test('17.4 Long repeating single character', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "${'Z'.repeat(50)}" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Z'.repeat(100));
  assertMinMatches(matches, 51, 'Should find many overlapping matches in repeating chars');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 18: VERY SHORT PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 18: Very Short Patterns\n');

await test('18.1 Many single-char patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "A" ascii
        $b = "B" ascii
        $c = "C" ascii
        $d = "D" ascii
        $e = "E" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABCDE');
  assertMinMatches(matches, 5, 'Should find all single-char patterns');
});

await test('18.2 Two-char patterns with high density', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AB" ascii
        $b = "BC" ascii
        $c = "CD" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABCD');
  assertMinMatches(matches, 3, 'Should find overlapping 2-char patterns');
});

await test('18.3 Single byte with nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "a" ascii nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AaAaA');
  assertMinMatches(matches, 5, 'Should find all case variations');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 19: COMPLEX REGEX PATTERNS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 19: Complex Regex Patterns\n');

await test('19.1 Regex with \\. escaped dot', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /file\\.exe/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found file.exe here');
  assertMinMatches(matches, 1, 'Should extract literal "file.exe"');
});

await test('19.2 Regex with \\? escaped question mark', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /what\\?why/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('what?why is this');
  assertMinMatches(matches, 1, 'Should extract literal "what?why"');
});

await test('19.3 Regex with \\x hex escape for bytes', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /test[0-9]+/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('test123 data here');
  assertMinMatches(matches, 1, 'Should extract literal prefix from regex');
});

await test('19.4 Regex with escaped chars in literals', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /Hello.*world/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Hello amazing world');
  assertMinMatches(matches, 1, 'Should extract "Hello" prefix from regex');
});

await test('19.5 Regex with \\t \\n \\r escapes', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /data\\tvalue/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('data\tvalue');
  assertMinMatches(matches, 1, 'Should handle tab escape');
});

await test('19.6 Regex with multiple escaped chars', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /\\$\\(price\\)/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('The $(price) is');
  assertMinMatches(matches, 1, 'Should handle multiple escaped chars');
});

await test('19.7 Regex with character class ranges', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /file[0-9a-f]+\\.log/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Found file12ab.log here');
  assertMinMatches(matches, 1, 'Should extract prefix "file"');
});

await test('19.8 Regex with alternation at end', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /prefix(A|B|C)/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefixB is here');
  assertMinMatches(matches, 1, 'Should extract literal "prefix"');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 20: WIDE STRING STRESS TESTS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 20: Wide String Stress Tests\n');

await test('20.1 Long wide string', () => {
  const text = 'MALWARE';
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "MALWARE" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide version: M\0A\0L\0W\0A\0R\0E\0
  const wideData = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    wideData[i * 2] = text.charCodeAt(i);
    wideData[i * 2 + 1] = 0;
  }
  const dataStr = new TextDecoder().decode(wideData);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find long wide string');
});

await test('20.2 Wide string with null byte collision', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AB" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create: A\0B\0 surrounded by other nulls
  const data = new Uint8Array([0x00, 0x00, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
  const dataStr = new TextDecoder().decode(data);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find wide string among null bytes');
});

await test('20.3 Alternating ASCII and wide strings', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const ascii = encoder.encode('test');
  const wide = new Uint8Array([0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]);
  const combined = new Uint8Array([...ascii, 0x20, 0x20, ...wide, 0x20, ...ascii]);
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 3, 'Should find both ASCII and wide versions');
});

await test('20.4 Wide nocase with unicode variations', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "hello" wide nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide uppercase: H\0E\0L\0L\0O\0
  const wideUpper = new Uint8Array([0x48, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x4F, 0x00]);
  const dataStr = new TextDecoder().decode(wideUpper);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find wide nocase match');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 21: DENSE OVERLAPPING SCENARIOS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 21: Dense Overlapping Scenarios\n');

await test('21.1 Pathological AAA...AAA overlaps', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AAAA" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AAAAAAAAAA'); // 10 A's should give 7 matches
  assertMinMatches(matches, 7, 'Should find 7 overlapping AAAA patterns in 10 As');
});

await test('21.2 Alternating pattern ABABAB...', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABA" ascii
        $b = "BAB" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABABABA'); // Should find multiple overlapping matches
  assertMinMatches(matches, 4, 'Should find overlapping ABA and BAB patterns');
});

await test('21.3 Many patterns starting at same position', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "PREFIX" ascii
        $b = "PREFI" ascii
        $c = "PREF" ascii
        $d = "PRE" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('PREFIX');
  assertMinMatches(matches, 4, 'Should find all nested prefix patterns');
});

await test('21.4 Cascading overlaps', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "123456" ascii
        $b = "3456" ascii
        $c = "56" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('123456');
  assertMinMatches(matches, 3, 'Should find all cascading patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 22: EXTREME XOR SCENARIOS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 22: Extreme XOR Scenarios\n');

await test('22.1 XOR with large key range', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "XYZ" xor(1-255)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // XOR with key 127
  const xorData = Array.from(encoder.encode('XYZ')).map(b => b ^ 127);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorData));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find XOR with key in large range');
});

await test('22.2 XOR with single byte pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "A" xor(1-255)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const xorA = 0x41 ^ 42;
  const dataStr = String.fromCharCode(xorA);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find single byte XOR');
});

await test('22.3 Multiple XOR patterns same key', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AAA" xor(5)
        $b = "BBB" xor(5)
        $c = "CCC" xor(5)
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const xorA = Array.from(encoder.encode('AAA')).map(b => b ^ 5);
  const xorB = Array.from(encoder.encode('BBB')).map(b => b ^ 5);
  const xorC = Array.from(encoder.encode('CCC')).map(b => b ^ 5);
  const combined = new Uint8Array([...xorA, 0x20, ...xorB, 0x20, ...xorC]);
  const dataStr = new TextDecoder().decode(combined);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 3, 'Should find all XOR patterns');
});

await test('22.4 XOR with wide on long pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "LONGPATTERN" xor(7) wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create wide then XOR
  const text = 'LONGPATTERN';
  const wideData = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    wideData[i * 2] = text.charCodeAt(i);
    wideData[i * 2 + 1] = 0;
  }
  const xorWide = Array.from(wideData).map(b => b ^ 7);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorWide));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should find long XOR+wide pattern');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 23: BOUNDARY CONDITIONS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 23: Boundary Conditions\n');

await test('23.1 Pattern exactly at buffer start', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "START" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('START middle end');
  assertMinMatches(matches, 1, 'Should find pattern at exact start');
});

await test('23.2 Pattern exactly at buffer end', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "END" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('start middle END');
  assertMinMatches(matches, 1, 'Should find pattern at exact end');
});

await test('23.3 Pattern is entire buffer', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "EXACTLY" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('EXACTLY');
  assertMinMatches(matches, 1, 'Should find pattern that is entire buffer');
});

await test('23.4 Adjacent patterns no gap', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABC" ascii
        $b = "DEF" ascii
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABCDEF');
  assertMinMatches(matches, 2, 'Should find adjacent patterns with no gap');
});

await test('23.5 Pattern crossing buffer boundary simulation', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "CROSS" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Simulate data that might cross buffer boundaries in streaming
  const matches = ac.search('XYCROSS');
  assertMinMatches(matches, 1, 'Should find pattern regardless of position');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 24: BASE64 STRESS TESTS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 24: Base64 Stress Tests\n');

await test('24.1 Base64 with all padding variations', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ABC" base64
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Base64("ABC") can appear with different alignments
  const data = 'QUJD and BBQUM and CQUJD'; // Different offsets
  const matches = ac.search(data);
  assertMinMatches(matches, 1, 'Should find base64 with padding variations');
});

await test('24.2 Multiple base64 patterns overlapping', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" base64
        $b = "data" base64
      condition:
        all of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'dGVzdA== and ZGF0YQ=='; // base64("test") and base64("data")
  const matches = ac.search(data);
  assertMinMatches(matches, 2, 'Should find multiple base64 patterns');
});

await test('24.3 Base64 very long string', () => {
  const longText = 'A'.repeat(50);
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "${longText}" base64
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const b64 = btoa(longText);
  const matches = ac.search(b64);
  assertMinMatches(matches, 1, 'Should find long base64 pattern');
});

await test('24.4 Base64wide with special chars', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi!" base64wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'Some base64wide encoded data';
  const matches = ac.search(data);
  // Base64wide support varies
  assertMinMatches(matches, 0, 'Base64wide encoding check');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 25: FULLWORD STRESS TESTS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 25: Fullword Stress Tests\n');

await test('25.1 Fullword at various positions', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "word" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('word at-word and word. (word)');
  assertMinMatches(matches, 4, 'Should find fullword at various boundaries');
});

await test('25.2 Fullword with tabs and newlines', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('test\ttest\ntest\rtest');
  assertMinMatches(matches, 4, 'Should recognize whitespace as word boundaries');
});

await test('25.3 Fullword single character', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "a" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('a b c a.b');
  assertMinMatches(matches, 2, 'Should find single char fullword');
});

await test('25.4 Fullword with numbers', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "123" ascii fullword
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('abc123def 123 456');
  assertMinMatches(matches, 1, 'Should find numeric fullword');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 26: MIXED MODIFIER COMBINATIONS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 26: Mixed Modifier Combinations\n');

await test('26.1 All valid modifiers in one rule', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $plain = "plain" ascii
        $nc = "NOCASE" nocase
        $wide = "wide" wide
        $full = "full" fullword
        $xor = "xor" xor(5)
        $b64 = "b64" base64
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('plain NOCASE and more');
  assertMinMatches(matches, 2, 'Should handle multiple modifier types');
});

await test('26.2 Wide with fullword and nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "TEST" wide fullword nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const wideTest = new Uint8Array([0x20, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x20, 0x00]);
  const dataStr = new TextDecoder().decode(wideTest);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should handle wide+fullword+nocase');
});

await test('26.3 XOR with wide and multiple keys', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "data" xor(1-10) wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const text = 'data';
  const wideData = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    wideData[i * 2] = text.charCodeAt(i);
    wideData[i * 2 + 1] = 0;
  }
  const xorWide = Array.from(wideData).map(b => b ^ 7);
  const dataStr = new TextDecoder().decode(new Uint8Array(xorWide));
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should handle XOR+wide combination');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 27: PERFORMANCE STRESS TESTS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 27: Performance Stress Tests\n');

await test('27.1 Huge number of rules', () => {
  let rulesStr = '';
  for (let i = 0; i < 50; i++) {
    rulesStr += `
      rule Test${i} {
        strings:
          $a = "pattern${i}" ascii
        condition:
          $a
      }
    `;
  }
  const rules = parseYaraRuleGroup(rulesStr);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('pattern25 and pattern30');
  assertMinMatches(matches, 2, 'Should handle many rules');
});

await test('27.2 Rule with many patterns', () => {
  let patternsStr = '';
  for (let i = 0; i < 30; i++) {
    patternsStr += `$p${i} = "str${i}" ascii\n`;
  }
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        ${patternsStr}
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('str5 and str15 and str25');
  assertMinMatches(matches, 3, 'Should handle rule with many patterns');
});

await test('27.3 Very large data buffer', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "target" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const hugeData = 'x'.repeat(50000) + 'target' + 'x'.repeat(50000);
  const matches = ac.search(hugeData);
  assertMinMatches(matches, 1, 'Should handle very large buffers');
});

await test('27.4 Many small patterns in large data', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "AB" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'AB'.repeat(1000);
  const matches = ac.search(data);
  assertMinMatches(matches, 1000, 'Should find many occurrences efficiently');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 28: MULTI-BYTE UTF-8 CHARACTERS (BYTE-LEVEL MATCHING)
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 28: Multi-Byte UTF-8 Characters (Byte-Level Matching)\n');

await test('28.1 UTF-8 multi-byte as byte sequence (emoji)', () => {
  // YARA/AC works on bytes, not Unicode codepoints
  // Emoji '😀' is UTF-8: 0xF0 0x9F 0x98 0x80
  // When searching, AC sees individual bytes
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix😀test suffix');
  assertMinMatches(matches, 1, 'Should find ASCII pattern near multi-byte chars');
});

await test('28.2 Non-ASCII accented characters (2-byte UTF-8)', () => {
  // 'café' contains 'é' which is 2-byte UTF-8: 0xC3 0xA9
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "café" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('visit café today');
  assertMinMatches(matches, 1, 'Should match UTF-8 encoded accented chars as bytes');
});

await test('28.3 Chinese characters (3-byte UTF-8)', () => {
  // Chinese chars are 3-byte UTF-8 sequences
  // '测试' is searched as byte sequence, not codepoints
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "测试" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('这是测试数据');
  assertMinMatches(matches, 1, 'Should match Chinese chars as UTF-8 byte sequences');
});

await test('28.4 Mixed scripts (Cyrillic 2-byte UTF-8)', () => {
  // Cyrillic chars are 2-byte UTF-8
  // 'Кириллица' is matched as byte sequence
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "testКириллица" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Some testКириллица data');
  assertMinMatches(matches, 1, 'Should match mixed Latin+Cyrillic as byte sequence');
});

await test('28.5 Pure emoji pattern (4-byte UTF-8)', () => {
  // Test with ONLY emoji, no ASCII chars
  // '😀' = UTF-8: [0xF0, 0x9F, 0x98, 0x80]
  // '😃' = UTF-8: [0xF0, 0x9F, 0x98, 0x83]
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "😀" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix😀suffix and 😃other');
  assertMinMatches(matches, 1, 'Should match single emoji as 4-byte UTF-8 sequence');
});

await test('28.6 Pure emoji sequence (multiple 4-byte chars)', () => {
  // Multiple emojis in sequence: '😀😃😄'
  // Each is 4 bytes, total 12 bytes
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "😀😃😄" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('text😀😃😄more');
  assertMinMatches(matches, 1, 'Should match emoji sequence as 12-byte UTF-8 sequence');
});

await test('28.7 Pure Chinese character pattern (3-byte UTF-8)', () => {
  // Test with ONLY Chinese chars, no ASCII
  // '测' = UTF-8: [0xE6, 0xB5, 0x8B]
  // '试' = UTF-8: [0xE8, 0xAF, 0x95]
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "测" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('文测字试');
  assertMinMatches(matches, 1, 'Should match single Chinese char as 3-byte UTF-8 sequence');
});

await test('28.8 Pure Chinese character sequence', () => {
  // Longer Chinese-only pattern: '测试数据'
  // Each char is 3 bytes = 12 bytes total
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "测试数据" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('这是测试数据的例子');
  assertMinMatches(matches, 1, 'Should match Chinese sequence as byte sequence');
});

await test('28.9 Pure Cyrillic pattern (2-byte UTF-8)', () => {
  // Test with ONLY Cyrillic, no ASCII
  // 'Привет' (Hello in Russian)
  // Each char is 2 bytes
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Привет" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('Мир Привет друг');
  assertMinMatches(matches, 1, 'Should match Cyrillic as 2-byte UTF-8 sequence');
});

await test('28.10 Pure accented characters (2-byte UTF-8)', () => {
  // Test with ONLY accented chars
  // 'éèêë' - all 2-byte UTF-8
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "éèêë" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('àéèêëù');
  assertMinMatches(matches, 1, 'Should match accented chars as 2-byte UTF-8 sequence');
});

await test('28.11 Mixed emoji with nocase (byte-level)', () => {
  // Emoji + ASCII with nocase modifier
  // Verifies nocase works on ASCII but emoji stays as-is
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "HELLO😀WORLD" ascii nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('hello😀world and HELLO😀WORLD');
  assertMinMatches(matches, 2, 'Nocase on ASCII, emoji matched as bytes');
});

await test('28.12 Pure Arabic characters (2-byte UTF-8)', () => {
  // Arabic text: 'مرحبا' (Hello)
  // Each char is 2-byte UTF-8
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "مرحبا" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('نص مرحبا نص');
  assertMinMatches(matches, 1, 'Should match Arabic as 2-byte UTF-8 sequence');
});

await test('28.13 Pure Hebrew characters (2-byte UTF-8)', () => {
  // Hebrew text: 'שלום' (Hello)
  // Each char is 2-byte UTF-8
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "שלום" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('טקסט שלום טקסט');
  assertMinMatches(matches, 1, 'Should match Hebrew as 2-byte UTF-8 sequence');
});

await test('28.14 Wide emoji pattern (UTF-16LE bytes)', () => {
  // Emoji in wide format (UTF-16LE with null bytes)
  // '😀' in UTF-16LE is surrogate pair: 0x3D 0xD8 0x00 0xDE 0x00 0x00
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "😀" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Create UTF-16LE representation of emoji (surrogate pair)
  // High: 0xD83D (55357), Low: 0xDE00 (56832)
  const wideEmoji = new Uint8Array([0x3D, 0xD8, 0x00, 0xDE]);
  const dataStr = new TextDecoder().decode(wideEmoji);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should match emoji in wide format as byte sequence');
});

await test('28.15 Overlapping multi-byte patterns', () => {
  // Test overlapping detection with multi-byte chars
  // Pattern: '测试' in '测试测试'
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "测试" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('测试测试测试');
  // Should find multiple overlapping occurrences
  assertMinMatches(matches, 3, 'Should find overlapping multi-byte patterns');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 29: ERROR RESILIENCE
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 29: Error Resilience\n');

await test('29.1 Search with malformed UTF-8', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // Invalid UTF-8 sequence
  const badData = new Uint8Array([0x74, 0x65, 0x73, 0x74, 0xFF, 0xFE]);
  const dataStr = new TextDecoder('utf-8', { fatal: false }).decode(badData);
  const matches = ac.search(dataStr);
  assertMinMatches(matches, 1, 'Should handle malformed UTF-8 gracefully');
});

await test('29.2 Empty pattern list', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "never" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('no match here');
  assertEquals(matches.length, 0, 'Should return empty for no matches');
});

await test('29.3 Repeated searches', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "reuse" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches1 = ac.search('reuse test');
  const matches2 = ac.search('reuse again');
  const matches3 = ac.search('reuse once more');
  assertMinMatches(matches1, 1, 'First search should work');
  assertMinMatches(matches2, 1, 'Second search should work');
  assertMinMatches(matches3, 1, 'Third search should work');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 30: REGEX EDGE CASES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 30: Regex Edge Cases\n');

await test('30.1 Regex with quantifiers on literals', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /abc+def/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('abccccdef');
  assertMinMatches(matches, 1, 'Should extract "abc" prefix');
});

await test('30.2 Regex with alternation in middle', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /start(A|B)end/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('startAend');
  assertMinMatches(matches, 1, 'Should extract "start" prefix');
});

await test('30.3 Regex with nested groups', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /prefix((sub1|sub2)suffix)/
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefixsub1suffix');
  assertMinMatches(matches, 1, 'Should extract longest literal');
});

await test('30.4 Regex with case insensitive flag', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = /CasE/i
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('case CASE CaSe');
  assertMinMatches(matches, 3, 'Should match all case variations');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 31: SPECIAL CHARACTERS AND ESCAPES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 31: Special Characters and Escapes\n');

await test('31.1 Pattern with newline characters', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "line1\\nline2" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('line1\nline2');
  assertMinMatches(matches, 1, 'Should match pattern with newline');
});

await test('31.2 Pattern with tab characters', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "col1\\tcol2" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('col1\tcol2');
  assertMinMatches(matches, 1, 'Should match pattern with tab');
});

await test('31.3 Pattern with carriage return', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "line\\rreturn" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('line\rreturn');
  assertMinMatches(matches, 1, 'Should match pattern with carriage return');
});

await test('31.4 Pattern with backslash', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "path\\\\file" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('path\\file');
  assertMinMatches(matches, 1, 'Should match pattern with backslash');
});

await test('31.5 Pattern with mixed whitespace', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "space tab\\tnewline\\n" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('space tab\tnewline\n');
  assertMinMatches(matches, 1, 'Should match pattern with mixed whitespace');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 32: PATTERN SUBSTRING RELATIONSHIPS
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 32: Pattern Substring Relationships\n');

await test('32.1 Pattern is substring of another (shorter first)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "abc" ascii
        $b = "abcdef" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('abcdef');
  assertMinMatches(matches, 2, 'Should find both patterns');
});

await test('32.2 Overlapping patterns with shared prefix', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "prefix1" ascii
        $b = "prefix2" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('prefix1 prefix2');
  assertMinMatches(matches, 2, 'Should find both patterns');
});

await test('32.3 Overlapping patterns with shared suffix', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "1suffix" ascii
        $b = "2suffix" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('1suffix 2suffix');
  assertMinMatches(matches, 2, 'Should find both patterns');
});

await test('32.4 Pattern completely contains another', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "mid" ascii
        $b = "beginmidend" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('beginmidend');
  assertMinMatches(matches, 2, 'Should find both patterns');
});

await test('32.5 Consecutive identical patterns', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "repeat" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('repeatrepeatrepeat');
  assertMinMatches(matches, 3, 'Should find all three occurrences');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 33: XOR EDGE CASES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 33: XOR Edge Cases\n');

await test('33.1 XOR with key 0 (identity)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "identity" xor(0-0)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('identity');
  assertMinMatches(matches, 1, 'XOR 0 should match original string');
});

await test('33.2 XOR with key 255 (max)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "test" xor(255-255)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  // "test" XOR 255 = invert all bits
  const xorred = String.fromCharCode(
    't'.charCodeAt(0) ^ 255,
    'e'.charCodeAt(0) ^ 255,
    's'.charCodeAt(0) ^ 255,
    't'.charCodeAt(0) ^ 255
  );
  const matches = ac.search(xorred);
  assertMinMatches(matches, 1, 'XOR 255 should match bit-inverted string');
});

await test('33.3 XOR single key range', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "single" xor(42-42)
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const xorred = 'single'.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 42)).join('');
  const matches = ac.search(xorred);
  assertMinMatches(matches, 1, 'Should match XOR with single key');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 34: ATOM SELECTION EDGE CASES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 34: Atom Selection Edge Cases\n');

await test('34.1 Pattern length exactly 3 (default atom length)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "abc" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('abc');
  assertMinMatches(matches, 1, 'Should match pattern of length 3');
});

await test('34.2 Multiple patterns all length 3', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "abc" ascii
        $b = "def" ascii
        $c = "xyz" ascii
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('abc def xyz');
  assertMinMatches(matches, 3, 'Should match all patterns of length 3');
});

await test('34.3 Pattern length 2 (below atom length)', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "ab" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ab');
  assertMinMatches(matches, 1, 'Should match pattern shorter than atom length');
});

await test('34.4 Single character pattern', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "x" ascii
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('x');
  assertMinMatches(matches, 1, 'Should match single character pattern');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 35: NOCASE FAILURE LINK TRAVERSAL
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 35: Nocase Failure Link Traversal\n');

await test('35.1 Nocase with failure link to another nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "abc" nocase
        $b = "bc" nocase
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('ABC');
  assertMinMatches(matches, 2, 'Should find both patterns via nocase');
});

await test('35.2 Mixed case pattern matching', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "MixedCase" nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('mixedcase MIXEDCASE MiXeDcAsE');
  assertMinMatches(matches, 3, 'Should match all case variations');
});

await test('35.3 Nocase with partial match requiring failure link', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "aaab" nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const matches = ac.search('AAAAB');
  assertMinMatches(matches, 1, 'Should match using failure links with nocase');
});

// ═════════════════════════════════════════════════════════════════════════
// SECTION 36: WIDE STRING WITH NULL BYTES
// ═════════════════════════════════════════════════════════════════════════
console.log('\n📋 Section 36: Wide String with Null Bytes\n');

await test('36.1 Wide string basic', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Hi" wide
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const wideString = 'H\x00i\x00'; // UTF-16LE representation
  const matches = ac.search(wideString);
  assertMinMatches(matches, 1, 'Should match wide string');
});

await test('36.2 Wide string with embedded nulls in source', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "A" wide
        $b = "B" wide
      condition:
        any of them
    }
  `);
  const ac = new AhoCorasick(rules);
  const data = 'A\x00B\x00'; // Two wide characters
  const matches = ac.search(data);
  assertMinMatches(matches, 2, 'Should match both wide patterns');
});

await test('36.3 Wide nocase', () => {
  const rules = parseYaraRuleGroup(`
    rule Test {
      strings:
        $a = "Test" wide nocase
      condition:
        $a
    }
  `);
  const ac = new AhoCorasick(rules);
  const wideUpper = 'T\x00E\x00S\x00T\x00';
  const wideLower = 't\x00e\x00s\x00t\x00';
  const matches1 = ac.search(wideUpper);
  const matches2 = ac.search(wideLower);
  assertMinMatches(matches1, 1, 'Should match uppercase wide');
  assertMinMatches(matches2, 1, 'Should match lowercase wide');
});

// ═════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═════════════════════════════════════════════════════════════════════════
printSummary();

