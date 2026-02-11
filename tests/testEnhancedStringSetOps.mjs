#!/usr/bin/env node

/**
 * Comprehensive tests for Enhanced String Set Operations
 * Tests: none of them, none of ($a*), range quantifiers, wildcard patterns
 */

import { test, assertEquals, assertTrue, assertFalse, printSummary, printSection } from './testingFramework.mjs';
import { InterceptScanner } from '../src/interceptScanner.mjs';

printSection('Enhanced String Set Operations Tests');

// ============================================================================
// None of them Tests
// ============================================================================

console.log('\n🚫 None of them');
console.log('-'.repeat(70));

await test('none of them - no strings match', async () => {
  const rule = `
    rule TestNoneOfThem {
      strings:
        $a = "malware"
        $b = "virus"
        $c = "trojan"
      condition:
        none of them
    }
  `;
  
  const data = Buffer.from('clean file with no bad strings');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match when no strings are found');
  assertEquals(results[0].rule, 'TestNoneOfThem');
});

await test('none of them - some strings match (should not match rule)', async () => {
  const rule = `
    rule TestNoneOfThemNoMatch {
      strings:
        $a = "malware"
        $b = "virus"
        $c = "clean"
      condition:
        none of them
    }
  `;
  
  const data = Buffer.from('clean file');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match when any string is found');
});

await test('none of them - all strings match (should not match rule)', async () => {
  const rule = `
    rule TestNoneAllMatch {
      strings:
        $a = "bad"
        $b = "file"
      condition:
        none of them
    }
  `;
  
  const data = Buffer.from('bad file');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match when all strings are found');
});

// ============================================================================
// None of ($pattern*) - Wildcard with None
// ============================================================================

console.log('\n🔍 None of ($pattern*) - Wildcard Patterns');
console.log('-'.repeat(70));

await test('none of ($api*) - no API strings match', async () => {
  const rule = `
    rule TestNoneOfWildcard {
      strings:
        $api_create = "CreateProcess"
        $api_open = "OpenFile"
        $api_write = "WriteFile"
        $benign = "Hello"
      condition:
        none of ($api*)
    }
  `;
  
  const data = Buffer.from('Hello World');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match when no API strings are found');
});

await test('none of ($api*) - some API strings match', async () => {
  const rule = `
    rule TestNoneOfWildcardFail {
      strings:
        $api_create = "CreateProcess"
        $api_open = "OpenFile"
        $other = "test"
      condition:
        none of ($api*)
    }
  `;
  
  const data = Buffer.from('Call CreateProcess now');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match when API strings are found');
});

await test('none of ($bad*, $virus*) - multiple wildcard patterns', async () => {
  const rule = `
    rule TestNoneMultipleWildcards {
      strings:
        $bad_api1 = "BadAPI1"
        $bad_api2 = "BadAPI2"
        $virus_sig1 = "VIRUS1"
        $virus_sig2 = "VIRUS2"
        $clean = "clean"
      condition:
        none of ($bad*, $virus*)
    }
  `;
  
  const data = Buffer.from('clean data only');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match when neither bad nor virus strings found');
});

// ============================================================================
// Range Quantifiers - N..M of them
// ============================================================================

console.log('\n📊 Range Quantifiers - N..M of them');
console.log('-'.repeat(70));

await test('2..3 of them - exactly 2 strings match', async () => {
  const rule = `
    rule TestRangeQuantifier2 {
      strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
        $d = "delta"
      condition:
        2..3 of them
    }
  `;
  
  const data = Buffer.from('alpha beta');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 2 strings (within range)');
});

await test('2..3 of them - exactly 3 strings match', async () => {
  const rule = `
    rule TestRangeQuantifier3 {
      strings:
        $a = "one"
        $b = "two"
        $c = "three"
        $d = "four"
      condition:
        2..3 of them
    }
  `;
  
  const data = Buffer.from('one two three');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 3 strings (within range)');
});

await test('2..3 of them - only 1 string matches (below range)', async () => {
  const rule = `
    rule TestRangeBelowMin {
      strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
      condition:
        2..3 of them
    }
  `;
  
  const data = Buffer.from('alpha only');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match with only 1 string (below range)');
});

await test('2..3 of them - 4 strings match (above range)', async () => {
  const rule = `
    rule TestRangeAboveMax {
      strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
      condition:
        2..3 of them
    }
  `;
  
  const data = Buffer.from('a b c d');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match with 4 strings (above range)');
});

await test('1..1 of them - exactly one match required', async () => {
  const rule = `
    rule TestRangeSingle {
      strings:
        $a = "target"
        $b = "other"
      condition:
        1..1 of them
    }
  `;
  
  const data = Buffer.from('target');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with exactly 1 string');
});

await test('0..2 of them - zero to two matches', async () => {
  const rule = `
    rule TestRangeWithZero {
      strings:
        $a = "foo"
        $b = "bar"
      condition:
        0..2 of them
    }
  `;
  
  const data = Buffer.from('unrelated content');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 0 strings (within range 0..2)');
});

// ============================================================================
// Range Quantifiers with Wildcards - N..M of ($pattern*)
// ============================================================================

console.log('\n🎯 Range Quantifiers with Wildcards');
console.log('-'.repeat(70));

await test('2..3 of ($api*) - wildcard with range', async () => {
  const rule = `
    rule TestRangeWildcard {
      strings:
        $api_create = "CreateProcess"
        $api_open = "OpenFile"
        $api_write = "WriteFile"
        $api_read = "ReadFile"
        $other = "benign"
      condition:
        2..3 of ($api*)
    }
  `;
  
  const data = Buffer.from('CreateProcess and OpenFile calls');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 2 API strings (within range)');
});

await test('2..4 of ($enc*, $crypto*) - multiple wildcards with range', async () => {
  const rule = `
    rule TestRangeMultiWildcard {
      strings:
        $enc_aes = "AES"
        $enc_des = "DES"
        $crypto_key = "CryptoKey"
        $crypto_hash = "CryptoHash"
        $benign = "normal"
      condition:
        2..4 of ($enc*, $crypto*)
    }
  `;
  
  const data = Buffer.from('AES DES CryptoKey found');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 3 crypto strings (within range)');
});

await test('1..2 of ($mal*) - below minimum for range', async () => {
  const rule = `
    rule TestRangeWildcardBelowMin {
      strings:
        $mal_api1 = "MalAPI1"
        $mal_api2 = "MalAPI2"
        $mal_api3 = "MalAPI3"
      condition:
        2..3 of ($mal*)
    }
  `;
  
  const data = Buffer.from('MalAPI1 only');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match with only 1 string (below min)');
});

// ============================================================================
// Percentage with Wildcards - X% of ($pattern*)
// ============================================================================

console.log('\n📈 Percentage Quantifiers with Wildcards');
console.log('-'.repeat(70));

await test('50% of ($api*) - percentage with wildcard', async () => {
  const rule = `
    rule TestPercentWildcard {
      strings:
        $api_1 = "API1"
        $api_2 = "API2"
        $api_3 = "API3"
        $api_4 = "API4"
        $other = "benign"
      condition:
        50% of ($api*)
    }
  `;
  
  // 2 out of 4 API strings = 50%
  const data = Buffer.from('API1 and API2');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 50% of API strings');
});

await test('75% of ($sig*) - high percentage threshold', async () => {
  const rule = `
    rule TestPercentHighThreshold {
      strings:
        $sig_1 = "SIG1"
        $sig_2 = "SIG2"
        $sig_3 = "SIG3"
        $sig_4 = "SIG4"
      condition:
        75% of ($sig*)
    }
  `;
  
  // Need 3 out of 4 (75%)
  const data = Buffer.from('SIG1 SIG2 SIG3');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 75% of signatures');
});

await test('80% of ($enc*) - not enough matches', async () => {
  const rule = `
    rule TestPercentNotEnough {
      strings:
        $enc_1 = "ENC1"
        $enc_2 = "ENC2"
        $enc_3 = "ENC3"
        $enc_4 = "ENC4"
        $enc_5 = "ENC5"
      condition:
        80% of ($enc*)
    }
  `;
  
  // Only 2 out of 5 = 40%, need 80%
  const data = Buffer.from('ENC1 ENC2');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match with only 40% (need 80%)');
});

// ============================================================================
// Complex Combined Tests
// ============================================================================

console.log('\n🔗 Complex Combined Operations');
console.log('-'.repeat(70));

await test('Complex: range + wildcard + logical operators', async () => {
  const rule = `
    rule TestComplexCombined {
      strings:
        $api_1 = "CreateFile"
        $api_2 = "WriteFile"
        $api_3 = "ReadFile"
        $enc_1 = "AES"
        $enc_2 = "RSA"
        $safe = "safe"
      condition:
        2..3 of ($api*) and none of ($enc*)
    }
  `;
  
  const data = Buffer.from('CreateFile WriteFile safe');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 2 APIs and no encryption');
});

await test('Complex: multiple range conditions', async () => {
  const rule = `
    rule TestMultipleRanges {
      strings:
        $net_1 = "socket"
        $net_2 = "connect"
        $net_3 = "send"
        $file_1 = "open"
        $file_2 = "read"
        $file_3 = "write"
      condition:
        1..2 of ($net*) and 2..3 of ($file*)
    }
  `;
  
  const data = Buffer.from('socket open read write');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with ranges satisfied for both patterns');
});

await test('Complex: none + percentage + range', async () => {
  const rule = `
    rule TestComplexMix {
      strings:
        $good_1 = "valid"
        $good_2 = "safe"
        $good_3 = "clean"
        $bad_1 = "malware"
        $bad_2 = "virus"
        $warn_1 = "suspicious"
      condition:
        none of ($bad*) and 50% of ($good*)
    }
  `;
  
  const data = Buffer.from('valid safe content');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with no bad strings and 66% good strings');
});

await test('Edge case: empty wildcard match', async () => {
  const rule = `
    rule TestEmptyWildcard {
      strings:
        $a = "test"
        $b = "data"
      condition:
        none of ($nonexistent*)
    }
  `;
  
  const data = Buffer.from('test data');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match when wildcard matches no string identifiers');
});

await test('Edge case: range 0..0 (must match exactly zero)', async () => {
  const rule = `
    rule TestRangeZeroZero {
      strings:
        $a = "bad"
        $b = "malware"
      condition:
        0..0 of them
    }
  `;
  
  const data = Buffer.from('clean file');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match when exactly 0 strings found');
});

await test('Edge case: large range 1..100', async () => {
  const rule = `
    rule TestLargeRange {
      strings:
        $a = "one"
        $b = "two"
        $c = "three"
      condition:
        1..100 of them
    }
  `;
  
  const data = Buffer.from('one two');
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 2 strings in range 1..100');
});

// ============================================================================
// Print Summary
// ============================================================================

printSummary();
