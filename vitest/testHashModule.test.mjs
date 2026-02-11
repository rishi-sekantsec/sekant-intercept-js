/**
 * Comprehensive test suite for YARA Hash Module
 * 
 * Tests all hash functions with various inputs:
 * - MD5, SHA1, SHA256, checksum32, CRC32
 * - String input vs data region (offset, size)
 * - Edge cases: empty strings, large data, Unicode
 * - Comparison with known hash values
 */

import { createHashModule, hash } from '../src/hashModule.mjs';
import {
  numberedTest as test,
  assertEquals,
  assertThrows,
  printSummary
} from './testingFramework.mjs';

// Alias for async tests (same as regular test in framework)
const asyncTest = test;

console.log('='.repeat(70));
console.log('YARA Hash Module - Comprehensive Test Suite');
console.log('='.repeat(70));

// =============================================================================
// Section 1: Standalone hash functions (string input only)
// =============================================================================
console.log('\n📦 Section 1: Standalone Hash Functions (String Input)');

await asyncTest('1.1: MD5 of simple string "hello"', async () => {
  const result = await hash.md5('hello');
  // Known MD5 of "hello" is 5d41402abc4b2a76b9719d911017c592
  assertEquals(result, '5d41402abc4b2a76b9719d911017c592');
});

await asyncTest('1.2: MD5 of empty string', async () => {
  const result = await hash.md5('');
  // Known MD5 of "" is d41d8cd98f00b204e9800998ecf8427e
  assertEquals(result, 'd41d8cd98f00b204e9800998ecf8427e');
});

await asyncTest('1.3: MD5 of "The quick brown fox jumps over the lazy dog"', async () => {
  const result = await hash.md5('The quick brown fox jumps over the lazy dog');
  // Known MD5
  assertEquals(result, '9e107d9d372bb6826bd81d3542a419d6');
});

await asyncTest('1.4: SHA1 of simple string "hello"', async () => {
  const result = await hash.sha1('hello');
  // Known SHA1 of "hello" is aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
  assertEquals(result, 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
});

await asyncTest('1.5: SHA1 of empty string', async () => {
  const result = await hash.sha1('');
  // Known SHA1 of "" is da39a3ee5e6b4b0d3255bfef95601890afd80709
  assertEquals(result, 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
});

await asyncTest('1.6: SHA1 of "The quick brown fox jumps over the lazy dog"', async () => {
  const result = await hash.sha1('The quick brown fox jumps over the lazy dog');
  // Known SHA1
  assertEquals(result, '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12');
});

await asyncTest('1.7: SHA256 of simple string "hello"', async () => {
  const result = await hash.sha256('hello');
  // Known SHA256 of "hello"
  assertEquals(result, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
});

await asyncTest('1.8: SHA256 of empty string', async () => {
  const result = await hash.sha256('');
  // Known SHA256 of ""
  assertEquals(result, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

await asyncTest('1.9: SHA256 of "The quick brown fox jumps over the lazy dog"', async () => {
  const result = await hash.sha256('The quick brown fox jumps over the lazy dog');
  // Known SHA256
  assertEquals(result, 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
});

await test('1.10: checksum32 of "hello"', () => {
  const result = hash.checksum32('hello');
  // Sum: h(104) + e(101) + l(108) + l(108) + o(111) = 532 = 0x214
  assertEquals(result, 532);
});

await test('1.11: checksum32 of empty string', () => {
  const result = hash.checksum32('');
  assertEquals(result, 0);
});

await test('1.12: checksum32 of "ABC"', () => {
  const result = hash.checksum32('ABC');
  // Sum: A(65) + B(66) + C(67) = 198 = 0xC6
  assertEquals(result, 198);
});

await test('1.13: CRC32 of "hello"', () => {
  const result = hash.crc32('hello');
  // Known CRC32 of "hello" is 0x3610A686
  assertEquals(result, 0x3610A686);
});

await test('1.14: CRC32 of empty string', () => {
  const result = hash.crc32('');
  assertEquals(result, 0);
});

await test('1.15: CRC32 of "123456789"', () => {
  const result = hash.crc32('123456789');
  // Known CRC32 of "123456789" is 0xCBF43926
  assertEquals(result, 0xCBF43926);
});

// =============================================================================
// Section 2: Hash module with data buffer (offset, size)
// =============================================================================
console.log('\n📦 Section 2: Hash Module with Data Buffer (offset, size)');

const testData = new Uint8Array([
  0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, // "Hello "
  0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21  // "World!"
]);
const hashModule = createHashModule(testData);

await asyncTest('2.1: MD5 of full data buffer', async () => {
  const result = await hashModule.md5(0, testData.length);
  // MD5 of "Hello World!" is ed076287532e86365e841e92bfc50d8c
  assertEquals(result, 'ed076287532e86365e841e92bfc50d8c');
});

await asyncTest('2.2: MD5 of partial data (first 5 bytes "Hello")', async () => {
  const result = await hashModule.md5(0, 5);
  // MD5 of "Hello" is 8b1a9953c4611296a827abf8c47804d7
  assertEquals(result, '8b1a9953c4611296a827abf8c47804d7');
});

await asyncTest('2.3: MD5 of partial data (last 6 bytes "World!")', async () => {
  const result = await hashModule.md5(6, 6);
  // MD5 of "World!" is e509465ef513154988e088d6ad3c21bf
  assertEquals(result, 'e509465ef513154988e088d6ad3c21bf');
});

await asyncTest('2.4: MD5 using string input on hash module', async () => {
  const result = await hashModule.md5('Test');
  // MD5 of "Test" is 0cbc6611f5540bd0809a388dc95a615b
  assertEquals(result, '0cbc6611f5540bd0809a388dc95a615b');
});

await asyncTest('2.5: SHA1 of full data buffer', async () => {
  const result = await hashModule.sha1(0, testData.length);
  // SHA1 of "Hello World!" is 2ef7bde608ce5404e97d5f042f95f89f1c232871
  assertEquals(result, '2ef7bde608ce5404e97d5f042f95f89f1c232871');
});

await asyncTest('2.6: SHA1 of partial data (first 5 bytes)', async () => {
  const result = await hashModule.sha1(0, 5);
  // SHA1 of "Hello" is f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
  assertEquals(result, 'f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0');
});

await asyncTest('2.7: SHA256 of full data buffer', async () => {
  const result = await hashModule.sha256(0, testData.length);
  // SHA256 of "Hello World!"
  assertEquals(result, '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069');
});

await asyncTest('2.8: SHA256 of partial data (last 6 bytes)', async () => {
  const result = await hashModule.sha256(6, 6);
  // SHA256 of "World!"
  assertEquals(result, '514b6bb7c846ecfb8d2d29ef0b5c79b63e6ae838f123da936fe827fda654276c');
});

await test('2.9: checksum32 of full data buffer', () => {
  const result = hashModule.checksum32(0, testData.length);
  // Sum of all bytes in "Hello World!"
  let sum = 0;
  for (let i = 0; i < testData.length; i++) sum += testData[i];
  assertEquals(result, sum);
});

await test('2.10: checksum32 of partial data (first 5 bytes)', () => {
  const result = hashModule.checksum32(0, 5);
  // Sum: H(72) + e(101) + l(108) + l(108) + o(111) = 500 = 0x1F4
  assertEquals(result, 500);
});

await test('2.11: CRC32 of full data buffer', () => {
  const result = hashModule.crc32(0, testData.length);
  // CRC32 of "Hello World!" is 0x1C291CA3
  assertEquals(result, 0x1C291CA3);
});

await test('2.12: CRC32 of partial data (first 5 bytes)', () => {
  const result = hashModule.crc32(0, 5);
  // CRC32 of "Hello"
  assertEquals(result, 0xF7D18982);
});

// =============================================================================
// Section 3: Edge Cases
// =============================================================================
console.log('\n📦 Section 3: Edge Cases');

await test('3.1: Hash module throws error on invalid range (negative offset)', () => {
  assertThrows(() => hashModule.checksum32(-1, 5));
});

await test('3.2: Hash module throws error on invalid range (negative size)', () => {
  assertThrows(() => hashModule.checksum32(0, -5));
});

await test('3.3: Hash module handles invalid range (exceeds buffer) with best effort', () => {
  const result = hashModule.checksum32(0, testData.length + 1);
  assertEquals(typeof result, 'number');
});

await test('3.4: Hash module handles invalid range (offset + size > length) with best effort', () => {
  const result = hashModule.checksum32(10, 10);
  assertEquals(typeof result, 'number');
});

await test('3.5: createHashModule throws error on null data', () => {
  assertThrows(() => createHashModule(null));
});

await test('3.6: createHashModule throws error on non-Uint8Array', () => {
  assertThrows(() => createHashModule([1, 2, 3]));
});

await asyncTest('3.7: Hash of zero-length region', async () => {
  const result = await hashModule.md5(0, 0);
  // MD5 of empty string
  assertEquals(result, 'd41d8cd98f00b204e9800998ecf8427e');
});

await test('3.8: checksum32 of zero-length region', () => {
  const result = hashModule.checksum32(5, 0);
  assertEquals(result, 0);
});

// =============================================================================
// Section 4: Unicode and Multi-byte Characters
// =============================================================================
console.log('\n📦 Section 4: Unicode and Multi-byte Characters');

await asyncTest('4.1: MD5 of string with emoji', async () => {
  const result = await hash.md5('Hello 👋 World 🌍');
  // Just verify it doesn't crash and returns valid hex
  assertEquals(result.length, 32);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await asyncTest('4.2: SHA1 of string with emoji', async () => {
  const result = await hash.sha1('🔥 Fire emoji');
  assertEquals(result.length, 40);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await asyncTest('4.3: SHA256 of Japanese text', async () => {
  const result = await hash.sha256('こんにちは世界');
  assertEquals(result.length, 64);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await test('4.4: checksum32 of emoji string', () => {
  const result = hash.checksum32('🎉');
  // Emoji is multiple bytes in UTF-8, checksum32 returns a number
  assertEquals(typeof result, 'number');
  assertEquals(result >= 0, true);
});

await test('4.5: CRC32 of Unicode string', () => {
  const result = hash.crc32('Ñoño');
  // CRC32 returns a number
  assertEquals(typeof result, 'number');
  assertEquals(result >= 0, true);
});

// =============================================================================
// Section 5: Large Data
// =============================================================================
console.log('\n📦 Section 5: Large Data');

const largeData = new Uint8Array(10000);
for (let i = 0; i < largeData.length; i++) {
  largeData[i] = i % 256;
}
const largeHashModule = createHashModule(largeData);

await asyncTest('5.1: MD5 of 10KB data', async () => {
  const result = await largeHashModule.md5(0, largeData.length);
  assertEquals(result.length, 32);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await asyncTest('5.2: SHA256 of 10KB data', async () => {
  const result = await largeHashModule.sha256(0, largeData.length);
  assertEquals(result.length, 64);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await test('5.3: checksum32 of 10KB data', () => {
  const result = largeHashModule.checksum32(0, largeData.length);
  // checksum32 returns a number
  assertEquals(typeof result, 'number');
  assertEquals(result >= 0, true);
});

await test('5.4: CRC32 of 10KB data', () => {
  const result = largeHashModule.crc32(0, largeData.length);
  // CRC32 returns a number
  assertEquals(typeof result, 'number');
  assertEquals(result >= 0, true);
});

// =============================================================================
// Section 6: Known Test Vectors
// =============================================================================
console.log('\n📦 Section 6: Known Test Vectors (RFC/Standard Tests)');

await asyncTest('6.1: MD5 test vector "abc"', async () => {
  const result = await hash.md5('abc');
  assertEquals(result, '900150983cd24fb0d6963f7d28e17f72');
});

await asyncTest('6.2: SHA1 test vector "abc"', async () => {
  const result = await hash.sha1('abc');
  assertEquals(result, 'a9993e364706816aba3e25717850c26c9cd0d89d');
});

await asyncTest('6.3: SHA256 test vector "abc"', async () => {
  const result = await hash.sha256('abc');
  assertEquals(result, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

await test('6.4: CRC32 test vector "The quick brown fox jumps over the lazy dog"', () => {
  const result = hash.crc32('The quick brown fox jumps over the lazy dog');
  assertEquals(result, 0x414FA339);
});

// =============================================================================
// Section 7: Binary Data
// =============================================================================
console.log('\n📦 Section 7: Binary Data');

const binaryData = new Uint8Array([0x00, 0xFF, 0x00, 0xFF, 0xAA, 0x55]);
const binaryHashModule = createHashModule(binaryData);

await asyncTest('7.1: MD5 of binary data', async () => {
  const result = await binaryHashModule.md5(0, binaryData.length);
  assertEquals(result.length, 32);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await asyncTest('7.2: SHA1 of binary data', async () => {
  const result = await binaryHashModule.sha1(0, binaryData.length);
  assertEquals(result.length, 40);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await asyncTest('7.3: SHA256 of binary data', async () => {
  const result = await binaryHashModule.sha256(0, binaryData.length);
  assertEquals(result.length, 64);
  assertEquals(/^[0-9a-f]+$/.test(result), true);
});

await test('7.4: checksum32 of binary data', () => {
  const result = binaryHashModule.checksum32(0, binaryData.length);
  // Sum: 0 + 255 + 0 + 255 + 170 + 85 = 765 = 0x2FD
  assertEquals(result, 765);
});

await test('7.5: CRC32 of binary data', () => {
  const result = binaryHashModule.crc32(0, binaryData.length);
  // CRC32 returns a number
  assertEquals(typeof result, 'number');
  assertEquals(result >= 0, true);
});

// =============================================================================
// Section 8: Consistency Tests
// =============================================================================
console.log('\n📦 Section 8: Consistency Tests (Module vs Standalone)');

await asyncTest('8.1: MD5 consistency - string hash vs module string hash', async () => {
  const standalone = await hash.md5('test');
  const module = await hashModule.md5('test');
  assertEquals(standalone, module);
});

await asyncTest('8.2: SHA1 consistency - string hash vs module string hash', async () => {
  const standalone = await hash.sha1('test');
  const module = await hashModule.sha1('test');
  assertEquals(standalone, module);
});

await asyncTest('8.3: SHA256 consistency - string hash vs module string hash', async () => {
  const standalone = await hash.sha256('test');
  const module = await hashModule.sha256('test');
  assertEquals(standalone, module);
});

await test('8.4: checksum32 consistency - string hash vs module string hash', () => {
  const standalone = hash.checksum32('test');
  const module = hashModule.checksum32('test');
  assertEquals(standalone, module);
});

await test('8.5: CRC32 consistency - string hash vs module string hash', () => {
  const standalone = hash.crc32('test');
  const module = hashModule.crc32('test');
  assertEquals(standalone, module);
});

// =============================================================================
// Section 9: Performance Characteristics
// =============================================================================
console.log('\n📦 Section 9: Performance Characteristics');

await test('9.1: Multiple hash calls on same data (no caching issues)', () => {
  const result1 = hashModule.checksum32(0, 5);
  const result2 = hashModule.checksum32(0, 5);
  assertEquals(result1, result2);
});

await asyncTest('9.2: Multiple MD5 calls return consistent results', async () => {
  const result1 = await hash.md5('consistent');
  const result2 = await hash.md5('consistent');
  const result3 = await hash.md5('consistent');
  assertEquals(result1, result2);
  assertEquals(result2, result3);
});

// =============================================================================
// Section 10: Hash Comparisons in Conditions
// =============================================================================
console.log('\n📦 Section 10: Hash Comparisons in Conditions (String Literals)');

await asyncTest('10.1: MD5 comparison with string literal in condition', async () => {
  const { InterceptScanner } = await import('../src/interceptScanner.mjs');
  const scanner = new InterceptScanner();
  
  const data = new TextEncoder().encode('test data');
  const hashMod = createHashModule(data);
  scanner.setModules({ hash: hashMod });
  
  scanner.addRules(`
    rule HashCheck {
      strings:
        $a = "test"
      condition:
        $a and hash.md5(0, filesize) == "eb733a00c0c9d336e65691a37ab54293"
    }
  `);
  
  const results = await scanner.scan(data);
  assertEquals(results.length, 1);
  assertEquals(results[0].rule, 'HashCheck');
});

await asyncTest('10.2: SHA256 comparison with string literal', async () => {
  const { InterceptScanner } = await import('../src/interceptScanner.mjs');
  const scanner = new InterceptScanner();
  
  const data = new TextEncoder().encode('hello');
  const hashMod = createHashModule(data);
  scanner.setModules({ hash: hashMod });
  
  scanner.addRules(`
    rule SHA256Check {
      condition:
        hash.sha256(0, filesize) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  `);
  
  const results = await scanner.scan(data);
  assertEquals(results.length, 1);
});

await asyncTest('10.3: Hash comparison not equal', async () => {
  const { InterceptScanner } = await import('../src/interceptScanner.mjs');
  const scanner = new InterceptScanner();
  
  const data = new TextEncoder().encode('test data');
  const hashMod = createHashModule(data);
  scanner.setModules({ hash: hashMod });
  
  scanner.addRules(`
    rule HashNotMatch {
      condition:
        hash.md5(0, filesize) == "wronghashvalue12345678901234567890"
    }
  `);
  
  const results = await scanner.scan(data);
  assertEquals(results.length, 0);
});

await asyncTest('10.4: Multiple hash comparisons combined', async () => {
  const { InterceptScanner } = await import('../src/interceptScanner.mjs');
  const scanner = new InterceptScanner();
  
  const data = new TextEncoder().encode('test data');
  const hashMod = createHashModule(data);
  scanner.setModules({ hash: hashMod });
  
  scanner.addRules(`
    rule MultiHashCheck {
      condition:
        hash.md5(0, 9) == "eb733a00c0c9d336e65691a37ab54293" and
        filesize == 9
    }
  `);
  
  const results = await scanner.scan(data);
  assertEquals(results.length, 1);
});

// =============================================================================
// Test Summary
// =============================================================================
console.log('\n' + '='.repeat(70));
console.log('Test Summary');
console.log('='.repeat(70));

printSummary();
