/**
 * Test Suite: Direct String Matching
 * Tests the internal findPlainMatches function for wide strings
 */

import { test, assertTrue, assertEquals, printSummary, printSection } from './testingFramework.mjs';

// Manually inline the function being tested
function findPlainMatches(data, pattern, nocase = false) {
  const matches = [];
  const pLen = pattern.length;
  const dLen = data.length;
  outer: for (let i = 0; i <= dLen - pLen; i++) {
    for (let j = 0; j < pLen; j++) {
      const dataByte = nocase ? lowercaseByte(data[i + j]) : data[i + j];
      if (dataByte !== pattern[j]) continue outer;
    }
    matches.push({ offset: i });
  }
  return matches;
}

function lowercaseByte(b) {
  if (b >= 0x41 && b <= 0x5a) {
    return b + 0x20;
  }
  return b;
}

printSection('Direct String Matching Tests');

await test('Wide string pattern matching', async () => {
  // Test data: wide version of "SGk="
  const b64 = 'SGk=';
  const wideB64 = new Uint8Array(b64.length * 2);
  for (let i = 0; i < b64.length; i++) {
    wideB64[i * 2] = b64.charCodeAt(i);
    wideB64[i * 2 + 1] = 0;
  }

  // Pattern: wide version of "SGk" (without '=')
  const b64NoEquals = 'SGk';
  const pattern = new Uint8Array(b64NoEquals.length * 2);
  for (let i = 0; i < b64NoEquals.length; i++) {
    pattern[i * 2] = b64NoEquals.charCodeAt(i);
    pattern[i * 2 + 1] = 0;
  }

  const matches = findPlainMatches(wideB64, pattern, false);
  assertEquals(matches.length, 1, 'Should find exactly 1 match');
  assertEquals(matches[0].offset, 0, 'Match should be at offset 0');
});

await test('Case-insensitive wide string matching', async () => {
  const text = 'ABC';
  const wideText = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    wideText[i * 2] = text.charCodeAt(i);
    wideText[i * 2 + 1] = 0;
  }

  const pattern = 'abc';
  const widePattern = new Uint8Array(pattern.length * 2);
  for (let i = 0; i < pattern.length; i++) {
    widePattern[i * 2] = pattern.charCodeAt(i);
    widePattern[i * 2 + 1] = 0;
  }

  const matches = findPlainMatches(wideText, widePattern, true);
  assertEquals(matches.length, 1, 'Should find case-insensitive match');
});

await test('No match when pattern not present', async () => {
  const text = 'Hello';
  const wideText = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    wideText[i * 2] = text.charCodeAt(i);
    wideText[i * 2 + 1] = 0;
  }

  const pattern = 'XYZ';
  const widePattern = new Uint8Array(pattern.length * 2);
  for (let i = 0; i < pattern.length; i++) {
    widePattern[i * 2] = pattern.charCodeAt(i);
    widePattern[i * 2 + 1] = 0;
  }

  const matches = findPlainMatches(wideText, widePattern, false);
  assertEquals(matches.length, 0, 'Should find no matches');
});

printSummary();
