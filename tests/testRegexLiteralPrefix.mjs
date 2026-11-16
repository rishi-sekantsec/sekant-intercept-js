/**
 * Regression tests for regex strings that have a literal prefix.
 *
 * `makeRegexMatcher` compiles one `g`-flagged RegExp and keeps it for the lifetime of the matcher,
 * while the scanner calls that matcher once per Aho-Corasick candidate. An early `break` in a
 * single-run verification (and the MAX_MATCHES cap) left `lastIndex` mid-text, so later candidates
 * started scanning past the match they were supposed to confirm: matches were lost from the third
 * candidate onward and a later offset was reported more than once.
 */

import { compileYaraLike } from '../src/yaraStringMatch.mjs';
import { InterceptScanner } from '../src/interceptScanner.mjs';
import {
  test,
  assertTrue,
  assertEquals,
  assertDeepEquals,
  printSection,
  printSummary,
} from './testingFramework.mjs';

const encoder = new TextEncoder();
const toBytes = (text) => encoder.encode(text);
const passwordLines = (n) => Array.from({ length: n }, (_, i) => `password: v${i}`).join('\n') + '\n';

/** Compile a single rule whose only string is `$m` and return its scan facts for `$m`. */
async function scanMatches(decl, input, scanner = new InterceptScanner({})) {
  scanner.addRules(`rule r {\n  strings:\n    ${decl}\n  condition:\n    #m > 0\n}`);
  const results = await scanner.scan(Buffer.from(input, 'latin1'));
  return results[0]?.strings?.$m ?? { count: 0, offsets: [] };
}

printSection('REGEX WITH LITERAL PREFIX - LASTINDEX REGRESSION');

// ============================================================================
// Section 1: Scanner-level results (the reported bug)
// ============================================================================

console.log('\n📋 Section 1: Scanner-level matches\n');

const expectedOffsets = (n) => Array.from({ length: n }, (_, i) => i * 13);

for (const count of [3, 4, 6]) {
  await test(`1.${[3, 4, 6].indexOf(count) + 1} Regex with literal prefix finds all ${count} occurrences`, async () => {
    const result = await scanMatches('$m = /password: [A-Za-z0-9]+/', passwordLines(count));
    assertDeepEquals(result.offsets, expectedOffsets(count), `offsets for ${count} occurrences`);
    assertEquals(result.count, count, 'match count');
  });
}

await test('1.4 Same scanner stays correct across repeated scans', async () => {
  const scanner = new InterceptScanner({});
  const first = await scanMatches('$m = /password: [A-Za-z0-9]+/', passwordLines(6), scanner);
  const second = await scanMatches('$m = /password: [A-Za-z0-9]+/', passwordLines(6), scanner);
  assertDeepEquals(second.offsets, expectedOffsets(6), 'second scan offsets');
  assertDeepEquals(second.offsets, first.offsets, 'both scans agree');
});

await test('1.5 Regex without a literal prefix is unaffected', async () => {
  const result = await scanMatches('$m = /[a-z]{2}[0-9]{2}/', 'aa11 bb22 cc33 dd44 ee55');
  assertDeepEquals(result.offsets, [0, 5, 10, 15, 20], 'offsets');
});

await test('1.6 Literal text control is unaffected', async () => {
  const result = await scanMatches('$m = "password: "', passwordLines(6));
  assertDeepEquals(result.offsets, expectedOffsets(6), 'offsets');
});

// ============================================================================
// Section 2: Direct matcher calls (isolates the shared-RegExp state)
// ============================================================================

console.log('\n📋 Section 2: Repeated matcher calls\n');

await test('2.1 Successive single-run calls each report their own offset', () => {
  const { matcher, literalPrefix } = compileYaraLike('/password: [A-Za-z0-9]+/');
  assertEquals(literalPrefix, 'password: ', 'pattern really has a literal prefix');

  const data = toBytes(passwordLines(6));
  for (const offset of expectedOffsets(6)) {
    const matches = matcher(data, offset);
    assertTrue(matches.length === 1, `candidate at ${offset} verified exactly once`);
    assertEquals(matches[0].offset, offset, `candidate at ${offset} reported at its own offset`);
  }
});

await test('2.2 A candidate the regex rejects reports nothing', () => {
  // "password: " is the prefix, but the trailing text has no [0-9] here, so this candidate fails.
  const { matcher } = compileYaraLike('/password: [0-9]+/');
  const data = toBytes('password: abc\npassword: 42\n');
  assertDeepEquals(matcher(data, 0), [], 'rejected candidate yields no match');
  assertDeepEquals(matcher(data, 14).map((m) => m.offset), [14], 'valid candidate still resolves');
});

await test('2.3 Full-data scans are repeatable', () => {
  const { matcher } = compileYaraLike('/password: [A-Za-z0-9]+/');
  const data = toBytes(passwordLines(6));
  const first = matcher(data).map((m) => m.offset);
  const second = matcher(data).map((m) => m.offset);
  assertDeepEquals(first, expectedOffsets(6), 'first full scan');
  assertDeepEquals(second, first, 'second full scan must not inherit lastIndex');
});

await test('2.4 Overlapping prefixes map to their own matches', () => {
  const overlapping = compileYaraLike('/aa+/');
  const repeats = compileYaraLike('/a+/');
  assertDeepEquals(overlapping.matcher(toBytes('aaa')).map((m) => m.offset), [0, 1], '/aa+/ on "aaa"');
  assertDeepEquals(repeats.matcher(toBytes('aaa')).map((m) => m.offset), [0, 1, 2], '/a+/ on "aaa"');
});

await test('2.5 The MAX_MATCHES cap does not leak into the next run', () => {
  const { matcher } = compileYaraLike('/password: [A-Za-z0-9]+/');
  const data = toBytes(passwordLines(150));
  const first = matcher(data);
  const second = matcher(data);
  assertEquals(first.length, 100, 'capped at MAX_MATCHES');
  assertDeepEquals(second.map((m) => m.offset), first.map((m) => m.offset), 'second run identical');
});

await test('2.6 Hex matcher is repeatable after hitting the cap', () => {
  const { matcher } = compileYaraLike('{ 41 42 }');
  const data = toBytes('AB'.repeat(150));
  const first = matcher(data);
  const second = matcher(data);
  assertEquals(first.length, 100, 'capped at MAX_MATCHES');
  assertDeepEquals(second, first, 'hex matcher must reset its RegExp between runs');
});

// ============================================================================
// SUMMARY
// ============================================================================
printSummary();
