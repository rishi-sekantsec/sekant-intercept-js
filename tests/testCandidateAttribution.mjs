/**
 * Regression tests for per-candidate verification attribution.
 *
 * The scanner calls a string matcher once per Aho-Corasick candidate, verifying "is there a match
 * at this offset?". Two defects made that answer wrong when occurrences overlap:
 *
 * - `makeRegexMatcher` compiles one `g`-flagged RegExp for the matcher's lifetime. An early `break`
 *   in a single run (and the MAX_MATCHES cap) left `lastIndex` mid-text, so later candidates
 *   scanned past the match they were supposed to confirm: matches were dropped from the third
 *   candidate onward and a later offset was reported more than once.
 * - The text matcher searched from the start of its slice, which lies one byte before the
 *   candidate for fullword context, so it re-reported the previous occurrence and lost its own
 *   (e.g. `"aa"` on `"aaa"` produced offsets [0,0] instead of [0,1]).
 *
 * A verification run must report the candidate's own offset or nothing at all, which is what the
 * matchers' `verifyAt(data, offset)` entry point does; the plain `matcher(data, offset)` form stays
 * a window scan.
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

printSection('STRING CANDIDATE VERIFICATION - ATTRIBUTION');

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
    const matches = matcher.verifyAt(data, offset);
    assertTrue(matches.length === 1, `candidate at ${offset} verified exactly once`);
    assertEquals(matches[0].offset, offset, `candidate at ${offset} reported at its own offset`);
  }
});

await test('2.2 A candidate the regex rejects reports nothing', () => {
  // "password: " is the prefix, but the trailing text has no [0-9] here, so this candidate fails.
  const { matcher } = compileYaraLike('/password: [0-9]+/');
  const data = toBytes('password: abc\npassword: 42\n');
  assertDeepEquals(matcher.verifyAt(data, 0), [], 'rejected candidate yields no match');
  assertDeepEquals(matcher.verifyAt(data, 14).map((m) => m.offset), [14], 'valid candidate still resolves');
});

await test('2.3 Full-data scans are repeatable', () => {
  const { matcher } = compileYaraLike('/password: [A-Za-z0-9]+/');
  const data = toBytes(passwordLines(6));
  const first = matcher(data).map((m) => m.offset);
  const second = matcher(data).map((m) => m.offset);
  assertDeepEquals(first, expectedOffsets(6), 'first full scan');
  assertDeepEquals(second, first, 'second full scan must not inherit lastIndex');
});

await test('2.3b The window-scan form keeps its documented behaviour', () => {
  // `matcher(data, offset, maxLength)` scans a window starting at `offset` — it is not an
  // exact-offset check, and existing callers/tests rely on that. `verifyAt` is the exact form.
  const data = toBytes('prefix test suffix');
  for (const decl of ['"test"', '/test/']) {
    const { matcher } = compileYaraLike(decl);
    assertDeepEquals(matcher(data, 0).map((m) => m.offset), [7], `${decl}: window from 0 finds the later match`);
    assertDeepEquals(matcher(data, 7).map((m) => m.offset), [7], `${decl}: window at the match`);
    assertDeepEquals(matcher(data, 9), [], `${decl}: window past the match finds nothing`);
    assertDeepEquals(matcher.verifyAt(data, 0), [], `${decl}: exact check at 0 fails`);
    assertDeepEquals(matcher.verifyAt(data, 7).map((m) => m.offset), [7], `${decl}: exact check at the match`);
  }
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

await test('2.7 Scanner maxMatches raises the cap for hex and prefixless regex', async () => {
  const scanner = new InterceptScanner({ maxMatches: 250 });
  const hex = await scanMatches('$m = { 41 42 }', 'AB'.repeat(300), scanner);
  assertEquals(hex.count, 250, 'hex matches honour maxMatches');
  assertEquals(hex.offsets.length, 250, 'offsets stay in sync with matches');

  const re = await scanMatches('$m = /[0-9]/', '0123456789'.repeat(30), new InterceptScanner({ maxMatches: 250 }));
  assertEquals(re.count, 250, 'prefixless regex honour maxMatches');
});

await test('2.8 Changing maxMatches after compile affects already-compiled rules', async () => {
  const scanner = new InterceptScanner({});
  const first = await scanMatches('$m = { 41 42 }', 'AB'.repeat(300), scanner);
  assertEquals(first.count, 100, 'default cap');
  scanner.maxMatches = 250;
  const second = await scanner.scan(Buffer.from('AB'.repeat(300), 'latin1'));
  assertEquals(second[0].strings.$m.count, 250, 'updated limit reaches the compiled matcher');
});

// ============================================================================
// Section 3: Overlapping text strings (previously duplicated the prior offset)
// ============================================================================

console.log('\n📋 Section 3: Overlapping text occurrences\n');

await test('3.1 Overlapping text reports every occurrence', async () => {
  assertDeepEquals((await scanMatches('$m = "aa"', 'aaa')).offsets, [0, 1], '"aa" on "aaa"');
  assertDeepEquals((await scanMatches('$m = "aa"', 'aaaa')).offsets, [0, 1, 2], '"aa" on "aaaa"');
});

await test('3.2 Overlapping text is case-insensitive when nocase', async () => {
  const result = await scanMatches('$m = "aa" nocase', 'AaAa');
  assertDeepEquals(result.offsets, [0, 1, 2], 'nocase overlaps');
});

await test('3.3 Overlapping wide text keeps its alignment', async () => {
  const data = Buffer.from('a\0a\0a\0', 'latin1');
  const scanner = new InterceptScanner({});
  scanner.addRules('rule r {\n  strings:\n    $m = "a" wide\n  condition:\n    #m > 0\n}');
  const [hit] = await scanner.scan(data);
  assertDeepEquals(hit.strings.$m.offsets, [0, 2, 4], 'wide overlaps');
});

await test('3.4 Overlapping xor text keeps every key match', async () => {
  // "AB" xor(0x01) == "@C"
  const result = await scanMatches('$m = "AB" xor(0x01)', '@C@C@C');
  assertDeepEquals(result.offsets, [0, 2, 4], 'xor overlaps');
});

await test('3.5 Text verification reports its own offset or nothing', () => {
  const { matcher } = compileYaraLike('"aa"');
  const data = toBytes('aaa');
  assertDeepEquals(matcher.verifyAt(data, 0).map((m) => m.offset), [0], 'candidate at 0');
  assertDeepEquals(matcher.verifyAt(data, 1).map((m) => m.offset), [1], 'candidate at 1');
  assertDeepEquals(matcher.verifyAt(data, 2), [], 'candidate past the last occurrence matches nothing');
});

await test('3.6 Non-overlapping text is unaffected', async () => {
  const result = await scanMatches('$m = "password: "', passwordLines(6));
  assertDeepEquals(result.offsets, expectedOffsets(6), 'offsets');
});

// ============================================================================
// SUMMARY
// ============================================================================
printSummary();
