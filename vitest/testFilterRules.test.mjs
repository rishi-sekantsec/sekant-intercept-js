/**
 * Intercept Filter Rule Tests
 *
 * Covers `filter rule` declarations and the `reject(...)` string modifier:
 * modifier parsing/composition, candidate-only evaluation across encodings, fact semantics,
 * boundaries, fail-open behavior, compilation errors, diagnostics, registry isolation, the
 * direct scanFilterRules() API, and module caching/laziness.
 */

import { InterceptScanner, MAX_FILTER_RULE_BUFFER_SIZE } from '../src/interceptScanner.mjs';
import { parseYaraRuleGroup, parseInterceptFilterRuleGroup } from '../src/yaraRuleCompiler.mjs';
import { compileYaraLike } from '../src/yaraStringMatch.mjs';
import { BaseCustomModule } from '../src/interceptCustomModules.mjs';
import {
  test,
  assertEquals,
  assertTrue,
  assertArrayLength,
  assertThrows,
  printSummary,
} from './testingFramework.mjs';

console.log('═══════════════════════════════════════════════════════════════');
console.log('  INTERCEPT FILTER RULE TESTS');
console.log('═══════════════════════════════════════════════════════════════\n');

const ALWAYS = `
  filter rule always {
    condition:
      true
  }
`;

const NEVER = `
  filter rule never {
    condition:
      false
  }
`;

// ═════════════════════════════════════════════════════════════════════════
// Section 1: Modifier parsing and composition
// ═════════════════════════════════════════════════════════════════════════

await test('1.1 reject is extracted from text, hex, and regex modifiers', () => {
  assertEquals(compileYaraLike('"abc" reject(first, second)').reject.join(','), 'first,second');
  assertEquals(compileYaraLike('{ 41 42 } reject(hex_filter)').reject.join(','), 'hex_filter');
  assertEquals(compileYaraLike('/ab+c/i reject(regex_filter)').reject.join(','), 'regex_filter');
  assertTrue(compileYaraLike('/ab+c/i reject(regex_filter)').nocase, 'i flag should still be honored');
});

await test('1.2 reject inside a string literal or a longer word is not a modifier', () => {
  assertEquals(compileYaraLike('"reject(fake)"').reject.length, 0);
  assertEquals(compileYaraLike('"abc" rejected(f)').reject.length, 0);
  assertEquals(compileYaraLike('"abc" rejectx(f)').reject.length, 0);
});

await test('1.3 repeated reject modifiers are unioned and deduplicated', () => {
  const compiled = compileYaraLike('"abc" reject(a, b) reject(b, c)');
  assertEquals(compiled.reject.join(','), 'a,b,c');
});

await test('1.4 empty reject is a no-op', () => {
  assertEquals(compileYaraLike('"abc" reject()').reject.length, 0);
});

await test('1.5 reject composes with nocase, wide, xor, and private', () => {
  const nocase = compileYaraLike('"abc" nocase reject(f)');
  assertTrue(nocase.nocase, 'nocase should survive reject extraction');
  assertEquals(nocase.reject.join(','), 'f');

  const reordered = compileYaraLike('"abc" reject(f) wide');
  assertTrue(reordered.patterns.some((pattern) => pattern.isWide), 'wide should survive reject extraction');

  const xor = compileYaraLike('"abc" xor(1-2) reject(f)');
  assertEquals(xor.xor.join(','), '1,2');
  assertEquals(xor.reject.join(','), 'f');

  const priv = compileYaraLike('"abc" private reject(f)');
  assertTrue(priv.private, 'private should survive reject extraction');
});

await test('1.6 whitespace and uppercase REJECT are accepted while names keep their case', () => {
  assertEquals(compileYaraLike('"abc" reject ( a , b )').reject.join(','), 'a,b');
  assertEquals(compileYaraLike('"abc" REJECT(MyFilter)').reject.join(','), 'MyFilter');
});

await test('1.7 hex and regex modifiers compose with reject', () => {
  const hex = compileYaraLike('{ 41 42 } private reject(f)');
  assertTrue(hex.private, 'hex private flag should survive');
  assertEquals(hex.reject.join(','), 'f');

  const regex = compileYaraLike('/a.b/s reject(f)');
  assertEquals(regex.reject.join(','), 'f');
  assertTrue(regex.matcher(new TextEncoder().encode('a\nb'), -1).length > 0, 's flag should still apply');
});

await test('1.8 rejectRECapture is extracted for all three string types', () => {
  assertEquals(compileYaraLike('"abc" rejectRECapture(cap)').rejectCapture.join(','), 'cap');
  assertEquals(compileYaraLike('{ 41 42 } rejectRECapture(cap)').rejectCapture.join(','), 'cap');
  assertEquals(compileYaraLike('/ab(c)/ rejectRECapture(cap)').rejectCapture.join(','), 'cap');
  assertEquals(compileYaraLike('"abc" rejectRECapture(cap)').reject.length, 0);
});

await test('1.9 reject and rejectRECapture stay in their own lists on one string', () => {
  const compiled = compileYaraLike('/ab(c)/ reject(full) rejectRECapture(cap)');
  assertEquals(compiled.reject.join(','), 'full');
  assertEquals(compiled.rejectCapture.join(','), 'cap');
  assertTrue(compiled.reject.length > 0, 'plain reject must not be swallowed by the capture variant');
});

await test('1.10 rejectRECapture accepts whitespace, uppercase, and repeated/empty forms', () => {
  assertEquals(compileYaraLike('"abc" rejectRECapture ( a , b )').rejectCapture.join(','), 'a,b');
  assertEquals(compileYaraLike('"abc" REJECTRECAPTURE(MyFilter)').rejectCapture.join(','), 'MyFilter');
  assertEquals(compileYaraLike('"abc" rejectRECapture()').rejectCapture.length, 0);
  assertEquals(
    compileYaraLike('"abc" rejectRECapture(a) rejectRECapture(a, b)').rejectCapture.join(','),
    'a,b'
  );
});

await test('1.11 rejectRECapture does not disturb regex flags or other modifiers', () => {
  const compiled = compileYaraLike('/ab(c)/i rejectRECapture(cap)');
  assertTrue(compiled.nocase, 'i flag should survive capture extraction');
  assertTrue(compileYaraLike('/ab(c)/rejectRECapture(cap)').nocase === false, 'no stray flag');
  assertTrue(
    compileYaraLike('"abc" nocase rejectRECapture(cap)').nocase,
    'text modifiers should survive capture extraction'
  );
});

// ═════════════════════════════════════════════════════════════════════════
// Section 2: Filtering behavior
// ═════════════════════════════════════════════════════════════════════════

await test('2.1 reject discards candidates and counts each rejected occurrence', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule HasShort {
      strings:
        $a = "abc" reject(always)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc xyz abc');
  assertArrayLength(results, 0);
  const count = results.diagnostics.find((entry) => entry.code === 'filter-rejection-count');
  assertEquals(count?.filter, 'always');
  assertEquals(count?.message.includes('2 candidate'), true);
});

await test('2.2 candidates are kept when all filters return false', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${NEVER}
    rule HasShort {
      strings:
        $a = "abc" reject(never)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc xyz abc');
  assertArrayLength(results, 1);
  assertEquals(results[0].strings.$a.count, 2);
});

await test('2.3 filter rule strings scan only the candidate buffer', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule starts_with_mal {
      strings:
        $m = "mal"
      condition:
        $m
    }
    rule Mixed {
      strings:
        $bad = "malware" reject(starts_with_mal)
        $good = "benign" reject(starts_with_mal)
      condition:
        any of them
    }
  `);

  const results = await scanner.scan('malware benign');
  assertArrayLength(results, 1);
  assertEquals(results[0].strings.$good?.matched, true);
  assertEquals(results[0].strings.$bad, undefined);
});

await test('2.4 multiple filters are an OR and unknown names are skipped', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${NEVER}${ALWAYS}
    rule Mixed {
      strings:
        $a = "abc" reject(missing_filter, never, always)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 0);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'unknown-filter-rule'));
});

await test('2.5 filters are applied before string facts are built', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule Filtered {
      strings:
        $a = "abc" reject(always)
      condition:
        #a == 2
    }
    rule Unfiltered {
      strings:
        $a = "abc"
      condition:
        #a == 2
    }
  `);

  const results = await scanner.scan('abc abc');
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'Unfiltered');
});

await test('2.6 hex and regex strings support reject', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule starts_with_mal {
      strings:
        $m = "mal"
      condition:
        $m
    }
    rule HexRule {
      strings:
        $h = { 4D 5A } reject(starts_with_mal)
      condition:
        $h
    }
    rule RegexRule {
      strings:
        $r = /ma[a-z]+/ reject(starts_with_mal)
      condition:
        $r
    }
  `);

  const results = await scanner.scan('MZ malware');
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'HexRule');
});

await test('2.7 wide candidates are filtered on their wide bytes', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule is_wide {
      condition:
        filesize == 6 and uint8(1) == 0
    }
    rule WideRule {
      strings:
        $a = "abc" wide reject(is_wide)
      condition:
        $a
    }
    rule PlainRule {
      strings:
        $b = "abc" reject(is_wide)
      condition:
        $b
    }
  `);

  const results = await scanner.scan('abc a\u0000b\u0000c\u0000');
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'PlainRule', 'the wide candidate should be rejected');
});

await test('2.8 nocase matching still presents the original candidate case to filters', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule sees_upper {
      strings:
        $m = "ABC"
      condition:
        $m
    }
    rule R {
      strings:
        $a = "abc" nocase reject(sees_upper)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('ABC'), 0);
  assertArrayLength(await scanner.scan('abc'), 1);
});

await test('2.9 xor candidates present the encoded bytes to filters', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule xor_candidate {
      condition:
        uint8(0) == 0x60 and uint8(1) == 0x63 and uint8(2) == 0x62
    }
    rule R {
      strings:
        $a = "abc" xor(1-1) reject(xor_candidate)
      condition:
        $a
    }
  `);

  const results = await scanner.scan(new Uint8Array([0x60, 0x63, 0x62]));
  assertArrayLength(results, 0);
});

await test('2.10 base64 candidates present the encoded text to filters', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule b64_candidate {
      condition:
        filesize == 4 and uint8(0) == 0x59
    }
    rule R {
      strings:
        $a = "abc" base64 reject(b64_candidate)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('YWJj'), 0);
});

await test('2.11 fullword, private, and anonymous strings support reject', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}${NEVER}
    rule Fullword {
      strings:
        $a = "cat" fullword reject(always)
      condition:
        $a
    }
    rule PrivateString {
      strings:
        $a = "dog" private reject(never)
      condition:
        $a
    }
    rule Anonymous {
      strings:
        $ = "fox" reject(always)
      condition:
        any of them
    }
  `);

  const results = await scanner.scan('cat dog fox');
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'PrivateString');
  assertEquals(results[0].strings.$a, undefined, 'private string should stay hidden');
});

await test('2.12 filter conditions support all of them, #a, @a, and at', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule both_parts {
      strings:
        $x = "ab"
        $y = "bc"
      condition:
        all of them and #x == 1 and @x == 0 and $y at 1
    }
    rule R {
      strings:
        $a = "abc" reject(both_parts)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('2.13 filter conditions support loops without treating the loop variable as a module', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule has_zero {
      condition:
        for any i in (0..filesize-1) : (uint8(i) == 0)
    }
    rule R {
      strings:
        $a = { 61 00 62 } reject(has_zero)
      condition:
        $a
    }
  `);

  const results = await scanner.scan(new Uint8Array([0x61, 0x00, 0x62]));
  assertArrayLength(results, 0);
  assertEquals(
    results.diagnostics.filter((entry) => entry.code === 'unknown-module').length,
    0
  );
});

await test('2.14 filter facts are buffer-relative: entrypoint is zero', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule zero_entrypoint {
      condition:
        entrypoint == 0
    }
    rule R {
      strings:
        $a = "abc" reject(zero_entrypoint)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('2.15 hash and math modules operate on the candidate buffer', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule abc_md5 {
      condition:
        hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72"
    }
    filter rule high_entropy {
      condition:
        math.entropy(0, filesize) > 1
    }
    rule ByHash {
      strings:
        $a = "abc" reject(abc_md5)
      condition:
        $a
    }
    rule ByEntropy {
      strings:
        $b = "xyz" reject(high_entropy)
      condition:
        $b
    }
  `);

  assertArrayLength(await scanner.scan('abc xyz'), 0);
});

await test('2.16 string module functions are available inside filters', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule parses_int {
      condition:
        string.to_int("42") == 42
    }
    rule R {
      strings:
        $a = "abc" reject(parses_int)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('2.17 non-boolean filter results do not reject', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule numeric {
      condition:
        1
    }
    rule R {
      strings:
        $a = "abc" reject(numeric)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 1);
});

await test('2.18 filter rule strings may be hex or regex', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule hex_and_regex {
      strings:
        $h = { 4D 5A }
        $r = /dr[0-9]+/
      condition:
        $h and $r
    }
    rule R {
      strings:
        $a = { 4D 5A 64 72 31 } reject(hex_and_regex)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan(new Uint8Array([0x4d, 0x5a, 0x64, 0x72, 0x31])), 0);
});

// ── rejectRECapture buffer selection ─────────────────────────────────────

const scanCapture = async (filterCondition, stringDefinition, data) => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule probe {
      condition:
        ${filterCondition}
    }
    rule R {
      strings:
        ${stringDefinition}
      condition:
        any of them
    }
  `);
  return scanner.scan(data);
};

await test('2.19 rejectRECapture passes capture group 1, not the full match', async () => {
  // group 1 is "cde" (3 bytes), the full match is "abcdef" (6)
  assertArrayLength(await scanCapture('filesize == 3', '$a = /ab(cde)f/ rejectRECapture(probe)', 'abcdef'), 0);
  assertArrayLength(await scanCapture('filesize == 6', '$a = /ab(cde)f/ rejectRECapture(probe)', 'abcdef'), 1);
});

await test('2.20 rejectRECapture uses only the first capture group', async () => {
  assertArrayLength(await scanCapture('filesize == 3', '$a = /ab(cde)(fg)/ rejectRECapture(probe)', 'abcdefg'), 0);
  assertArrayLength(await scanCapture('filesize == 2', '$a = /ab(cde)(fg)/ rejectRECapture(probe)', 'abcdefg'), 1);
});

await test('2.21 rejectRECapture falls back to the full match when there is no group', async () => {
  assertArrayLength(await scanCapture('filesize == 6', '$a = /abcdef/ rejectRECapture(probe)', 'abcdef'), 0);
  assertArrayLength(await scanCapture('filesize == 3', '$a = /abcdef/ rejectRECapture(probe)', 'abcdef'), 1);
});

await test('2.22 rejectRECapture falls back when group 1 did not participate', async () => {
  // "abc" matches via the second alternative, so group 1 is undefined
  assertArrayLength(await scanCapture('filesize == 3', '$a = /(?:x)|(abc)/ rejectRECapture(probe)', 'abc'), 0);
});

await test('2.23 rejectRECapture falls back when group 1 is empty', async () => {
  assertArrayLength(await scanCapture('filesize == 3', '$a = /ab(.*)f/ rejectRECapture(probe)', 'abf'), 0);
});

await test('2.24 text and hex strings fall back to the full match', async () => {
  assertArrayLength(await scanCapture('filesize == 3', '$a = "abc" rejectRECapture(probe)', 'abc'), 0);
  assertArrayLength(
    await scanCapture('filesize == 3', '$a = { 61 62 63 } rejectRECapture(probe)', new Uint8Array([0x61, 0x62, 0x63])),
    0
  );
});

await test('2.25 reject and rejectRECapture receive different buffers on one string', async () => {
  // full match is 6 bytes, capture is 3; the rule matches when either string survives
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule only_full {
      condition:
        filesize == 6
    }
    rule R {
      strings:
        $full = /ab(cde)f/ reject(only_full)
        $cap = /ab(cde)f/ rejectRECapture(only_full)
      condition:
        any of them
    }
  `);

  const results = await scanner.scan('abcdef');
  assertArrayLength(results, 1);
  assertEquals(results[0].strings.$cap?.matched, true, 'capture string should survive');
  assertEquals(results[0].strings.$full, undefined, 'full-match string should be rejected');
});

await test('2.26 rejectRECapture works with the i flag and multibyte captures', async () => {
  assertArrayLength(await scanCapture('filesize == 3', '$a = /AB(cde)F/i rejectRECapture(probe)', 'abcdef'), 0);

  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule one_char {
      condition:
        filesize == 4
    }
    rule R {
      strings:
        $a = /x(.+)y/ rejectRECapture(one_char)
      condition:
        $a
    }
  `);
  // "😀" is 4 UTF-8 bytes
  assertArrayLength(await scanner.scan('x😀y'), 0);
});

// ═════════════════════════════════════════════════════════════════════════
// Section 3: Boundaries, fail-open, and module resolution
// ═════════════════════════════════════════════════════════════════════════

await test('3.1 a candidate of exactly MAX_FILTER_RULE_BUFFER_SIZE is filtered', async () => {
  assertEquals(MAX_FILTER_RULE_BUFFER_SIZE, 4096);

  const data = 'A' + 'x'.repeat(4094) + 'B';
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule Boundary {
      strings:
        $a = { 41 [4094] 42 } reject(always)
      condition:
        $a
    }
  `);

  const results = await scanner.scan(data);
  assertArrayLength(results, 0);
  assertEquals(
    results.diagnostics.filter((entry) => entry.code === 'filter-buffer-too-large').length,
    0
  );
});

await test('3.2 a candidate above MAX_FILTER_RULE_BUFFER_SIZE keeps the match and is diagnosed', async () => {
  const data = 'A' + 'x'.repeat(4095) + 'B';
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule Oversize {
      strings:
        $a = { 41 [4095] 42 } reject(always)
      condition:
        $a
    }
  `);

  const results = await scanner.scan(data);
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'filter-buffer-too-large'));
});

await test('3.3 a failing filter fails open and records filter-error', async () => {
  class ThrowingModule extends BaseCustomModule {
    constructor() {
      super('boom');
    }

    async initialize() {
      throw new Error('boom');
    }

    createModule() {
      return {};
    }
  }

  const scanner = new InterceptScanner({ modules: { boom: new ThrowingModule() } });
  scanner.compile(`
    filter rule explodes {
      condition:
        boom.value == 1
    }
    rule R {
      strings:
        $a = "abc" reject(explodes)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'filter-error'));
});

await test('3.4 an unknown module is diagnosed and fails open', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule unknown_module {
      condition:
        fakemod.value == 1
    }
    rule R {
      strings:
        $a = "abc" reject(unknown_module)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'unknown-module'));
  assertTrue(results.diagnostics.some((entry) => entry.code === 'filter-error'));
});

await test('3.5 a custom module registered after compilation is usable', async () => {
  class LaterModule extends BaseCustomModule {
    constructor() {
      super('later');
    }

    async initialize() {
      return { value: 1 };
    }

    createModule(interimResults) {
      return interimResults;
    }
  }

  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule later_filter {
      condition:
        later.value == 1
    }
    rule R {
      strings:
        $a = "abc" reject(later_filter)
      condition:
        $a
    }
  `);

  assertTrue(scanner.filterDiagnostics.some((entry) => entry.code === 'unknown-module'));

  scanner.setModules({ later: new LaterModule() });
  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('3.6 custom modules resolve by getName(), not registration key', async () => {
  class KeywordModule extends BaseCustomModule {
    constructor() {
      super('keyword');
    }

    async initialize() {
      return { value: 42 };
    }

    createModule(interimResults) {
      return interimResults;
    }
  }

  const scanner = new InterceptScanner({ modules: { registeredUnderOtherKey: new KeywordModule() } });
  scanner.compile(`
    filter rule uses_keyword {
      condition:
        keyword.value == 42
    }
    rule R {
      strings:
        $a = "abc" reject(uses_keyword)
      condition:
        $a
    }
  `);

  assertEquals(scanner.filterDiagnostics.length, 0);
  assertArrayLength(await scanner.scan('abc'), 0);
});

// ═════════════════════════════════════════════════════════════════════════
// Section 4: Compilation rules
// ═════════════════════════════════════════════════════════════════════════

const compileError = (text) => () => new InterceptScanner().compile(text);

await test('4.1 reject inside a filter rule is a compile error', () => {
  assertThrows(compileError(`
    filter rule nested {
      strings:
        $a = "x" reject(other)
      condition:
        $a
    }
  `));
});

await test('4.2 global filter rule is a compile error', () => {
  assertThrows(compileError(`
    global filter rule bad {
      condition:
        true
    }
  `));
});

await test('4.3 filter name colliding with a rule name is a compile error', () => {
  assertThrows(compileError(`
    filter rule DuplicateName {
      condition:
        true
    }
    rule DuplicateName {
      strings:
        $a = "a"
      condition:
        $a
    }
  `));
});

await test('4.4 pe and elf references inside a filter rule are compile errors', () => {
  assertThrows(compileError(`
    filter rule uses_pe {
      condition:
        pe.is_dll
    }
  `));
  assertThrows(compileError(`
    filter rule uses_elf {
      condition:
        elf.is_64bit
    }
  `));
});

await test('4.5 a filter condition referencing a rule is a compile error', () => {
  assertThrows(compileError(`
    rule Other {
      strings:
        $a = "a"
      condition:
        $a
    }
    filter rule uses_rule {
      condition:
        Other
    }
  `));
});

await test('4.5b rejectRECapture inside a filter rule is a compile error', () => {
  assertThrows(compileError(`
    filter rule nested {
      strings:
        $a = /x(y)/ rejectRECapture(other)
      condition:
        $a
    }
  `));
});

await test('4.5c unknown names in rejectRECapture are diagnosed', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = /ab(c)/ rejectRECapture(missing_capture_filter)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertTrue(
    results.diagnostics.some(
      (entry) => entry.code === 'unknown-filter-rule' && entry.filter === 'missing_capture_filter'
    )
  );
  assertArrayLength(results, 1, 'unknown names must not reject');
});

await test('4.6 private filter rule is accepted and private is ignored', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    private filter rule always {
      condition:
        true
    }
    rule R {
      strings:
        $a = "abc" reject(always)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('4.7 duplicate filter rules: last one wins with a diagnostic', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule winner {
      condition:
        true
    }
    filter rule winner {
      condition:
        false
    }
    rule R {
      strings:
        $a = "abc" reject(winner)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'duplicate-filter-rule'));
});

await test('4.8 filter names are case-sensitive', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule MyFilter {
      condition:
        true
    }
    rule R {
      strings:
        $a = "abc" reject(myfilter)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'unknown-filter-rule'));
});

await test('4.9 filters may be declared after the rules that reference them', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = "abc" reject(later_filter)
      condition:
        $a
    }
    filter rule later_filter {
      condition:
        true
    }
  `);

  assertEquals(
    scanner.filterDiagnostics.filter((entry) => entry.code === 'unknown-filter-rule').length,
    0
  );
  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('4.10 a filter compiled later applies to previously compiled rules', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = "abc" reject(later_filter)
      condition:
        $a
    }
  `);

  assertTrue(scanner.filterDiagnostics.some((entry) => entry.code === 'unknown-filter-rule'));

  scanner.compile(`
    filter rule later_filter {
      condition:
        true
    }
  `);

  assertEquals(scanner.filterDiagnostics.length, 0);
  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('4.11 a filter compiled later can still collide with an existing rule', () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule Collision {
      strings:
        $a = "a"
      condition:
        $a
    }
  `);

  assertThrows(() => scanner.compile(`
    filter rule Collision {
      condition:
        true
    }
  `));
});

await test('4.12 duplicates across compile calls: last one wins with a diagnostic', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule R {
      strings:
        $a = "abc" reject(always)
      condition:
        $a
    }
  `);

  scanner.compile(`
    filter rule always {
      condition:
        false
    }
  `);

  const results = await scanner.scan('abc');
  assertArrayLength(results, 1);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'duplicate-filter-rule'));
});

await test('4.13 filter meta and tags are parsed and exposed by scanFilterRules', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule tagged : alpha beta {
      meta:
        author = "test"
      condition:
        true
    }
  `);

  const results = await scanner.scanFilterRules('abc', {}, ['tagged']);
  assertArrayLength(results, 1);
  assertEquals(results[0].tags.join(','), 'alpha,beta');
  assertEquals(results[0].metadata.author, 'test');
});

await test('4.14 a filter rule with no strings is valid', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule R {
      strings:
        $a = "abc" reject(always)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('4.15 import statements are accepted around filter rules', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`import "math"
    filter rule always {
      condition:
        math.entropy(0, filesize) >= 0
    }
    rule R {
      strings:
        $a = "abc" reject(always)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

// ═════════════════════════════════════════════════════════════════════════
// Section 5: Registries, API, and diagnostics
// ═════════════════════════════════════════════════════════════════════════

await test('5.1 filter rules are excluded from the normal rule registry', () => {
  const text = `${ALWAYS}
    rule NormalRule {
      strings:
        $a = "abc"
      condition:
        $a
    }
  `;

  const normalRules = parseYaraRuleGroup(text);
  const { rules: filterRules } = parseInterceptFilterRuleGroup(text);

  assertArrayLength(normalRules, 1);
  assertEquals(normalRules[0].name, 'NormalRule');
  assertArrayLength(filterRules, 1);
  assertEquals(filterRules[0].id, 'filter:always');

  const scanner = new InterceptScanner();
  scanner.compile(text);
  assertEquals(scanner.getStats().totalRules, 1);
  assertEquals(scanner.getStats().totalFilterRules, 1);
});

await test('5.2 scanFilterRules returns scan-shaped results and skips unknown names', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule accepts_anything {
      condition:
        filesize > 0
    }
  `);

  const results = await scanner.scanFilterRules('abc', {}, ['accepts_anything', 'missing']);
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'accepts_anything');
  assertEquals(results[0].namespace, 'default');
  assertEquals(typeof results[0].strings, 'object');
  assertTrue(Array.isArray(results.diagnostics));
});

await test('5.3 scanFilterRules evaluates multiple rules and accepts string input', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}${NEVER}`);

  const results = await scanner.scanFilterRules('abc', {}, ['always', 'never']);
  assertArrayLength(results, 1);
  assertEquals(results[0].rule, 'always');
});

await test('5.4 scanFilterRules with no names or no compiled filters returns an empty array', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}`);

  assertArrayLength(await scanner.scanFilterRules('abc', {}, []), 0);

  const emptyScanner = new InterceptScanner();
  assertArrayLength(await emptyScanner.scanFilterRules('abc', {}, ['always']), 0);
});

await test('5.5 scanFilterRules does not disturb normal scanning', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}
    rule Normal {
      strings:
        $a = "hello"
      condition:
        $a
    }
    rule Filtered {
      strings:
        $b = "abc" reject(always)
      condition:
        $b
    }
  `);

  assertEquals((await scanner.scan('hello abc')).map((result) => result.rule).join(','), 'Normal');
  assertArrayLength(await scanner.scanFilterRules('abc', {}, ['always']), 1);
  assertEquals((await scanner.scan('hello abc')).map((result) => result.rule).join(','), 'Normal');
});

await test('5.6 scanFilterRules hides private and anonymous strings', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule with_strings {
      strings:
        $visible = "abc"
        $secret = "abc" private
        $ = "abc"
      condition:
        all of them
    }
  `);

  const results = await scanner.scanFilterRules('abc', {}, ['with_strings']);
  assertArrayLength(results, 1);
  assertEquals(results[0].strings.$visible?.matched, true, 'visible string should be reported');
  assertEquals(results[0].strings.$secret, undefined, 'private string should be hidden');
  assertEquals(results[0].strings['$.anon_0'], undefined, 'anonymous string should be hidden');
  assertEquals(results[0].strings['.anon_0'], undefined, 'raw anonymous key should be hidden');
});

await test('5.7 clearRules and clear both drop filter rules', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${ALWAYS}`);
  assertEquals(scanner.getStats().totalFilterRules, 1);

  scanner.clearRules();
  assertEquals(scanner.getStats().totalFilterRules, 0);
  assertArrayLength(await scanner.scanFilterRules('abc', {}, ['always']), 0);

  scanner.compile(`${ALWAYS}`);
  scanner.clear();
  assertEquals(scanner.getStats().totalFilterRules, 0);
});

await test('5.8 diagnostics are non-enumerable and survive empty scans', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = "abc" reject(missing_filter)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abc');
  assertEquals(Array.isArray(results.diagnostics), true);
  assertEquals(Object.prototype.propertyIsEnumerable.call(results, 'diagnostics'), false);
  assertTrue(results.diagnostics.some((entry) => entry.code === 'unknown-filter-rule'));

  const filterOnly = new InterceptScanner();
  filterOnly.compile(`${ALWAYS}`);
  const emptyResults = await filterOnly.scan('abc');
  assertArrayLength(emptyResults, 0);
  assertEquals(Array.isArray(emptyResults.diagnostics), true);
});

// ═════════════════════════════════════════════════════════════════════════
// Section 6: Module caching and laziness
// ═════════════════════════════════════════════════════════════════════════

await test('6.1 identical candidates share one filter verdict and one module init', async () => {
  class CountingModule extends BaseCustomModule {
    constructor() {
      super('counting');
      this.initializeLengths = [];
    }

    async initialize(data) {
      this.initializeLengths.push(data.length);
      return {};
    }

    createModule() {
      return {};
    }
  }

  const moduleInstance = new CountingModule();
  const scanner = new InterceptScanner({ modules: { counting: moduleInstance } });
  scanner.compile(`
    filter rule uses_counter {
      condition:
        counting.ok == true
    }
    rule R {
      strings:
        $a = "abc" reject(uses_counter)
      condition:
        $a
    }
  `);

  await scanner.scan('abc abc');

  // Main rule evaluation initializes modules once with the file (length 7). Filter evaluation runs
  // on candidates (length 3) and should initialize once thanks to the buffer-hash cache.
  assertEquals(moduleInstance.initializeLengths.filter((length) => length === 3).length, 1);
  assertEquals(moduleInstance.initializeLengths.filter((length) => length === 7).length, 1);
});

await test('5.9 capture stays out of the serialized result shape', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`${NEVER}
    rule R {
      strings:
        $a = /ab(cde)f/ rejectRECapture(never)
      condition:
        $a
    }
  `);

  const results = await scanner.scan('abcdef');
  assertArrayLength(results, 1);
  assertEquals(Object.keys(results[0].strings.$a.matches[0]).join(','), 'offset,length');
  assertEquals(JSON.stringify(results).includes('capture'), false);
  assertEquals(JSON.stringify(results).includes('cde'), false);
});

await test('6.2 filter verdicts do not leak across scans', async () => {
  class MarkerModule extends BaseCustomModule {
    constructor() {
      super('marker');
    }

    async initialize(data, metadata) {
      return { enabled: metadata.enabled === true };
    }

    createModule(interimResults) {
      return interimResults;
    }
  }

  const scanner = new InterceptScanner({ modules: { marker: new MarkerModule() } });
  scanner.compile(`
    filter rule enabled {
      condition:
        marker.enabled == true
    }
    rule R {
      strings:
        $a = "abc" reject(enabled)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc', { enabled: true }), 0);
  assertArrayLength(await scanner.scan('abc', { enabled: false }), 1);
});

await test('6.4 verdict cache separates capture buffers from full-match buffers', async () => {
  // Same filter name, same file. $full is rejected on its 6-byte match; $cap must be evaluated on
  // its 3-byte capture instead of reusing that verdict.
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule six_bytes {
      condition:
        filesize == 6
    }
    rule R {
      strings:
        $full = /ab(cde)f/ reject(six_bytes)
        $cap = /ab(cde)f/ rejectRECapture(six_bytes)
      condition:
        any of them
    }
  `);

  const results = await scanner.scan('abcdef');
  assertArrayLength(results, 1);
  assertEquals(results[0].strings.$cap?.matched, true);
});

await test('6.3 filters that reference no custom module do not initialize any', async () => {
  class CountingModule extends BaseCustomModule {
    constructor() {
      super('counting');
      this.calls = 0;
    }

    async initialize() {
      this.calls++;
      return {};
    }

    createModule() {
      return {};
    }
  }

  const moduleInstance = new CountingModule();
  const scanner = new InterceptScanner({ modules: { counting: moduleInstance } });
  scanner.compile(`
    filter rule plain {
      condition:
        true
    }
  `);

  await scanner.scanFilterRules('abcdef', {}, ['plain']);
  assertEquals(moduleInstance.calls, 0);
});

// ═════════════════════════════════════════════════════════════════════════
// Section 7: The $_ buffer placeholder
// ═════════════════════════════════════════════════════════════════════════

await test('7.1 $_ is the candidate buffer inside a filter', async () => {
  assertArrayLength(await scanCapture('string.length($_) == 3', '$a = "abc" reject(probe)', 'abc'), 0);
  assertArrayLength(await scanCapture('string.length($_) == 4', '$a = "abc" reject(probe)', 'abc'), 1);
});

await test('7.2 $_ is the capture inside a rejectRECapture filter', async () => {
  assertArrayLength(await scanCapture('string.length($_) == 3', '$a = /ab(cde)f/ rejectRECapture(probe)', 'abcdef'), 0);
  assertArrayLength(await scanCapture('string.length($_) == 6', '$a = /ab(cde)f/ rejectRECapture(probe)', 'abcdef'), 1);
});

await test('7.3 $_ reaches module functions as text', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule abc_hash {
      condition:
        hash.md5($_) == "900150983cd24fb0d6963f7d28e17f72"
    }
    rule R {
      strings:
        $a = "abc" reject(abc_hash)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0);
});

await test('7.4 $_ is the whole file in a normal rule condition', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = "abc"
      condition:
        $a and string.length($_) == 6
    }
  `);

  assertArrayLength(await scanner.scan('abcdef'), 1);
  assertArrayLength(await scanner.scan('abcdefg'), 0);
});

await test('7.5 a declared $_ keeps ordinary string semantics', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $_ = "abc"
      condition:
        $_
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 1);
  assertArrayLength(await scanner.scan('xyz'), 0);
});

await test('7.6 $_ never joins the of-them set', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    rule R {
      strings:
        $a = "zzz"
      condition:
        any of them and string.length($_) == 3
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 0, '$a never matches, so the rule must not match');
});

await test('7.7 #_ is 0 while @_ and !_ are undefined when $_ is undeclared', async () => {
  const countRule = new InterceptScanner();
  countRule.compile(`
    rule R {
      strings:
        $a = "abc"
      condition:
        $a and #_ == 0
    }
  `);
  assertArrayLength(await countRule.scan('abc'), 1, '#_ evaluates to 0 for an undeclared $_');

  const lengthRule = new InterceptScanner();
  lengthRule.compile(`
    rule R {
      strings:
        $a = "abc"
      condition:
        $a and !_ == 0
    }
  `);
  assertArrayLength(await lengthRule.scan('abc'), 0, '!_ is undefined, so the comparison is undefined');

  const offsetRule = new InterceptScanner();
  offsetRule.compile(`
    rule R {
      strings:
        $a = "abc"
      condition:
        $a and @_ == 0
    }
  `);
  assertArrayLength(await offsetRule.scan('abc'), 0, '@_ is undefined, so the comparison is undefined');
});

await test('7.8 a filter using !_ fails open when $_ is undeclared', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule needs_length {
      condition:
        !_ == 3
    }
    rule R {
      strings:
        $a = "abc" reject(needs_length)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abc'), 1, 'undefined must not reject the candidate');
});

printSummary();
