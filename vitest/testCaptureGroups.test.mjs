/**
 * Capture-group output (`includeCaptures`).
 *
 * Intercept exposes the first capture group on regex matches — the same group `rejectRECapture(...)`
 * hands to filter rules — as `{ index, name?, value, offset, length }`. Only group 1 is reported, so
 * the other groups' substrings become collectable as soon as the match iteration ends. Positions
 * come from the `d` (hasIndices) flag, which is added internally and never appears in rule text.
 *
 * Off by default: YARA's match record carries no capture data, so default output stays YARA-shaped.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, assertEquals, assertTrue, assertArrayLength, printSummary } from './testingFramework.mjs';

console.log('═══════════════════════════════════════════════════════════════');
console.log('  CAPTURE GROUP TESTS');
console.log('═══════════════════════════════════════════════════════════════\n');

const matchesFor = async (definition, data, options = {}) => {
  const scanner = new InterceptScanner(options);
  scanner.compile(`
    rule R {
      strings:
        $a = ${definition}
      condition:
        $a
    }
  `);
  const results = await scanner.scan(data);
  return results[0]?.strings.$a?.matches ?? [];
};

await test('1. capture output is absent by default', async () => {
  const matches = await matchesFor('/id=([a-z]+)/', 'id=abc', {});
  assertEquals(matches[0].captures, undefined);
  assertEquals(JSON.stringify(matches).includes('captures'), false);
});

await test('2. includeCaptures emits group 1 with value and position', async () => {
  const matches = await matchesFor('/id=([a-z]+)/', 'id=abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].value, 'abc');
  assertEquals(matches[0].captures[0].offset, 3);
  assertEquals(matches[0].captures[0].length, 3);
  assertTrue(JSON.stringify(matches).includes('captures'), 'captures should be enumerable when opted in');
});

await test('3. only group 1 is reported, later groups are dropped', async () => {
  const matches = await matchesFor('/id=([a-z]+)([0-9]+)/', 'id=abc123', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].value, 'abc');
});

await test('4. capture offsets address the scanned buffer directly', async () => {
  const data = 'prefix id=abc; suffix';
  const matches = await matchesFor('/id=([a-z]+)/', data, { includeCaptures: true });
  const capture = matches[0].captures[0];
  assertEquals(Object.keys(capture).join(','), 'index,value,offset,length');
  assertEquals(data.slice(capture.offset, capture.offset + capture.length), 'abc');
});

await test('5. named groups keep their name on the numbered entry', async () => {
  const matches = await matchesFor('/id=(?<user>[a-z]+)/', 'id=abc', { includeCaptures: true });
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].name, 'user');
  assertEquals(matches[0].captures[0].value, 'abc');
  assertEquals(matches[0].captures[0].offset, 3);
});

await test('6. a named group still counts as group 1 behind a non-capturing group', async () => {
  const matches = await matchesFor('/(?:id)=(?<user>[a-z]+)(?=;)/', 'id=abc;', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].name, 'user');
  assertEquals(matches[0].captures[0].value, 'abc');
});

await test('7. a non-participating group reports a null value', async () => {
  const matches = await matchesFor('/(zzz)|(abc)/', 'abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].value, null);
  assertEquals(matches[0].captures[0].offset, null);
  assertEquals(matches[0].captures[0].length, null);
});

await test('8. an empty participating group reports an empty string', async () => {
  const matches = await matchesFor('/a(b*)c/', 'ac', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].value, '');
  assertEquals(matches[0].captures[0].offset, 1);
  assertEquals(matches[0].captures[0].length, 0);
});

await test('9. a pattern with no groups yields an empty list', async () => {
  const matches = await matchesFor('/abc/', 'abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 0);
});

await test('10. a lookahead capture is reported even when the match is zero-length', async () => {
  const matches = await matchesFor('/(?=(abc))/', 'abc', { includeCaptures: true });
  assertEquals(matches[0].length, 0);
  assertEquals(matches[0].captures[0].value, 'abc');
  assertEquals(matches[0].captures[0].offset, 0);
  assertEquals(matches[0].captures[0].length, 3);
});

await test('11. multibyte captures report UTF-8 byte offsets', async () => {
  const matches = await matchesFor('/x(é)/', 'xé', { includeCaptures: true });
  assertEquals(matches[0].captures[0].value, 'é');
  assertEquals(matches[0].captures[0].offset, 1);
  assertEquals(matches[0].captures[0].length, 2);
});

await test('12. captures are produced on the full-scan path too', async () => {
  const matches = await matchesFor('/(.+)b/', 'aab', { includeCaptures: true });
  assertEquals(matches[0].captures[0].value, 'aa');
});

await test('13. text and hex strings have no captures', async () => {
  assertEquals((await matchesFor('"abc"', 'abc', { includeCaptures: true }))[0].captures, undefined);
  assertEquals(
    (await matchesFor('{ 61 62 63 }', new Uint8Array([0x61, 0x62, 0x63]), { includeCaptures: true }))[0].captures,
    undefined
  );
});

await test('14. a user-written d flag is ignored; the option alone controls it', async () => {
  const off = await matchesFor('/id=([a-z]+)/d', 'id=abc', {});
  assertEquals(off[0].captures, undefined, 'plain d in the rule must not enable capture output');

  const on = await matchesFor('/id=([a-z]+)/d', 'id=abc', { includeCaptures: true });
  assertEquals(on[0].captures[0].offset, 3, 'the option still works when d is present in the rule');
});

await test('15. rejectRECapture still works without including captures', async () => {
  const scanner = new InterceptScanner();
  scanner.compile(`
    filter rule three {
      condition:
        filesize == 3
    }
    rule R {
      strings:
        $a = /ab(cde)f/ rejectRECapture(three)
      condition:
        $a
    }
  `);

  assertArrayLength(await scanner.scan('abcdef'), 0);
});

await test('15b. a lookbehind capture may lie before the match', async () => {
  const matches = await matchesFor('/(?<=(ab))c/', 'abc', { includeCaptures: true });
  assertEquals(matches[0].offset, 2);
  assertEquals(matches[0].captures[0].value, 'ab');
  assertEquals(matches[0].captures[0].offset, 0);
  assertEquals(matches[0].captures[0].length, 2);
});

await test('16. capture output also applies to filter rules via scanFilterRules', async () => {
  const scanner = new InterceptScanner({ includeCaptures: true });
  scanner.compile(`
    filter rule probe {
      strings:
        $u = /id=([a-z]+)/
      condition:
        $u
    }
  `);

  const results = await scanner.scanFilterRules('id=abc', {}, ['probe']);
  assertArrayLength(results, 1);
  const capture = results[0].strings.$u.matches[0].captures[0];
  assertEquals(capture.value, 'abc');
  assertEquals(capture.offset, 3);
  assertEquals(capture.length, 3);
});

printSummary();
