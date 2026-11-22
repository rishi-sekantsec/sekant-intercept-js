/**
 * Capture-group output (`includeCaptures`).
 *
 * Intercept exposes the first capture group's value on regex matches — the same group
 * `rejectRECapture(...)` hands to filter rules. Only group 1 is kept, so the other groups' strings
 * become collectable as soon as the match iteration ends, and no `d` (hasIndices) flag is needed.
 *
 * Off by default: YARA's match record carries no capture data, so default output stays YARA-shaped.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, assertEquals, assertTrue, assertArrayLength, printSummary } from './testingFramework.mjs';

console.log('═══════════════════════════════════════════════════════════════');
console.log('  CAPTURE GROUP VALUE TESTS');
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

await test('2. includeCaptures emits group 1 as a value', async () => {
  const matches = await matchesFor('/id=([a-z]+)/', 'id=abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].value, 'abc');
  assertTrue(JSON.stringify(matches).includes('captures'), 'captures should be enumerable when opted in');
});

await test('3. only group 1 is reported, later groups are dropped', async () => {
  const matches = await matchesFor('/id=([a-z]+)([0-9]+)/', 'id=abc123', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].value, 'abc');
});

await test('4. capture entries carry no position information', async () => {
  const matches = await matchesFor('/id=([a-z]+)/', 'prefix id=abc', { includeCaptures: true });
  const capture = matches[0].captures[0];
  assertEquals(Object.keys(capture).join(','), 'index,value');
  assertEquals(capture.offset, undefined);
  assertEquals(capture.length, undefined);
});

await test('5. named groups keep their name on the numbered entry', async () => {
  const matches = await matchesFor('/id=(?<user>[a-z]+)/', 'id=abc', { includeCaptures: true });
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].name, 'user');
  assertEquals(matches[0].captures[0].value, 'abc');
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
});

await test('8. an empty participating group reports an empty string', async () => {
  const matches = await matchesFor('/a(b*)c/', 'ac', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].value, '');
});

await test('9. a pattern with no groups yields an empty list', async () => {
  const matches = await matchesFor('/abc/', 'abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 0);
});

await test('10. a lookahead capture is reported even when the match is zero-length', async () => {
  const matches = await matchesFor('/(?=(abc))/', 'abc', { includeCaptures: true });
  assertEquals(matches[0].length, 0);
  assertEquals(matches[0].captures[0].value, 'abc');
});

await test('11. multibyte captures are reported intact', async () => {
  const matches = await matchesFor('/(é)/', 'é', { includeCaptures: true });
  assertEquals(matches[0].captures[0].value, 'é');
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

await test('14. a user-written d flag is ignored and no d flag is needed', async () => {
  const matches = await matchesFor('/abc/d', 'abc', { includeCaptures: true });
  assertEquals(matches[0].length, 3);
  assertArrayLength(matches[0].captures, 0, 'no groups, so an empty list — and no crash from the d flag');
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
  assertEquals(results[0].strings.$u.matches[0].captures[0].value, 'abc');
});

printSummary();
