/**
 * Capture-group offset output (`includeCaptures`).
 *
 * Offsets are an Intercept extension: libyara's YR_MATCH carries no capture information, so the
 * default output is unchanged. `includeCaptures` is the only switch — the `d` flag it needs is an
 * implementation detail and never appears in rule text.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, assertEquals, assertTrue, assertArrayLength, printSummary } from './testingFramework.mjs';

console.log('═══════════════════════════════════════════════════════════════');
console.log('  CAPTURE GROUP OFFSET TESTS');
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

await test('1. capture offsets are absent by default', async () => {
  const matches = await matchesFor('/id=([a-z]+)/', 'id=abc', {});
  assertEquals(matches[0].captures, undefined);
  assertEquals(JSON.stringify(matches).includes('captures'), false);
});

await test('2. includeCaptures emits every group with absolute byte offsets', async () => {
  const matches = await matchesFor('/id=([a-z]+)([0-9]+)/', 'id=abc123;', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 2);
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].offset, 3);
  assertEquals(matches[0].captures[0].length, 3);
  assertEquals(matches[0].captures[1].index, 2);
  assertEquals(matches[0].captures[1].offset, 6);
  assertEquals(matches[0].captures[1].length, 3);
  assertTrue(JSON.stringify(matches).includes('captures'), 'captures should be enumerable when opted in');
});

await test('3. offsets address the scanned buffer directly', async () => {
  const data = 'prefix id=abc123; suffix';
  const matches = await matchesFor('/id=([a-z]+)([0-9]+)/', data, { includeCaptures: true });
  const [user, digits] = matches[0].captures;
  assertEquals(data.slice(user.offset, user.offset + user.length), 'abc');
  assertEquals(data.slice(digits.offset, digits.offset + digits.length), '123');
});

await test('4. named groups carry their name on the numbered entry', async () => {
  const matches = await matchesFor('/id=(?<user>[a-z]+)/', 'prefix id=abc', { includeCaptures: true });
  assertEquals(matches[0].captures[0].index, 1);
  assertEquals(matches[0].captures[0].name, 'user');
  assertEquals(matches[0].captures[0].offset, 10);
  assertEquals(matches[0].captures[0].length, 3);
});

await test('5. non-capturing groups and lookarounds are not numbered', async () => {
  const matches = await matchesFor('/(?:id)=(?<user>[a-z]+)(?=;)/', 'id=abc;', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 1);
  assertEquals(matches[0].captures[0].name, 'user');
});

await test('6. a non-participating group reports null offset and length', async () => {
  const matches = await matchesFor('/(zzz)|(abc)/', 'abc', { includeCaptures: true });
  assertEquals(matches[0].captures[0].offset, null);
  assertEquals(matches[0].captures[0].length, null);
  assertEquals(matches[0].captures[1].offset, 0);
  assertEquals(matches[0].captures[1].length, 3);
});

await test('7. an empty participating group reports a zero length', async () => {
  const matches = await matchesFor('/a(b*)c/', 'ac', { includeCaptures: true });
  assertEquals(matches[0].captures[0].offset, 1);
  assertEquals(matches[0].captures[0].length, 0);
});

await test('8. a pattern with no groups yields an empty list', async () => {
  const matches = await matchesFor('/abc/', 'abc', { includeCaptures: true });
  assertArrayLength(matches[0].captures, 0);
});

await test('9. a lookahead capture may extend past a zero-length match', async () => {
  const matches = await matchesFor('/(?=(abc))/', 'abc', { includeCaptures: true });
  assertEquals(matches[0].length, 0);
  assertEquals(matches[0].captures[0].offset, 0);
  assertEquals(matches[0].captures[0].length, 3);
});

await test('10. multibyte captures report UTF-8 byte offsets', async () => {
  const matches = await matchesFor('/(é)/', 'é', { includeCaptures: true });
  assertEquals(matches[0].length, 2);
  assertEquals(matches[0].captures[0].offset, 0);
  assertEquals(matches[0].captures[0].length, 2);
});

await test('11. captures are produced on the full-scan path too', async () => {
  const matches = await matchesFor('/(.+)b/', 'aab', { includeCaptures: true });
  assertEquals(matches[0].offset, 0);
  assertEquals(matches[0].captures[0].offset, 0);
  assertEquals(matches[0].captures[0].length, 2);
});

await test('12. text and hex strings have no captures', async () => {
  assertEquals((await matchesFor('"abc"', 'abc', { includeCaptures: true }))[0].captures, undefined);
  assertEquals(
    (await matchesFor('{ 61 62 63 }', new Uint8Array([0x61, 0x62, 0x63]), { includeCaptures: true }))[0].captures,
    undefined
  );
});

await test('13. a user-written d flag is ignored', async () => {
  const matches = await matchesFor('/abc/d', 'abc', {});
  assertEquals(matches[0].captures, undefined);
  assertEquals(matches[0].length, 3);
});

await test('14. rejectRECapture still works without including captures', async () => {
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

await test('15. capture output also applies to filter rules via scanFilterRules', async () => {
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
  assertEquals(capture.offset, 3);
  assertEquals(capture.length, 3);
});

printSummary();
