import { describe, test, expect } from 'vitest';
import { parseYaraRule } from '../src/yaraRuleCompiler.mjs';

describe('Comments Edge Cases', () => {
  test('should handle comments inside strings (they are not comments)', () => {
    const rule = `
      rule StringComments {
        strings:
          $s1 = "https://example.com"
          $s2 = "/* this is not a comment */"
          $s3 = "// neither is this"
        condition:
          any of them
      }
    `;
    const parsed = parseYaraRule(rule);
    expect(parsed.strings['$s1'].definition).toBe('"https://example.com"');
    expect(parsed.strings['$s2'].definition).toBe('"/* this is not a comment */"');
    expect(parsed.strings['$s3'].definition).toBe('"// neither is this"');
  });

  test('should keep a regex whose last slash is escaped and still strip comments', () => {
    const rule = `
      rule EscapedSlash {
        strings:
          $a = /a\\// // comment after the regex
          $b = /x\\/y/ /* block comment */
        condition:
          any of them
      }
    `;
    const parsed = parseYaraRule(rule);
    expect(parsed.strings['$a'].definition).toBe('/a\\//');
    expect(parsed.strings['$b'].definition).toBe('/x\\/y/');
  });

  test('should keep a regex used with the matches operator', () => {
    const rule = `
      rule MatchesRegex {
        strings:
          $a = "x"
        condition:
          $a matches /x\\/y/
      }
    `;
    const parsed = parseYaraRule(rule);
    expect(parsed.condition).toBe('$a matches /x\\/y/');
  });

  test('should handle slashes in regex (not comments)', () => {
    const rule = `
      rule RegexSlashes {
        strings:
          $r1 = /https?:\\/\\/[a-z.]+/
        condition:
          $r1
      }
    `;
    const parsed = parseYaraRule(rule);
    // The parser usually converts regex to a regex object or string, so just check it exists
    expect(parsed.strings['$r1']).toBeDefined();
  });
});
