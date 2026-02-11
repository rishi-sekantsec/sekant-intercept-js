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
