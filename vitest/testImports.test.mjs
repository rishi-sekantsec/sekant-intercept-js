import { describe, test, expect } from 'vitest';
import { InterceptScanner } from '../src/interceptScanner.mjs';

describe('YARA Imports', () => {
  test('should parse complex valid imports', async () => {
    const ruleSource = `
      import "pe"
      import "elf"
      import "math"
      
      rule ImportTest {
        condition:
          math.abs(-1) == 1
      }
    `;
    
    const scanner = new InterceptScanner();
    // This should not throw
    await scanner.compile(ruleSource);
    
    // Check if the rule was compiled
    expect(scanner.compiledRules).toHaveLength(1);
    expect(scanner.compiledRules[0].name).toBe('ImportTest');
  });

  test('should handle standard rule without imports', async () => {
     const ruleSource = `
      rule NoImport {
        condition:
          filesize > 0
      }
    `;
    const scanner = new InterceptScanner();
    await scanner.compile(ruleSource);
    expect(scanner.compiledRules).toHaveLength(1);
  });
});
