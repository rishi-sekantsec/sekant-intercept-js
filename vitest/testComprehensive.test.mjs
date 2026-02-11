import { describe, test, expect } from 'vitest';
import { InterceptScanner } from '../src/interceptScanner.mjs';

describe('Comprehensive Rule Test', () => {
  const ruleSource = `
    rule DetectMalware {
      meta:
        description = "Detects malicious patterns"
        severity = "High"
      strings:
        $text_string = "malicious_payload" nocase
        $hex_pattern = { 4D 5A 90 }
      condition:
        $text_string or $hex_pattern
    }
  `;

  test('should match text pattern', async () => {
    const scanner = new InterceptScanner();
    await scanner.compile(ruleSource);
    
    // Ensure the rules are actually compiled before matching
    expect(scanner.compiledRules.length).toBeGreaterThan(0);

    const data = new TextEncoder().encode('This file contains MALICIOUS_PAYLOAD inside it.');
    const results = await scanner.scan(data);
    
    expect(results).toHaveLength(1);
    expect(results[0].rule).toBe('DetectMalware');
    
    // Check match details - structure depends on InterceptScanner details
    // Based on src/interceptScanner.mjs comments:
    // results[0].strings["$text_string"].matched should be true
    expect(results[0].strings['$text_string'].matched).toBe(true);
  });

  test('should match hex pattern', async () => {
    const scanner = new InterceptScanner();
    await scanner.compile(ruleSource);

    const data = new Uint8Array([0x00, 0x4D, 0x5A, 0x90, 0x00]);
    const results = await scanner.scan(data);
    
    expect(results).toHaveLength(1);
    expect(results[0].rule).toBe('DetectMalware');
    expect(results[0].strings['$hex_pattern'].matched).toBe(true);
  });

  test('should not match innocent data', async () => {
    const scanner = new InterceptScanner();
    await scanner.compile(ruleSource);

    const data = new TextEncoder().encode('This is a safe file.');
    const results = await scanner.scan(data);
    
    expect(results).toHaveLength(0);
  });
});
