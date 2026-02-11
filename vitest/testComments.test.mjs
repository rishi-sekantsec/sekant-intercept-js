
/*
 * Test YARA rule with various comment styles
 */
import { describe, test, expect } from 'vitest';
import { parseYaraRule, compileYaraRule } from '../src/yaraRuleCompiler.mjs';

describe('YARA Comments Parsing', () => {
  const testRule = `
/* 
 * Multi-line comment at the start
 * This should be ignored
 */
rule TestRule : malware trojan { // inline comment after rule declaration
  meta:
    author = "Test Author" // inline comment after metadata
    /* multi-line comment in metadata
       section */
    description = "A test rule with comments"
    version = 1 // version number
  
  strings:
    // Single line comment before string definition
    $text1 = "malware" ascii // This is a malicious string
    /* Another multi-line
       comment between strings */
    $text2 = "virus" wide nocase
    $hex1 = { 4D 5A 90 00 } // PE header
    $regex1 = /evil[0-9]+/ // regex pattern
  
  condition:
    // Condition comment
    any of them /* inline multi-line comment */ and filesize < 1MB
}
`;

  test('should parse rule with extensive comments', () => {
    const parsed = parseYaraRule(testRule);
    
    expect(parsed.name).toBe('TestRule');
    expect(parsed.tags).toEqual(['malware', 'trojan']);
    expect(parsed.metadata).toHaveProperty('author', 'Test Author');
    expect(parsed.metadata).toHaveProperty('description', 'A test rule with comments');
    expect(parsed.metadata).toHaveProperty('version', 1);
    
    expect(Object.keys(parsed.strings)).toContain('$text1');
    expect(Object.keys(parsed.strings)).toContain('$text2');
    expect(Object.keys(parsed.strings)).toContain('$hex1');
    expect(Object.keys(parsed.strings)).toContain('$regex1');
  });

  test('should compile rule with comments', () => {
    const compiled = compileYaraRule(testRule);
    expect(compiled.name).toBe('TestRule');
    expect(Object.keys(compiled.strings)).toHaveLength(4);
  });
});
