import { parseYaraRule, compileYaraRule } from '../yaraRuleCompiler.mjs';

// Test YARA rule with various comment styles
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

console.log('Testing YARA rule parser with comments...\n');

try {
  const parsed = parseYaraRule(testRule);
  console.log('✓ Successfully parsed rule with comments\n');
  
  console.log('Rule name:', parsed.name);
  console.log('Tags:', parsed.tags);
  console.log('Metadata:', parsed.metadata);
  console.log('Strings:', Object.keys(parsed.strings));
  console.log('Condition:', parsed.condition);
  
  console.log('\n--- Compiled Rule Test ---\n');
  const compiled = compileYaraRule(testRule);
  console.log('Compiled rule name:', compiled.name);
  console.log('Number of string matchers:', Object.keys(compiled.strings).length);
  
  // Test matching
  const testData = new TextEncoder().encode('This contains malware and other stuff');
  const result = compiled.match(testData);
  console.log('\nMatch result for test data:');
  console.log('String matches:', Object.entries(result.stringMatches).map(([k, v]) => `${k}: ${v.length} matches`));
  
} catch (error) {
  console.error('✗ Error:', error.message);
}
