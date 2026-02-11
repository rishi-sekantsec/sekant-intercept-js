import { compileYaraRule } from '../src/yaraRuleCompiler.mjs';

// Example: A comprehensive YARA rule with extensive comments
const comprehensiveRule = `
/*
 * YARA Rule: Advanced Malware Detector
 * Author: Security Team
 * Purpose: Detect various malware patterns
 */

rule AdvancedMalwareDetector : malware ransomware { // Tags for categorization
  meta:
    // Basic metadata
    author = "Security Team"
    date = "2025-11-05"
    version = 2
    /* 
     * Detailed description
     * This rule detects multiple malware indicators
     */
    description = "Multi-pattern malware detection"
    severity = "high" // Critical alert
  
  strings:
    // PE header detection
    $pe_header = { 4D 5A 90 00 } // DOS MZ header
    
    /* Common malware strings */
    $malware1 = "ransom" nocase ascii // Ransomware indicator
    $malware2 = "encrypt" wide nocase // Wide string variant
    
    // Network indicators
    $url = /https?:\\/\\/evil[0-9]+\\.com/ // Malicious URL pattern
    
    /* 
     * String with comment-like content
     * Note: This should be preserved in the string itself
     */
    $tricky = "Code: /* not a comment */" ascii
    
    // XOR-encoded string detection
    $xor_string = "hidden" xor(1-255) // Detect with any XOR key
    
  condition:
    // Match condition with inline comments
    $pe_header at 0 and // File starts with PE header
    (
      /* Any malware string */
      any of ($malware*) or
      $url or // Or URL pattern
      $xor_string // Or XOR encoded
    )
    // and filesize < 10MB // Size constraint (commented out)
}
`;

console.log('=== Comprehensive YARA Rule Parser Test ===\n');

try {
  // Parse and compile the rule
  const compiled = compileYaraRule(comprehensiveRule);
  
  console.log('✓ Successfully compiled rule with extensive comments\n');
  console.log('Rule Details:');
  console.log('  Name:', compiled.name);
  console.log('  Tags:', compiled.tags.join(', '));
  console.log('\nMetadata:');
  for (const [key, value] of Object.entries(compiled.metadata)) {
    console.log(`  ${key}: ${value}`);
  }
  
  console.log('\nString Definitions:');
  for (const [varName, stringDef] of Object.entries(compiled.strings)) {
    console.log(`  $${varName}: ${stringDef.definition}`);
    console.log(`    -> Matcher: ${stringDef.matcher ? '✓ compiled' : '✗ failed'}`);
  }
  
  console.log('\nCondition:');
  console.log(`  ${compiled.condition}`);
  
  // Test matching
  console.log('\n=== Testing String Matching ===\n');
  
  const testData1 = new TextEncoder().encode('MZ\x90\x00This file contains RANSOM notes');
  const result1 = compiled.match(testData1);
  
  console.log('Test 1: PE header + "ransom" text');
  for (const [varName, matches] of Object.entries(result1.stringMatches)) {
    if (matches.length > 0) {
      console.log(`  ✓ $${varName}: ${matches.length} match(es) at offset(s) ${matches.map(m => m.offset).join(', ')}`);
    }
  }
  
  const testData2 = new TextEncoder().encode('Check this URL: http://evil123.com/payload');
  const result2 = compiled.match(testData2);
  
  console.log('\nTest 2: Malicious URL pattern');
  for (const [varName, matches] of Object.entries(result2.stringMatches)) {
    if (matches.length > 0) {
      console.log(`  ✓ $${varName}: ${matches.length} match(es) at offset(s) ${matches.map(m => m.offset).join(', ')}`);
    }
  }
  
  console.log('\n✓ All tests completed successfully!');
  
} catch (error) {
  console.error('✗ Error:', error.message);
  console.error(error.stack);
}
