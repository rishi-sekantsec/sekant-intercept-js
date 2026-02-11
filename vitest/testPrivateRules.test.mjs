/**
 * Test Suite: Private Rules
 * 
 * Tests the private rule modifier which prevents rules from being included
 * in scan results. Private rules can still be used in other rule conditions
 * but won't appear in the final output.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, printSummary, printSection } from './testingFramework.mjs';

printSection('Private Rules Tests');

// ======================================================================
// Section 1: Basic Private Rule Tests
// ======================================================================

await test('1.1 Private rule matches but not in output', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // Rule should match but not appear in results
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('1.2 Regular rule appears in output', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    rule PublicRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'PublicRule') {
    throw new Error(`Expected rule 'PublicRule', got '${results[0].rule}'`);
  }
});

await test('1.3 Mix of private and public rules', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateRule {
      strings:
        $a = "test"
      condition:
        $a
    }
    
    rule PublicRule {
      strings:
        $b = "data"
      condition:
        $b
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // Only public rule should appear
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'PublicRule') {
    throw new Error(`Expected rule 'PublicRule', got '${results[0].rule}'`);
  }
});

// ======================================================================
// Section 2: Private Rules with Tags
// ======================================================================

await test('2.1 Private rule with tags', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateTaggedRule : tag1 tag2 {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('2.2 Mix of private and public tagged rules', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateTagged : malware {
      strings:
        $a = "evil"
      condition:
        $a
    }
    
    rule PublicTagged : malware detection {
      strings:
        $b = "evil"
      condition:
        $b
    }
  `);
  
  const results = await scanner.scan('evil code');
  
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'PublicTagged') {
    throw new Error(`Expected 'PublicTagged'`);
  }
  if (results[0].tags.length !== 2 || !results[0].tags.includes('malware')) {
    throw new Error('Expected tags [malware, detection]');
  }
});

// ======================================================================
// Section 3: Private Rules with Metadata
// ======================================================================

await test('3.1 Private rule with metadata', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateWithMeta {
      meta:
        author = "test"
        version = 1
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

// ======================================================================
// Section 4: Private Rules with Complex Conditions
// ======================================================================

await test('4.1 Private rule with multiple strings', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateMultiString {
      strings:
        $a = "test"
        $b = "data"
        $c = "more"
      condition:
        all of them
    }
  `);
  
  const results = await scanner.scan('test data more');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('4.2 Private rule with hex patterns', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateHex {
      strings:
        $hex = { 4D 5A }
      condition:
        $hex
    }
  `);
  
  const results = await scanner.scan(new Uint8Array([0x4D, 0x5A, 0x90, 0x00]));
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('4.3 Private rule with regex', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateRegex {
      strings:
        $re = /test[0-9]+/
      condition:
        $re
    }
  `);
  
  const results = await scanner.scan('test123 data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

// ======================================================================
// Section 5: Multiple Private Rules
// ======================================================================

await test('5.1 Multiple private rules, none in output', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule Private1 {
      strings:
        $a = "test"
      condition:
        $a
    }
    
    private rule Private2 {
      strings:
        $b = "data"
      condition:
        $b
    }
    
    private rule Private3 {
      strings:
        $c = "more"
      condition:
        $c
    }
  `);
  
  const results = await scanner.scan('test data more');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (all private), got ${results.length}`);
  }
});

await test('5.2 Mix of multiple private and public rules', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule Private1 {
      strings:
        $a = "test"
      condition:
        $a
    }
    
    rule Public1 {
      strings:
        $b = "data"
      condition:
        $b
    }
    
    private rule Private2 {
      strings:
        $c = "more"
      condition:
        $c
    }
    
    rule Public2 {
      strings:
        $d = "test"
      condition:
        $d
    }
  `);
  
  const results = await scanner.scan('test data more');
  
  if (results.length !== 2) {
    throw new Error(`Expected 2 public results, got ${results.length}`);
  }
  
  const ruleNames = results.map(r => r.rule).sort();
  if (ruleNames[0] !== 'Public1' || ruleNames[1] !== 'Public2') {
    throw new Error(`Expected [Public1, Public2], got [${ruleNames.join(', ')}]`);
  }
});

// ======================================================================
// Section 6: Private Rules with Modules
// ======================================================================

await test('6.1 Private rule with filesize check', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateFilesize {
      strings:
        $a = "test"
      condition:
        $a and filesize < 100
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('6.2 Private rule with hash module', async () => {
  const scanner = new InterceptScanner();
  const { createHashModule } = await import('../src/hashModule.mjs');
  
  const data = new TextEncoder().encode('test data');
  const hashModule = createHashModule(data);
  scanner.setModules({ hash: hashModule });
  
  scanner.addRules(`
    private rule PrivateHash {
      strings:
        $a = "test"
      condition:
        $a and hash.md5(0, filesize) == "eb733a00c0c9d336e65691a37ab54293"
    }
  `);
  
  const results = await scanner.scan(data);
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

// ======================================================================
// Section 7: Edge Cases
// ======================================================================

await test('7.1 Private rule that does not match', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateNoMatch {
      strings:
        $a = "nonexistent"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('7.2 Only private rules in file, all matching', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule Private1 {
      strings:
        $a = "test"
      condition:
        $a
    }
    
    private rule Private2 {
      strings:
        $b = "data"
      condition:
        $b
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (all private), got ${results.length}`);
  }
});

await test('7.3 Private rule with anonymous strings', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule PrivateAnonymous {
      strings:
        $ = "test"
        $ = "data"
      condition:
        any of them
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('7.4 Private keyword case sensitivity', async () => {
  const scanner = new InterceptScanner();
  scanner.addRules(`
    private rule LowerCase {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

// ======================================================================
// Test Summary
// ======================================================================

printSummary();
