/**
 * Test Suite: Global Rules
 * 
 * Tests the global rule modifier which causes a rule to be evaluated first.
 * If a global rule doesn't match, ALL other rules automatically fail to match,
 * regardless of whether their conditions would normally be satisfied.
 * 
 * Global rules act as a "gate" - they must pass for any scanning to succeed.
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { test, printSummary, printSection } from './testingFramework.mjs';

printSection('Global Rules Tests');

// ======================================================================
// Section 1: Basic Global Rule Behavior
// ======================================================================

await test('1.1 Global rule matches - other rules can match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule GlobalCheck {
      condition:
        true
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // Both GlobalCheck and TestRule should match (global rule is not private)
  if (results.length !== 2) {
    throw new Error(`Expected 2 results, got ${results.length}`);
  }
  
  const ruleNames = results.map(r => r.rule).sort();
  if (ruleNames[0] !== 'GlobalCheck' || ruleNames[1] !== 'TestRule') {
    throw new Error(`Expected ['GlobalCheck', 'TestRule'], got ${JSON.stringify(ruleNames)}`);
  }
});

await test('1.2 Global rule fails - other rules cannot match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule GlobalCheck {
      condition:
        false
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // TestRule should NOT match because GlobalCheck failed, even though "test" is in the data
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}: ${JSON.stringify(results)}`);
  }
});

await test('1.3 Global private rule matches - other rules can match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      condition:
        true
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // TestRule should match, GlobalCheck should not appear (it's private)
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'TestRule') {
    throw new Error(`Expected 'TestRule', got '${results[0].rule}'`);
  }
});

await test('1.4 Global private rule fails - other rules cannot match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      condition:
        false
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test data');
  
  // No rules should match because global rule failed
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}: ${JSON.stringify(results)}`);
  }
});

// ======================================================================
// Section 2: Global Rules with String Matching
// ======================================================================

await test('2.1 Global rule with string - matches, other rules can match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      strings:
        $g = "foo"
      condition:
        $g
    }
    
    rule TestRule {
      strings:
        $a = "bar"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('foobar');
  
  // Both strings match, so TestRule should match
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'TestRule') {
    throw new Error(`Expected 'TestRule', got '${results[0].rule}'`);
  }
});

await test('2.2 Global rule with string - fails, other rules cannot match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      strings:
        $g = "foo"
      condition:
        $g
    }
    
    rule TestRule {
      strings:
        $a = "bar"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('bar');
  
  // Even though "bar" is present, TestRule should NOT match because global rule failed
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}: ${JSON.stringify(results)}`);
  }
});

// ======================================================================
// Section 3: Multiple Global Rules
// ======================================================================

await test('3.1 Multiple global rules - all match, other rules can match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck1 {
      condition:
        true
    }
    
    global private rule GlobalCheck2 {
      strings:
        $g = "foo"
      condition:
        $g
    }
    
    rule TestRule {
      strings:
        $a = "bar"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('foobar');
  
  // All global rules match, so TestRule should match
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'TestRule') {
    throw new Error(`Expected 'TestRule', got '${results[0].rule}'`);
  }
});

await test('3.2 Multiple global rules - one fails, other rules cannot match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck1 {
      condition:
        true
    }
    
    global private rule GlobalCheck2 {
      strings:
        $g = "foo"
      condition:
        $g
    }
    
    rule TestRule {
      strings:
        $a = "bar"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('bar');
  
  // GlobalCheck2 fails, so no rules should match
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}: ${JSON.stringify(results)}`);
  }
});

// ======================================================================
// Section 4: Multiple Non-Global Rules with Global Rule
// ======================================================================

await test('4.1 Global passes - multiple rules can all match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      condition:
        true
    }
    
    rule Rule1 {
      strings:
        $a = "foo"
      condition:
        $a
    }
    
    rule Rule2 {
      strings:
        $b = "bar"
      condition:
        $b
    }
  `);
  
  const results = await scanner.scan('foobar');
  
  // Both rules should match
  if (results.length !== 2) {
    throw new Error(`Expected 2 results, got ${results.length}`);
  }
  
  const ruleNames = results.map(r => r.rule).sort();
  if (ruleNames[0] !== 'Rule1' || ruleNames[1] !== 'Rule2') {
    throw new Error(`Expected ['Rule1', 'Rule2'], got ${JSON.stringify(ruleNames)}`);
  }
});

await test('4.2 Global fails - no rules match even though conditions would pass', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      condition:
        false
    }
    
    rule Rule1 {
      strings:
        $a = "foo"
      condition:
        $a
    }
    
    rule Rule2 {
      strings:
        $b = "bar"
      condition:
        $b
    }
  `);
  
  const results = await scanner.scan('foobar');
  
  // No rules should match because global rule failed
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}: ${JSON.stringify(results)}`);
  }
});

// ======================================================================
// Section 5: Global Rules with Tags and Metadata
// ======================================================================

await test('5.1 Global rule with tags - matches', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule GlobalCheck : system required {
      condition:
        true
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test');
  
  // Both GlobalCheck and TestRule should match (global rule is not private)
  if (results.length !== 2) {
    throw new Error(`Expected 2 results, got ${results.length}`);
  }
  
  const ruleNames = results.map(r => r.rule).sort();
  if (ruleNames[0] !== 'GlobalCheck' || ruleNames[1] !== 'TestRule') {
    throw new Error(`Expected ['GlobalCheck', 'TestRule'], got ${JSON.stringify(ruleNames)}`);
  }
});

await test('5.2 Global rule with metadata - fails', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global private rule GlobalCheck {
      meta:
        description = "Global validation rule"
        required = true
      condition:
        false
    }
    
    rule TestRule {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test');
  
  // No rules should match
  if (results.length !== 0) {
    throw new Error(`Expected 0 results (global rule failed), got ${results.length}`);
  }
});

// ======================================================================
// Section 6: Edge Cases
// ======================================================================

await test('6.1 Only global rule - appears in results when matches', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule OnlyGlobal {
      strings:
        $a = "test"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('test');
  
  // Global rule should appear in results (it's not private)
  if (results.length !== 1) {
    throw new Error(`Expected 1 result, got ${results.length}`);
  }
  if (results[0].rule !== 'OnlyGlobal') {
    throw new Error(`Expected 'OnlyGlobal', got '${results[0].rule}'`);
  }
});

await test('6.2 Only global rule - no results when fails', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule OnlyGlobal {
      condition:
        false
    }
  `);
  
  const results = await scanner.scan('test');
  
  // No results when global rule fails
  if (results.length !== 0) {
    throw new Error(`Expected 0 results, got ${results.length}`);
  }
});

await test('6.3 Global and private global rules together', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    global rule PublicGlobal {
      condition:
        true
    }
    
    global private rule PrivateGlobal {
      strings:
        $g = "foo"
      condition:
        $g
    }
    
    rule TestRule {
      strings:
        $a = "bar"
      condition:
        $a
    }
  `);
  
  const results = await scanner.scan('foobar');
  
  // Both global rules pass, so TestRule should match
  // PublicGlobal should appear (it's not private), PrivateGlobal should not
  if (results.length !== 2) {
    throw new Error(`Expected 2 results, got ${results.length}`);
  }
  
  const ruleNames = results.map(r => r.rule).sort();
  if (ruleNames[0] !== 'PublicGlobal' || ruleNames[1] !== 'TestRule') {
    throw new Error(`Expected ['PublicGlobal', 'TestRule'], got ${JSON.stringify(ruleNames)}`);
  }
});

printSummary();
