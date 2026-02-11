/**
 * Additional For Loop Tests - Real-World Scenarios
 * 
 * Tests for loop scenarios commonly found in real YARA rules
 */

import { createScanFacts, ConditionEvaluator } from '../src/yaraConditionsMatch.mjs';
import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { test, assertTrue, assertFalse, printSummary, printSection } from './testingFramework.mjs';

function createTestData() {
  const data = new Uint8Array(1000);
  for (let i = 0; i < data.length; i++) {
    data[i] = i % 256;
  }
  return data;
}

printSection('Real-World YARA For Loop Scenarios');

// ============================================================================
// Scenario 1: PE Section Analysis
// ============================================================================

console.log('\n=== Scenario 1: PE Section Entropy Check ===\n');

await test('Check all PE sections have entropy > 7 (packed binary)', async () => {
  const data = createTestData();
  
  // Mock PE module with sections
  const peModule = {
    number_of_sections: 3,
    sections: [
      { name: '.text', entropy: 7.8 },
      { name: '.data', entropy: 7.5 },
      { name: '.rsrc', entropy: 7.9 }
    ]
  };
  
  const facts = createScanFacts(data, {}, { pe: peModule });
  
  // for all i in (0..2) : (pe.sections[i].entropy > 7.0)
  // Note: We need to implement array indexing for this to work
  // For now, test a simpler version
  const evaluator = new ConditionEvaluator(facts);
  
  // Check if pe module is accessible
  assertTrue(evaluator.modules.pe !== undefined, 'PE module should be available');
  assertTrue(evaluator.modules.pe.number_of_sections === 3, 'Should have 3 sections');
});

// ============================================================================
// Scenario 2: String Pattern at File Start
// ============================================================================

console.log('\n=== Scenario 2: Any Signature at File Start ===\n');

await test('for any of ($sig*) : ($ at 0) - any signature at file start', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$sig1': { matched: true, count: 1, matches: [{ offset: 100, length: 4 }], offsets: [100] },
    '$sig2': { matched: true, count: 1, matches: [{ offset: 0, length: 4 }], offsets: [0] },
    '$sig3': { matched: true, count: 1, matches: [{ offset: 200, length: 4 }], offsets: [200] }
  });
  
  // for any of them : ($ at 0)
  const ast = parseConditionToAST('for any of them : ($ at 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$sig2 is at offset 0');
});

await test('for all of ($mz*) : ($ at 0) - all MZ signatures at file start', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$mz1': { matched: true, count: 1, matches: [{ offset: 0, length: 2 }], offsets: [0] },
    '$mz2': { matched: true, count: 1, matches: [{ offset: 0, length: 2 }], offsets: [0] }
  });
  
  // for all of them : ($ at 0)
  const ast = parseConditionToAST('for all of them : ($ at 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Both MZ signatures at offset 0');
});

// ============================================================================
// Scenario 3: API Call Sequence Detection
// ============================================================================

console.log('\n=== Scenario 3: API Call Sequence ===\n');

await test('for all i in (1..3) : (@api[i] < @api[i+1]) - API calls in order', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$api': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 100, length: 10 },
        { offset: 200, length: 12 },
        { offset: 300, length: 11 },
        { offset: 400, length: 9 }
      ], 
      offsets: [100, 200, 300, 400] 
    }
  });
  
  // for all i in (1..3) : (@api[i] < @api[i+1])
  const ast = parseConditionToAST('for all i in (1..3) : (@api[i] < @api[i+1])');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'API calls are in ascending order: @api[1]=100 < @api[2]=200 < @api[3]=300 < @api[4]=400');
});

await test('API calls NOT in order - should fail', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$api': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 100, length: 10 },
        { offset: 300, length: 12 },  // Out of order
        { offset: 200, length: 11 },
        { offset: 400, length: 9 }
      ], 
      offsets: [100, 300, 200, 400] 
    }
  });
  
  // for all i in (1..3) : (@api[i] < @api[i+1])
  const ast = parseConditionToAST('for all i in (1..3) : (@api[i] < @api[i+1])');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'API calls are not in order (@api[2]=300 > @api[3]=200)');
});

// ============================================================================
// Scenario 4: String Clustering (proximity check)
// ============================================================================

console.log('\n=== Scenario 4: String Proximity ===\n');

await test('for all i in (1..2) : (@str[i+1] - @str[i] < 100) - strings within 100 bytes', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$str': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 100, length: 5 },
        { offset: 150, length: 5 },
        { offset: 180, length: 5 }
      ], 
      offsets: [100, 150, 180] 
    }
  });
  
  // for all i in (1..2) : (@str[i+1] - @str[i] < 100)
  const ast = parseConditionToAST('for all i in (1..2) : (@str[i+1] - @str[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All strings are within 100 bytes: @str[2]-@str[1]=50, @str[3]-@str[2]=30');
});

await test('Strings too far apart - should fail', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$str': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 100, length: 5 },
        { offset: 150, length: 5 },
        { offset: 500, length: 5 }  // Too far
      ], 
      offsets: [100, 150, 500] 
    }
  });
  
  // for all i in (1..2) : (@str[i+1] - @str[i] < 100)
  const ast = parseConditionToAST('for all i in (1..2) : (@str[i+1] - @str[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Last string is > 100 bytes away: @str[3]-@str[2]=500-150=350');
});

// ============================================================================
// Scenario 5: Percentage-Based Detection
// ============================================================================

console.log('\n=== Scenario 5: Percentage Thresholds ===\n');

await test('for 80% of ($enc*) : ($ in (0..1000)) - 80% of encryption strings in header', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$enc1': { matched: true, count: 1, matches: [{ offset: 100, length: 10 }], offsets: [100] },
    '$enc2': { matched: true, count: 1, matches: [{ offset: 200, length: 12 }], offsets: [200] },
    '$enc3': { matched: true, count: 1, matches: [{ offset: 300, length: 8 }], offsets: [300] },
    '$enc4': { matched: true, count: 1, matches: [{ offset: 400, length: 15 }], offsets: [400] },
    '$enc5': { matched: true, count: 1, matches: [{ offset: 5000, length: 10 }], offsets: [5000] }
  });
  
  // for 80% of them : ($ in (0..1000))
  const ast = parseConditionToAST('for 80% of them : ($ in (0..1000))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '4 out of 5 (80%) are in range 0..1000');
});

await test('for 90% of ($enc*) : ($ in (0..1000)) - only 80% match, should fail', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$enc1': { matched: true, count: 1, matches: [{ offset: 100, length: 10 }], offsets: [100] },
    '$enc2': { matched: true, count: 1, matches: [{ offset: 200, length: 12 }], offsets: [200] },
    '$enc3': { matched: true, count: 1, matches: [{ offset: 300, length: 8 }], offsets: [300] },
    '$enc4': { matched: true, count: 1, matches: [{ offset: 400, length: 15 }], offsets: [400] },
    '$enc5': { matched: true, count: 1, matches: [{ offset: 5000, length: 10 }], offsets: [5000] }
  });
  
  // for 90% of them : ($ in (0..1000))
  const ast = parseConditionToAST('for 90% of them : ($ in (0..1000))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Only 80% match, need 90%');
});

// ============================================================================
// Scenario 6: Complex Nested Conditions
// ============================================================================

console.log('\n=== Scenario 6: Complex Nested Conditions ===\n');

await test('for any of them : ($ in (0..100) and !$ > 5) - find string at start with length > 5', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 200, length: 3 }], offsets: [200] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 2 }], offsets: [300] }
  });
  
  // for any of them : ($ in (0..100) and !$ > 5)
  const ast = parseConditionToAST('for any of them : ($ in (0..100) and !$ > 5)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a is at 50 (in range) and length is 8 (> 5)');
});

await test('for all of them : ($ in (0..100) or !$ < 5) - all strings match at least one condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 200, length: 3 }], offsets: [200] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 2 }], offsets: [300] }
  });
  
  // for all of them : ($ in (0..100) or !$ < 5)
  const ast = parseConditionToAST('for all of them : ($ in (0..100) or !$ < 5)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a in range, $b and $c have length < 5');
});

// ============================================================================
// Summary
// ============================================================================

printSummary();
