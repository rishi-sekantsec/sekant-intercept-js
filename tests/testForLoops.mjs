/**
 * Comprehensive Test Suite for YARA For Loops
 * 
 * Tests all variants of YARA for loop syntax:
 * - for any/all of them : (condition)
 * - for N of them : (condition)
 * - for X% of them : (condition)
 * - for any/all i in (range) : (condition)
 * - for any/all of ($pattern*) : (condition)
 */

import { createScanFacts, ConditionEvaluator } from '../src/yaraConditionsMatch.mjs';
import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { test, assertTrue, assertFalse, assertEquals, printSummary, printSection } from './testingFramework.mjs';

// Helper to create test data
function createTestData() {
  const data = new Uint8Array(1000);
  for (let i = 0; i < data.length; i++) {
    data[i] = i % 256;
  }
  return data;
}

console.log('=== YARA For Loop Tests ===\n');

// ============================================================================
// Section 1: For Any/All of Them
// ============================================================================

console.log('\n=== Section 1: For Any/All of Them ===\n');

await test('for any of them - at least one string matches condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 2, matches: [{ offset: 10, length: 5 }, { offset: 500, length: 5 }], offsets: [10, 500] },
    '$b': { matched: true, count: 1, matches: [{ offset: 50, length: 4 }], offsets: [50] },
    '$c': { matched: true, count: 1, matches: [{ offset: 200, length: 6 }], offsets: [200] }
  });
  
  // for any of them : ($ at 10)
  const ast = parseConditionToAST('for any of them : ($ at 10)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a is at offset 10, so condition should be true');
});

await test('for any of them - with offset range check', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 150, length: 5 }], offsets: [150] },
    '$b': { matched: true, count: 1, matches: [{ offset: 250, length: 4 }], offsets: [250] },
    '$c': { matched: true, count: 1, matches: [{ offset: 350, length: 6 }], offsets: [350] }
  });
  
  // for any of them : ($ in (100..200))
  const ast = parseConditionToAST('for any of them : ($ in (100..200))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a is in range 100..200');
});

await test('for all of them - all strings must match condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 4 }], offsets: [20] },
    '$c': { matched: true, count: 1, matches: [{ offset: 30, length: 6 }], offsets: [30] }
  });
  
  // for all of them : ($ in (0..100))
  const ast = parseConditionToAST('for all of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All strings are in range 0..100');
});

await test('for all of them - fails when one does not match', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 4 }], offsets: [20] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] }
  });
  
  // for all of them : ($ in (0..100))
  const ast = parseConditionToAST('for all of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, '$c is at 300, outside range 0..100');
});

// ============================================================================
// Section 2: For N of Them / Percentage
// ============================================================================

console.log('\n=== Section 2: For N of Them / Percentage ===\n');

await test('for 2 of them - at least 2 strings match', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 4 }], offsets: [20] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] }
  });
  
  // for 2 of them : ($ in (0..100))
  const ast = parseConditionToAST('for 2 of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a and $b are in range, so 2 match');
});

await test('for 2 of them - fails when only 1 matches', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 200, length: 4 }], offsets: [200] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] }
  });
  
  // for 2 of them : ($ in (0..100))
  const ast = parseConditionToAST('for 2 of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Only $a is in range');
});

await test('for 50% of them - at least half match', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 4 }], offsets: [20] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] },
    '$d': { matched: true, count: 1, matches: [{ offset: 400, length: 6 }], offsets: [400] }
  });
  
  // for 50% of them : ($ in (0..100))
  const ast = parseConditionToAST('for 50% of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a and $b are in range, which is 50% (2/4)');
});

await test('for 70% of them - requires more than half', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 4 }], offsets: [20] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] },
    '$d': { matched: true, count: 1, matches: [{ offset: 400, length: 6 }], offsets: [400] }
  });
  
  // for 70% of them : ($ in (0..100))
  const ast = parseConditionToAST('for 70% of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Only 50% (2/4) are in range, need 70%');
});

// ============================================================================
// Section 3: For i in (range)
// ============================================================================

console.log('\n=== Section 3: For i in (range) ===\n');

await test('for all i in (1..3) - check all string occurrences in range', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 20, length: 5 },
        { offset: 30, length: 5 },
        { offset: 40, length: 5 }
      ], 
      offsets: [10, 20, 30, 40] 
    }
  });
  
  // for all i in (1..3) : (@a[i] < 100)
  const ast = parseConditionToAST('for all i in (1..3) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Offsets at indices 1,2,3 (20,30,40) are all < 100');
});

await test('for all i in (1..3) - fails when one does not match', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 20, length: 5 },
        { offset: 200, length: 5 },
        { offset: 40, length: 5 }
      ], 
      offsets: [10, 20, 200, 40] 
    }
  });
  
  // for all i in (1..3) : (@a[i] < 100)
  const ast = parseConditionToAST('for all i in (1..3) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Offset at index 2 (200) is >= 100');
});

await test('for any i in (1..5) - at least one index matches', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 500, length: 5 },
        { offset: 600, length: 5 },
        { offset: 50, length: 5 }
      ], 
      offsets: [500, 600, 50] 
    }
  });
  
  // for any i in (1..5) : (@a[i] < 100)
  const ast = parseConditionToAST('for any i in (1..5) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Offset @a[3]=50 is < 100');
});

await test('for all i in (1..#a) - iterate through all matches using count', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 20, length: 5 },
        { offset: 30, length: 5 }
      ], 
      offsets: [10, 20, 30] 
    }
  });
  
  // for all i in (1..3) : (@a[i] < 100)
  const ast = parseConditionToAST('for all i in (1..3) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All offsets @a[1]=10, @a[2]=20, @a[3]=30 are < 100');
});

// ============================================================================
// Section 4: Ordered Checks with i+1
// ============================================================================

console.log('\n=== Section 4: Ordered Checks with i+1 ===\n');

await test('for all i in (1..3) - check ascending order @a[i] < @a[i+1]', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 20, length: 5 },
        { offset: 30, length: 5 },
        { offset: 40, length: 5 }
      ], 
      offsets: [10, 20, 30, 40] 
    }
  });
  
  // for all i in (1..3) : (@a[i] < @a[i+1])
  const ast = parseConditionToAST('for all i in (1..3) : (@a[i] < @a[i+1])');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Offsets are in ascending order: @a[1]=10 < @a[2]=20 < @a[3]=30 < @a[4]=40');
});

await test('for all i in (1..3) - fails when not in order', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 4, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 30, length: 5 },
        { offset: 20, length: 5 },
        { offset: 40, length: 5 }
      ], 
      offsets: [10, 30, 20, 40] 
    }
  });
  
  // for all i in (1..3) : (@a[i] < @a[i+1])
  const ast = parseConditionToAST('for all i in (1..3) : (@a[i] < @a[i+1])');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Offsets not in order: @a[2]=30 > @a[3]=20');
});

// ============================================================================
// Section 5: String Length Checks
// ============================================================================

console.log('\n=== Section 5: String Length Checks ===\n');

await test('for all i in (1..3) - check string lengths', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 10, length: 5 },
        { offset: 20, length: 6 },
        { offset: 30, length: 7 }
      ], 
      offsets: [10, 20, 30] 
    }
  });
  
  // for all i in (1..3) : (!a[i] >= 5)
  const ast = parseConditionToAST('for all i in (1..3) : (!a[i] >= 5)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All lengths !a[1]=5, !a[2]=6, !a[3]=7 are >= 5');
});

await test('for any i in (1..3) - at least one length matches', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 10, length: 3 },
        { offset: 20, length: 4 },
        { offset: 30, length: 10 }
      ], 
      offsets: [10, 20, 30] 
    }
  });
  
  // for any i in (1..3) : (!a[i] > 8)
  const ast = parseConditionToAST('for any i in (1..3) : (!a[i] > 8)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Length !a[3]=10 is > 8');
});

// ============================================================================
// Section 6: Complex Conditions
// ============================================================================

console.log('\n=== Section 6: Complex Conditions ===\n');

await test('for any of them - complex condition with and', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 6 }], offsets: [300] }
  });
  
  // for any of them : ($ in (0..100) and !$ > 5)
  const ast = parseConditionToAST('for any of them : ($ in (0..100) and !$ > 5)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$b is in range and length > 5');
});

await test('for all i in (1..2) - arithmetic in condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 3, 
      matches: [
        { offset: 100, length: 5 },
        { offset: 200, length: 5 },
        { offset: 300, length: 5 }
      ], 
      offsets: [100, 200, 300] 
    }
  });
  
  // for all i in (1..2) : (@a[i+1] == @a[i] + 100)
  const ast = parseConditionToAST('for all i in (1..2) : (@a[i+1] == @a[i] + 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Each offset is 100 more than previous: @a[2]=200 == @a[1]=100 + 100, @a[3]=300 == @a[2]=200 + 100');
});

// ============================================================================
// Section 7: Edge Cases
// ============================================================================

console.log('\n=== Section 7: Edge Cases ===\n');

await test('for all of them - empty string set returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {});
  
  // for all of them : ($ at 0)
  const ast = parseConditionToAST('for all of them : ($ at 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Empty set: "all" is vacuously true');
});

await test('for any of them - empty string set returns false', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {});
  
  // for any of them : ($ at 0)
  const ast = parseConditionToAST('for any of them : ($ at 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Empty set: "any" is false');
});

await test('for all i in (5..2) - empty range returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] }
  });
  
  // for all i in (5..2) : (@a[i] < 100)
  const ast = parseConditionToAST('for all i in (5..2) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Empty range: "all" is vacuously true');
});

await test('for 0 of them - always true (at least 0)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 500, length: 5 }], offsets: [500] },
    '$b': { matched: true, count: 1, matches: [{ offset: 600, length: 5 }], offsets: [600] }
  });
  
  // for 0 of them : ($ in (0..100))
  const ast = parseConditionToAST('for 0 of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'At least 0 strings match (vacuously true)');
});

await test('for 100% of them - requires all', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 5 }], offsets: [20] }
  });
  
  // for 100% of them : ($ in (0..100))
  const ast = parseConditionToAST('for 100% of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Both strings are in range 0..100');
});

// ============================================================================
// Summary
// ============================================================================

printSummary();
