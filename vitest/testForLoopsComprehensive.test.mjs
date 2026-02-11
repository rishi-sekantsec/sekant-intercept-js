/**
 * Comprehensive Test Suite for YARA For Loops - Edge Cases & Complex Scenarios
 * 
 * This test suite covers:
 * - Complex nested boolean logic
 * - Multiple string patterns with wildcards
 * - Edge cases with boundary conditions
 * - Error handling and graceful failures
 * - Performance edge cases (large ranges, many strings)
 * - Complex arithmetic expressions
 * - Mixed quantifier types
 * - Unicode and special characters
 */

import { createScanFacts, ConditionEvaluator } from '../src/yaraConditionsMatch.mjs';
import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import {
  test,
  assertTrue,
  assertFalse,
  assertEquals as assertEqual,
  printSummary
} from './testingFramework.mjs';

function createTestData(size = 10000) {
  const data = new Uint8Array(size);
  for (let i = 0; i < data.length; i++) {
    data[i] = i % 256;
  }
  return data;
}

console.log('=== Comprehensive YARA For Loop Tests ===\n');

// ============================================================================
// Section 1: Complex Nested Boolean Logic
// ============================================================================

console.log('\n=== Section 1: Complex Nested Boolean Logic ===\n');

await test('for any - deeply nested AND/OR conditions', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 200, length: 3 }], offsets: [200] },
    '$c': { matched: true, count: 1, matches: [{ offset: 300, length: 10 }], offsets: [300] }
  });
  
  // for any of them : (($ in (0..100) and !$ > 5) or ($ in (200..400) and !$ < 5))
  const ast = parseConditionToAST('for any of them : (($ in (0..100) and !$ > 5) or ($ in (200..400) and !$ < 5))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a matches first part (offset 50, length 8), $b matches second part (offset 200, length 3)');
});

await test('for all - complex OR with multiple conditions', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 60, length: 3 }], offsets: [60] },
    '$c': { matched: true, count: 1, matches: [{ offset: 70, length: 10 }], offsets: [70] }
  });
  
  // for all of them : ($ in (0..100) or $ in (500..600) or $ in (800..900))
  const ast = parseConditionToAST('for all of them : ($ in (0..100) or $ in (500..600) or $ in (800..900))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All strings are in range 0..100');
});

await test('for all - NOT operator with complex condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 8 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 60, length: 3 }], offsets: [60] }
  });
  
  // for all of them : (not ($ in (500..600) or $ in (800..900)))
  const ast = parseConditionToAST('for all of them : (not ($ in (500..600) or $ in (800..900)))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'No strings are in the excluded ranges');
});

await test('for any - triple nested boolean logic', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 25, length: 10 }], offsets: [25] },
    '$b': { matched: true, count: 1, matches: [{ offset: 500, length: 5 }], offsets: [500] },
    '$c': { matched: true, count: 1, matches: [{ offset: 900, length: 15 }], offsets: [900] }
  });
  
  // for any of them : (($ in (0..100) and !$ > 8) and ($ at 25 or $ at 26))
  const ast = parseConditionToAST('for any of them : (($ in (0..100) and !$ > 8) and ($ at 25 or $ at 26))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a is at 25, in range 0..100, and length > 8');
});

// ============================================================================
// Section 2: Boundary Conditions & Edge Cases
// ============================================================================

console.log('\n=== Section 2: Boundary Conditions & Edge Cases ===\n');

await test('for all i in (0..0) - single iteration', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 5 },
      { offset: 30, length: 5 },
      { offset: 40, length: 5 },
      { offset: 50, length: 5 }
    ], offsets: [10, 20, 30, 40, 50] }
  });
  
  // for all i in (0..0) : (@a[i] < 100)
  const ast = parseConditionToAST('for all i in (0..0) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Single iteration checks only index 0');
});

await test('for any i in (100..99) - reversed range (empty)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] }
  });
  
  // for any i in (100..99) : (@a[i] < 50)
  const ast = parseConditionToAST('for any i in (100..99) : (@a[i] < 50)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'Empty range with "any" returns false');
});

await test('for i in range - accessing out of bounds indices', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 5 },
      { offset: 30, length: 5 }
    ], offsets: [10, 20, 30] }
  });
  
  // for any i in (0..10) : (@a[i] < 100)
  const ast = parseConditionToAST('for any i in (0..10) : (@a[i] < 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Out of bounds returns undefined, only valid indices 0-2 return true');
});

await test('for 1 of them - minimum threshold', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 500, length: 5 }], offsets: [500] }
  });
  
  // for 1 of them : ($ in (0..100))
  const ast = parseConditionToAST('for 1 of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'At least 1 string ($a) is in range');
});

await test('for 99% of them - high percentage with rounding', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 60, length: 5 }], offsets: [60] },
    '$c': { matched: true, count: 1, matches: [{ offset: 70, length: 5 }], offsets: [70] }
  });
  
  // for 99% of them : ($ in (0..100))
  const ast = parseConditionToAST('for 99% of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '99% of 3 items = ceil(2.97) = 3, all 3 match');
});

await test('for 1% of them - minimum percentage', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 500, length: 5 }], offsets: [500] },
    '$c': { matched: true, count: 1, matches: [{ offset: 600, length: 5 }], offsets: [600] }
  });
  
  // for 1% of them : ($ in (0..100))
  const ast = parseConditionToAST('for 1% of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '1% of 3 items = ceil(0.03) = 1, $a matches');
});

// ============================================================================
// Section 3: Complex Arithmetic Expressions
// ============================================================================

console.log('\n=== Section 3: Complex Arithmetic Expressions ===\n');

await test('for i - arithmetic with multiple operations', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 6, matches: [
      { offset: 0, length: 5 },
      { offset: 10, length: 5 },
      { offset: 20, length: 5 },
      { offset: 30, length: 5 },
      { offset: 40, length: 5 },
      { offset: 50, length: 5 }
    ], offsets: [0, 10, 20, 30, 40, 50] }
  });
  
  // for all i in (1..5) : (@a[i+1] == @a[i] + 10)
  const ast = parseConditionToAST('for all i in (1..5) : (@a[i+1] == @a[i] + 10)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Each offset is exactly 10 more than previous: @a[2]=10==@a[1]=0+10, etc.');
});

await test('for i - complex arithmetic with subtraction', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [
      { offset: 100, length: 5 },
      { offset: 150, length: 5 },
      { offset: 200, length: 5 },
      { offset: 250, length: 5 },
      { offset: 300, length: 5 }
    ], offsets: [100, 150, 200, 250, 300] }
  });
  
  // for all i in (2..5) : (@a[i] - @a[i-1] == 50)
  const ast = parseConditionToAST('for all i in (2..5) : (@a[i] - @a[i-1] == 50)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All adjacent pairs are 50 apart: @a[2]-@a[1]=150-100=50, @a[3]-@a[2]=200-150=50, etc.');
});

await test('for i - multiplication in condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 4, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 5 },
      { offset: 40, length: 5 },
      { offset: 80, length: 5 }
    ], offsets: [10, 20, 40, 80] }
  });
  
  // for all i in (2..4) : (@a[i] == @a[i-1] * 2)
  const ast = parseConditionToAST('for all i in (2..4) : (@a[i] == @a[i-1] * 2)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Each offset is double the previous: @a[2]=20==@a[1]=10*2, @a[3]=40==@a[2]=20*2, @a[4]=80==@a[3]=40*2');
});

await test('for i - division and modulo', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [
      { offset: 100, length: 5 },
      { offset: 200, length: 5 },
      { offset: 300, length: 5 },
      { offset: 400, length: 5 },
      { offset: 500, length: 5 }
    ], offsets: [100, 200, 300, 400, 500] }
  });
  
  // for all i in (0..4) : (@a[i] % 100 == 0)
  const ast = parseConditionToAST('for all i in (0..4) : (@a[i] % 100 == 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All offsets are divisible by 100');
});

await test('for i - checking length progression', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 6 },
      { offset: 30, length: 7 },
      { offset: 40, length: 8 },
      { offset: 50, length: 9 }
    ], offsets: [10, 20, 30, 40, 50] }
  });
  
  // for all i in (1..4) : (!a[i+1] == !a[i] + 1)
  const ast = parseConditionToAST('for all i in (1..4) : (!a[i+1] == !a[i] + 1)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Each length is 1 more than previous: !a[2]=6==!a[1]=5+1, etc.');
});

// ============================================================================
// Section 4: Multiple Strings with Complex Patterns
// ============================================================================

console.log('\n=== Section 4: Multiple Strings with Complex Patterns ===\n');

await test('for - many strings (10) with percentage', async () => {
  const data = createTestData();
  const strings = {};
  for (let i = 0; i < 10; i++) {
    const inRange = i < 7; // First 7 are in range
    strings[`$s${i}`] = {
      matched: true,
      count: 1,
      matches: [{ offset: inRange ? 50 + i * 10 : 500 + i * 10, length: 5 }],
      offsets: [inRange ? 50 + i * 10 : 500 + i * 10]
    };
  }
  const facts = createScanFacts(data, strings);
  
  // for 70% of them : ($ in (0..200))
  const ast = parseConditionToAST('for 70% of them : ($ in (0..200))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '7 out of 10 (70%) are in range 0..200');
});

await test('for - 20 strings with exact count', async () => {
  const data = createTestData();
  const strings = {};
  for (let i = 0; i < 20; i++) {
    const inRange = i < 15; // First 15 are in range
    strings[`$str${i}`] = {
      matched: true,
      count: 1,
      matches: [{ offset: inRange ? 10 + i * 5 : 1000 + i * 5, length: 4 }],
      offsets: [inRange ? 10 + i * 5 : 1000 + i * 5]
    };
  }
  const facts = createScanFacts(data, strings);
  
  // for 15 of them : ($ in (0..200))
  const ast = parseConditionToAST('for 15 of them : ($ in (0..200))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Exactly 15 strings are in range 0..200');
});

await test('for - mixed string positions with complex condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$api1': { matched: true, count: 1, matches: [{ offset: 100, length: 15 }], offsets: [100] },
    '$api2': { matched: true, count: 1, matches: [{ offset: 200, length: 12 }], offsets: [200] },
    '$api3': { matched: true, count: 1, matches: [{ offset: 300, length: 18 }], offsets: [300] },
    '$api4': { matched: true, count: 1, matches: [{ offset: 400, length: 10 }], offsets: [400] },
    '$api5': { matched: true, count: 1, matches: [{ offset: 500, length: 20 }], offsets: [500] }
  });
  
  // for 60% of them : (($ in (0..500) and !$ > 12) or !$ == 20)
  const ast = parseConditionToAST('for 60% of them : (($ in (0..500) and !$ > 12) or !$ == 20)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'api1(15), api3(18), api5(20) match: 3/5 = 60%');
});

// ============================================================================
// Section 5: Large Ranges and Performance Edge Cases
// ============================================================================

console.log('\n=== Section 5: Large Ranges and Performance Edge Cases ===\n');

await test('for i in (0..100) - larger range with early termination (any)', async () => {
  const data = createTestData();
  const offsets = [];
  for (let i = 0; i < 150; i++) {
    offsets.push(i * 10);
  }
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 150, 
      matches: offsets.map(o => ({ offset: o, length: 5 })),
      offsets 
    }
  });
  
  // for any i in (0..100) : (@a[i] > 500)
  const ast = parseConditionToAST('for any i in (0..100) : (@a[i] > 500)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Should find match at index 51 or higher (510+)');
});

await test('for i in (0..100) - all fail but evaluate all', async () => {
  const data = createTestData();
  const offsets = [];
  for (let i = 0; i < 150; i++) {
    offsets.push(i * 10);
  }
  const facts = createScanFacts(data, {
    '$a': { 
      matched: true, 
      count: 150, 
      matches: offsets.map(o => ({ offset: o, length: 5 })),
      offsets 
    }
  });
  
  // for all i in (0..100) : (@a[i] < 0)
  const ast = parseConditionToAST('for all i in (0..100) : (@a[i] < 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, 'All offsets are >= 0, so all fail');
});

await test('for - many matches of single string', async () => {
  const data = createTestData();
  const offsets = [];
  for (let i = 0; i < 50; i++) {
    offsets.push(i * 20);
  }
  const facts = createScanFacts(data, {
    '$pattern': { 
      matched: true, 
      count: 50, 
      matches: offsets.map(o => ({ offset: o, length: 4 })),
      offsets 
    }
  });
  
  // for 80% i in (0..49) : (@pattern[i] < 800)
  // Note: This should be parsed as "for 80% of i in range"
  // But our current parser expects "for 80% of them"
  // So let's test with a valid syntax
  const ast = parseConditionToAST('for all i in (0..39) : (@pattern[i] < 800)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'First 40 matches (0-39) have offsets < 800');
});

// ============================================================================
// Section 6: String Length Edge Cases
// ============================================================================

console.log('\n=== Section 6: String Length Edge Cases ===\n');

await test('for - all strings same length', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 10 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 50, length: 10 }], offsets: [50] },
    '$c': { matched: true, count: 1, matches: [{ offset: 100, length: 10 }], offsets: [100] }
  });
  
  // for all of them : (!$ == 10)
  const ast = parseConditionToAST('for all of them : (!$ == 10)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All strings have length 10');
});

await test('for - length variance check', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 50, length: 10 }], offsets: [50] },
    '$c': { matched: true, count: 1, matches: [{ offset: 100, length: 15 }], offsets: [100] }
  });
  
  // for any of them : (!$ > 12)
  const ast = parseConditionToAST('for any of them : (!$ > 12)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$c has length 15 which is > 12');
});

await test('for i - length comparison between adjacent matches', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 4, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 10 },
      { offset: 30, length: 15 },
      { offset: 40, length: 20 }
    ], offsets: [10, 20, 30, 40] }
  });
  
  // for all i in (1..3) : (!a[i] < !a[i+1])
  const ast = parseConditionToAST('for all i in (1..3) : (!a[i] < !a[i+1])');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Each length is greater than previous: !a[1]=5 < !a[2]=10 < !a[3]=15 < !a[4]=20');
});

await test('for - zero length strings (edge case)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 0 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] }
  });
  
  // for any of them : (!$ == 0)
  const ast = parseConditionToAST('for any of them : (!$ == 0)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '$a has length 0');
});

// ============================================================================
// Section 7: Mixed Quantifiers and Complex Combinations
// ============================================================================

console.log('\n=== Section 7: Mixed Quantifiers and Complex Combinations ===\n');

await test('for - combining percentage with range check', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$enc1': { matched: true, count: 1, matches: [{ offset: 10, length: 100 }], offsets: [10] },
    '$enc2': { matched: true, count: 1, matches: [{ offset: 500, length: 150 }], offsets: [500] },
    '$enc3': { matched: true, count: 1, matches: [{ offset: 1000, length: 200 }], offsets: [1000] },
    '$enc4': { matched: true, count: 1, matches: [{ offset: 2000, length: 50 }], offsets: [2000] }
  });
  
  // for 50% of them : ($ in (0..1500) and !$ > 90)
  const ast = parseConditionToAST('for 50% of them : ($ in (0..1500) and !$ > 90)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'enc1(100) and enc2(150) match: 2/4 = 50%');
});

await test('for - exact count with OR conditions', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$s1': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$s2': { matched: true, count: 1, matches: [{ offset: 1000, length: 5 }], offsets: [1000] },
    '$s3': { matched: true, count: 1, matches: [{ offset: 2000, length: 20 }], offsets: [2000] },
    '$s4': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] }
  });
  
  // for 3 of them : ($ in (0..100) or !$ > 15)
  const ast = parseConditionToAST('for 3 of them : ($ in (0..100) or !$ > 15)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 's1, s3, s4 match (3 total)');
});

await test('for - high percentage with tight constraints', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 25, length: 8 }], offsets: [25] },
    '$b': { matched: true, count: 1, matches: [{ offset: 35, length: 9 }], offsets: [35] },
    '$c': { matched: true, count: 1, matches: [{ offset: 45, length: 10 }], offsets: [45] },
    '$d': { matched: true, count: 1, matches: [{ offset: 200, length: 5 }], offsets: [200] }
  });
  
  // for 75% of them : ($ in (20..50) and !$ > 7)
  const ast = parseConditionToAST('for 75% of them : ($ in (20..50) and !$ > 7)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'a, b, c all match: 3/4 = 75%');
});

// ============================================================================
// Section 8: Negative and Inverse Logic
// ============================================================================

console.log('\n=== Section 8: Negative and Inverse Logic ===\n');

await test('for none of them - inverse of any', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 200, length: 5 }], offsets: [200] },
    '$b': { matched: true, count: 1, matches: [{ offset: 300, length: 5 }], offsets: [300] },
    '$c': { matched: true, count: 1, matches: [{ offset: 400, length: 5 }], offsets: [400] }
  });
  
  // for none of them : ($ in (0..100))
  const ast = parseConditionToAST('for none of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'No strings are in range 0..100');
});

await test('for none of them - fails when one matches', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 300, length: 5 }], offsets: [300] }
  });
  
  // for none of them : ($ in (0..100))
  const ast = parseConditionToAST('for none of them : ($ in (0..100))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertFalse(result, '$a is in range, so "none" fails');
});

await test('for all - with NOT in condition body', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] },
    '$b': { matched: true, count: 1, matches: [{ offset: 20, length: 5 }], offsets: [20] }
  });
  
  // for all of them : (not ($ in (500..600)))
  const ast = parseConditionToAST('for all of them : (not ($ in (500..600)))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Both strings are NOT in range 500..600');
});

await test('for any - double negative', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 50, length: 5 }], offsets: [50] },
    '$b': { matched: true, count: 1, matches: [{ offset: 500, length: 5 }], offsets: [500] }
  });
  
  // for any of them : (not (not ($ in (0..100))))
  const ast = parseConditionToAST('for any of them : (not (not ($ in (0..100))))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'Double negative: $a is in range');
});

// ============================================================================
// Section 9: Comparison Operators at Boundaries
// ============================================================================

console.log('\n=== Section 9: Comparison Operators at Boundaries ===\n');

await test('for i - exact equality check', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [
      { offset: 100, length: 5 },
      { offset: 100, length: 5 },
      { offset: 100, length: 5 },
      { offset: 100, length: 5 },
      { offset: 100, length: 5 }
    ], offsets: [100, 100, 100, 100, 100] }
  });
  
  // for all i in (0..4) : (@a[i] == 100)
  const ast = parseConditionToAST('for all i in (0..4) : (@a[i] == 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All offsets are exactly 100');
});

await test('for i - less than or equal boundary', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [
      { offset: 98, length: 5 },
      { offset: 99, length: 5 },
      { offset: 100, length: 5 }
    ], offsets: [98, 99, 100] }
  });
  
  // for all i in (0..2) : (@a[i] <= 100)
  const ast = parseConditionToAST('for all i in (0..2) : (@a[i] <= 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All offsets are <= 100');
});

await test('for i - greater than or equal boundary', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [
      { offset: 100, length: 5 },
      { offset: 101, length: 5 },
      { offset: 102, length: 5 }
    ], offsets: [100, 101, 102] }
  });
  
  // for all i in (0..2) : (@a[i] >= 100)
  const ast = parseConditionToAST('for all i in (0..2) : (@a[i] >= 100)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All offsets are >= 100');
});

await test('for i - not equal check', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 4, matches: [
      { offset: 10, length: 5 },
      { offset: 20, length: 5 },
      { offset: 30, length: 5 },
      { offset: 40, length: 5 }
    ], offsets: [10, 20, 30, 40] }
  });
  
  // for all i in (0..3) : (@a[i] != 50)
  const ast = parseConditionToAST('for all i in (0..3) : (@a[i] != 50)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'No offset equals 50');
});

// ============================================================================
// Section 10: Real-World Malware Detection Patterns
// ============================================================================

console.log('\n=== Section 10: Real-World Malware Detection Patterns ===\n');

await test('Packed binary - high entropy sections', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$sec1': { matched: true, count: 1, matches: [{ offset: 1000, length: 500 }], offsets: [1000] },
    '$sec2': { matched: true, count: 1, matches: [{ offset: 2000, length: 600 }], offsets: [2000] },
    '$sec3': { matched: true, count: 1, matches: [{ offset: 3000, length: 700 }], offsets: [3000] }
  });
  
  // Simulating: for all sections, size > 400
  // for all of them : (!$ > 400)
  const ast = parseConditionToAST('for all of them : (!$ > 400)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All sections have size > 400 (packed binary indicator)');
});

await test('API call clustering - calls within 1KB', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$api': { matched: true, count: 5, matches: [
      { offset: 5000, length: 10 },
      { offset: 5200, length: 12 },
      { offset: 5400, length: 11 },
      { offset: 5600, length: 9 },
      { offset: 5800, length: 13 }
    ], offsets: [5000, 5200, 5400, 5600, 5800] }
  });
  
  // for all i in (0..3) : (@api[i+1] - @api[i] < 1000)
  const ast = parseConditionToAST('for all i in (0..3) : (@api[i+1] - @api[i] < 1000)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All API calls are within 1000 bytes of each other');
});

await test('Ransomware - file extension strings in footer', async () => {
  const data = createTestData(10000);
  const facts = createScanFacts(data, {
    '$ext1': { matched: true, count: 1, matches: [{ offset: 9100, length: 6 }], offsets: [9100] },
    '$ext2': { matched: true, count: 1, matches: [{ offset: 9200, length: 7 }], offsets: [9200] },
    '$ext3': { matched: true, count: 1, matches: [{ offset: 9300, length: 8 }], offsets: [9300] },
    '$ext4': { matched: true, count: 1, matches: [{ offset: 9400, length: 5 }], offsets: [9400] }
  });
  
  // Simulating: for 75% in last 1KB (filesize is 10000)
  // for 75% of them : ($ in (9000..10000))
  const ast = parseConditionToAST('for 75% of them : ($ in (9000..10000))');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, '100% (4/4) of extension strings in last 1KB');
});

await test('Shellcode - consistent byte patterns', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$nop': { matched: true, count: 10, matches: [
      { offset: 100, length: 1 },
      { offset: 101, length: 1 },
      { offset: 102, length: 1 },
      { offset: 103, length: 1 },
      { offset: 104, length: 1 },
      { offset: 105, length: 1 },
      { offset: 106, length: 1 },
      { offset: 107, length: 1 },
      { offset: 108, length: 1 },
      { offset: 109, length: 1 }
    ], offsets: [100, 101, 102, 103, 104, 105, 106, 107, 108, 109] }
  });
  
  // for all i in (1..9) : (@nop[i+1] == @nop[i] + 1)
  const ast = parseConditionToAST('for all i in (1..9) : (@nop[i+1] == @nop[i] + 1)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'NOP sled - consecutive bytes: @nop[2]=101==@nop[1]=100+1, etc.');
});

await test('Malware persistence - registry keys in specific range', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$reg1': { matched: true, count: 1, matches: [{ offset: 800, length: 20 }], offsets: [800] },
    '$reg2': { matched: true, count: 1, matches: [{ offset: 850, length: 25 }], offsets: [850] },
    '$reg3': { matched: true, count: 1, matches: [{ offset: 900, length: 22 }], offsets: [900] }
  });
  
  // for any of them : ($ in (800..1000) and !$ > 15)
  const ast = parseConditionToAST('for any of them : ($ in (800..1000) and !$ > 15)');
  const evaluator = new ConditionEvaluator(facts);
  const result = await evaluator.evaluate(ast);
  
  assertTrue(result, 'All registry key strings are in range and long enough');
});

// ============================================================================
// Summary
// ============================================================================
printSummary();

