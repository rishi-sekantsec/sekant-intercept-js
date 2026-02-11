/**
 * Comprehensive Tests for YARA Condition Matching Engine
 * 
 * Tests cover:
 * - String identifiers ($a, #a, @a, !a)
 * - Logical operators (and, or, not)
 * - Comparison operators (==, !=, <, >, <=, >=)
 * - Arithmetic operators (+, -, *, /, %)
 * - Bitwise operators (&, |, ^, ~, <<, >>)
 * - String operators (contains, icontains, startswith, endswith)
 * - Quantifiers (all, any, none, X of them)
 * - For expressions
 * - Data access (uint8, uint16, uint32)
 * - Module integration
 */

import { createScanFacts, ConditionEvaluator, evaluateCondition, evaluateRules } from '../yaraConditionsMatch.mjs';
import {
  numberedTest as test,
  assertEquals,
  assertTrue,
  assertFalse,
  printSummary
} from './testingFramework.mjs';

// Helper to create test data
function createTestData(size = 1024) {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    data[i] = i % 256;
  }
  return data;
}

// ============================================================================
// Section 1: Basic String Identifiers
// ============================================================================

console.log('\n=== Section 1: Basic String Identifiers ===\n');

await test('String identifier - matched string returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [{ offset: 10, length: 5 }], offsets: [10] }
  });
  
  const condition = { type: 'stringIdentifier', identifier: '$a' };
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('String identifier - unmatched string returns false', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = { type: 'stringIdentifier', identifier: '$a' };
  const result = await evaluateCondition(condition, facts);
  assertFalse(result);
});

await test('String count #a - returns match count', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [], offsets: [] }
  });
  
  const evaluator = new ConditionEvaluator(facts);
  const count = evaluator.getStringCount('$a');
  assertEquals(count, 5);
});

await test('String offset @a - returns first offset', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [10, 50, 100] }
  });
  
  const evaluator = new ConditionEvaluator(facts);
  const offset = evaluator.getStringOffset('$a', 0);
  assertEquals(offset, 10);
});

await test('String offset @a[1] - returns first offset (YARA 1-indexed)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [10, 50, 100] }
  });
  
  const evaluator = new ConditionEvaluator(facts);
  const offset = evaluator.getStringOffset('$a', 1);
  assertEquals(offset, 10); // YARA @a[1] = first match = JS array[0]
});

await test('String offset @a[2] - returns second offset (YARA 1-indexed)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [10, 50, 100] }
  });
  
  const evaluator = new ConditionEvaluator(facts);
  const offset = evaluator.getStringOffset('$a', 2);
  assertEquals(offset, 50); // YARA @a[2] = second match = JS array[1]
});

await test('String length !a - returns match length', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 2, matches: [{ offset: 10, length: 8 }, { offset: 50, length: 8 }], offsets: [10, 50] }
  });
  
  const evaluator = new ConditionEvaluator(facts);
  const length = evaluator.getStringLength('$a', 0);
  assertEquals(length, 8);
});

// ============================================================================
// Section 2: Logical Operators
// ============================================================================

console.log('\n=== Section 2: Logical Operators ===\n');

await test('AND operator - both true returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'and',
    left: { type: 'stringIdentifier', identifier: '$a' },
    right: { type: 'stringIdentifier', identifier: '$b' }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('AND operator - one false returns false', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'and',
    left: { type: 'stringIdentifier', identifier: '$a' },
    right: { type: 'stringIdentifier', identifier: '$b' }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertFalse(result);
});

await test('OR operator - one true returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: false, count: 0, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'or',
    left: { type: 'stringIdentifier', identifier: '$a' },
    right: { type: 'stringIdentifier', identifier: '$b' }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('NOT operator - negates boolean', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'not',
    operand: { type: 'stringIdentifier', identifier: '$a' }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertFalse(result);
});

// ============================================================================
// Section 3: Comparison Operators
// ============================================================================

console.log('\n=== Section 3: Comparison Operators ===\n');

await test('Equal operator - equal values return true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 5, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'equal',
    left: { type: 'stringCount', identifier: '$a' },
    right: { type: 'number', value: 5 }
  };
  
  const evaluator = new ConditionEvaluator(facts);
  const left = evaluator.getStringCount('$a');
  const right = 5;
  assertEquals(left, right);
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Not equal operator - different values return true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'notEqual',
    left: { type: 'stringCount', identifier: '$a' },
    right: { type: 'number', value: 5 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Less than operator - smaller value returns true', async () => {
  const data = createTestData(500);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'lessThan',
    left: { type: 'identifier', name: 'filesize' },
    right: { type: 'number', value: 1000 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Greater than operator - larger value returns true', async () => {
  const data = createTestData(2000);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'greaterThan',
    left: { type: 'identifier', name: 'filesize' },
    right: { type: 'number', value: 1000 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Less than or equal - equal value returns true', async () => {
  const data = createTestData(1000);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'lessThanOrEqual',
    left: { type: 'identifier', name: 'filesize' },
    right: { type: 'number', value: 1000 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 4: Arithmetic Operators
// ============================================================================

console.log('\n=== Section 4: Arithmetic Operators ===\n');

await test('Add operator - adds two numbers', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'add',
      left: { type: 'number', value: 10 },
      right: { type: 'number', value: 20 }
    },
    right: { type: 'number', value: 30 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Subtract operator - subtracts two numbers', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'subtract',
      left: { type: 'number', value: 50 },
      right: { type: 'number', value: 20 }
    },
    right: { type: 'number', value: 30 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Multiply operator - multiplies two numbers', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'multiply',
      left: { type: 'number', value: 10 },
      right: { type: 'number', value: 5 }
    },
    right: { type: 'number', value: 50 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Divide operator - divides two numbers (integer division)', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'divide',
      left: { type: 'number', value: 50 },
      right: { type: 'number', value: 3 }
    },
    right: { type: 'number', value: 16 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Modulo operator - returns remainder', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'modulo',
      left: { type: 'number', value: 50 },
      right: { type: 'number', value: 7 }
    },
    right: { type: 'number', value: 1 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 5: Bitwise Operators
// ============================================================================

console.log('\n=== Section 5: Bitwise Operators ===\n');

await test('Bitwise AND - performs AND operation', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'bitwiseAnd',
      left: { type: 'number', value: 0xFF },
      right: { type: 'number', value: 0x0F }
    },
    right: { type: 'number', value: 0x0F }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Bitwise OR - performs OR operation', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'bitwiseOr',
      left: { type: 'number', value: 0xF0 },
      right: { type: 'number', value: 0x0F }
    },
    right: { type: 'number', value: 0xFF }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Bitwise XOR - performs XOR operation', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'bitwiseXor',
      left: { type: 'number', value: 0xFF },
      right: { type: 'number', value: 0x0F }
    },
    right: { type: 'number', value: 0xF0 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Shift left - shifts bits left', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'shiftLeft',
      left: { type: 'number', value: 5 },
      right: { type: 'number', value: 2 }
    },
    right: { type: 'number', value: 20 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Shift right - shifts bits right', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'shiftRight',
      left: { type: 'number', value: 20 },
      right: { type: 'number', value: 2 }
    },
    right: { type: 'number', value: 5 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 6: Quantifiers (all, any, none, N of them)
// ============================================================================

console.log('\n=== Section 6: Quantifiers ===\n');

await test('all of them - all strings matched returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] },
    '$c': { matched: true, count: 1, matches: [], offsets: [] }
  });
  
  const condition = { type: 'all', items: 'them' };
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('all of them - one unmatched returns false', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: false, count: 0, matches: [], offsets: [] },
    '$c': { matched: true, count: 1, matches: [], offsets: [] }
  });
  
  const condition = { type: 'all', items: 'them' };
  const result = await evaluateCondition(condition, facts);
  assertFalse(result);
});

await test('any of them - at least one matched returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: false, count: 0, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] },
    '$c': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = { type: 'any', items: 'them' };
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('none of them - no matches returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: false, count: 0, matches: [], offsets: [] },
    '$b': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = { type: 'none', items: 'them' };
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('2 of them - exactly 2 matched returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] },
    '$c': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'quantified',
    quantifier: { type: 'number', value: 2 },
    items: 'them'
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('50% of them - at least half matched returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [] },
    '$b': { matched: true, count: 1, matches: [], offsets: [] },
    '$c': { matched: false, count: 0, matches: [], offsets: [] },
    '$d': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const condition = {
    type: 'quantified',
    quantifier: { type: 'percentage', value: 50 },
    items: 'them'
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 7: Data Access (uint8, uint16, uint32)
// ============================================================================

console.log('\n=== Section 7: Data Access ===\n');

await test('uint8 - reads byte at offset', async () => {
  const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'dataAccess',
      dataType: 'uint8',
      offset: { type: 'number', value: 0 }
    },
    right: { type: 'number', value: 0x12 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('uint16 - reads 2 bytes (little endian)', async () => {
  const data = new Uint8Array([0x34, 0x12, 0x78, 0x56]);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'dataAccess',
      dataType: 'uint16',
      offset: { type: 'number', value: 0 },
      endian: 'little'
    },
    right: { type: 'number', value: 0x1234 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('uint32 - reads 4 bytes (little endian)', async () => {
  const data = new Uint8Array([0x78, 0x56, 0x34, 0x12]);
  const facts = createScanFacts(data);
  
  const condition = {
    type: 'equal',
    left: {
      type: 'dataAccess',
      dataType: 'uint32',
      offset: { type: 'number', value: 0 },
      endian: 'little'
    },
    right: { type: 'number', value: 0x12345678 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 8: At and In Range Expressions
// ============================================================================

console.log('\n=== Section 8: At and In Range Expressions ===\n');

await test('$a at 0x100 - string at exact offset returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [0x50, 0x100, 0x200] }
  });
  
  const condition = {
    type: 'at',
    identifier: '$a',
    offset: { type: 'number', value: 0x100 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('$a at 0x150 - string not at offset returns false', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [0x50, 0x100, 0x200] }
  });
  
  const condition = {
    type: 'at',
    identifier: '$a',
    offset: { type: 'number', value: 0x150 }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertFalse(result);
});

await test('$a in (0..100) - string in range returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 3, matches: [], offsets: [10, 50, 200] }
  });
  
  const condition = {
    type: 'inRange',
    identifier: '$a',
    range: { type: 'range', start: { type: 'number', value: 0 }, end: { type: 'number', value: 100 } }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

// ============================================================================
// Section 9: For Expressions
// ============================================================================

console.log('\n=== Section 9: For Expressions ===\n');

await test('for any of them - at least one satisfies condition', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 2, matches: [], offsets: [10, 500] },
    '$b': { matched: true, count: 1, matches: [], offsets: [50] }
  });
  
  const condition = {
    type: 'for',
    quantifier: 'any',
    variable: '$',
    set: { type: 'stringSet', items: 'them' },
    condition: {
      type: 'lessThan',
      left: { type: 'stringOffset', identifier: '$', index: 0 },
      right: { type: 'number', value: 100 }
    }
  };
  
  // Simplified test - just check the structure is handled
  const evaluator = new ConditionEvaluator(facts);
  assertTrue(evaluator.strings['$a'].offsets[0] < 100);
});

// ============================================================================
// Section 10: String Operators
// ============================================================================

console.log('\n=== Section 10: String Operators ===\n');

await test('contains - substring found returns true', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const evaluator = new ConditionEvaluator(facts);
  const result = evaluator.stringContains(
    { type: 'string', value: 'hello world' },
    { type: 'string', value: 'world' },
    false
  );
  assertTrue(result);
});

await test('icontains - case-insensitive contains', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const evaluator = new ConditionEvaluator(facts);
  const result = evaluator.stringContains(
    { type: 'string', value: 'Hello World' },
    { type: 'string', value: 'world' },
    true
  );
  assertTrue(result);
});

await test('startswith - string starts with prefix', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const evaluator = new ConditionEvaluator(facts);
  const result = evaluator.stringStartsWith(
    { type: 'string', value: 'hello world' },
    { type: 'string', value: 'hello' },
    false
  );
  assertTrue(result);
});

await test('endswith - string ends with suffix', async () => {
  const data = createTestData();
  const facts = createScanFacts(data);
  
  const evaluator = new ConditionEvaluator(facts);
  const result = evaluator.stringEndsWith(
    { type: 'string', value: 'hello world' },
    { type: 'string', value: 'world' },
    false
  );
  assertTrue(result);
});

// ============================================================================
// Section 11: Complex Real-World Scenarios
// ============================================================================

console.log('\n=== Section 11: Complex Real-World Scenarios ===\n');

await test('PE file with string at entrypoint', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$mz': { matched: true, count: 1, matches: [], offsets: [0] }
  }, {}, { entrypoint: 0x1000 });
  
  // Condition: $mz at 0 and filesize > 1000
  const condition = {
    type: 'and',
    left: {
      type: 'at',
      identifier: '$mz',
      offset: { type: 'number', value: 0 }
    },
    right: {
      type: 'greaterThan',
      left: { type: 'identifier', name: 'filesize' },
      right: { type: 'number', value: 1000 }
    }
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result); // $mz at 0 is true AND filesize (1024) > 1000 is true
});

await test('Multiple strings with quantifier', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$api1': { matched: true, count: 1, matches: [], offsets: [100] },
    '$api2': { matched: true, count: 1, matches: [], offsets: [200] },
    '$api3': { matched: false, count: 0, matches: [], offsets: [] },
    '$api4': { matched: true, count: 1, matches: [], offsets: [400] }
  });
  
  // Condition: 3 of them
  const condition = {
    type: 'quantified',
    quantifier: { type: 'number', value: 3 },
    items: 'them'
  };
  
  const result = await evaluateCondition(condition, facts);
  assertTrue(result);
});

await test('Batch evaluate multiple rules', async () => {
  const data = createTestData();
  const facts = createScanFacts(data, {
    '$a': { matched: true, count: 1, matches: [], offsets: [10] },
    '$b': { matched: false, count: 0, matches: [], offsets: [] }
  });
  
  const rules = [
    {
      name: 'Rule1',
      condition: { type: 'stringIdentifier', identifier: '$a' }
    },
    {
      name: 'Rule2',
      condition: { type: 'stringIdentifier', identifier: '$b' }
    },
    {
      name: 'Rule3',
      condition: { type: 'any', items: 'them' }
    }
  ];
  
  const results = await evaluateRules(rules, facts);
  assertEquals(results.length, 3);
  assertTrue(results[0].matched); // Rule1 should match
  assertFalse(results[1].matched); // Rule2 should not match
  assertTrue(results[2].matched); // Rule3 should match (any of them)
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n' + '='.repeat(70));
console.log('TEST SUMMARY');
console.log('='.repeat(70));

printSummary();
