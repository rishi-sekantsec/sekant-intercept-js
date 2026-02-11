/**
 * Comprehensive Test Suite for YARA Bitwise Operators
 * 
 * Tests all bitwise operators with the parser:
 * - & (bitwise AND)
 * - | (bitwise OR)
 * - ^ (bitwise XOR)
 * - ~ (bitwise NOT)
 * - << (left shift)
 * - >> (right shift)
 */

import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { ConditionEvaluator, createScanFacts } from '../src/yaraConditionsMatch.mjs';
import { test, assertTrue, printSummary, printSection } from './testingFramework.mjs';

// Helper to create test data
function createTestData(content = 'test') {
  return new TextEncoder().encode(content);
}

// Helper to evaluate a condition string
function evaluateConditionString(conditionStr, data = createTestData()) {
  const facts = createScanFacts(data);
  const ast = parseConditionToAST(conditionStr);
  const evaluator = new ConditionEvaluator(facts);
  return evaluator.evaluate(ast);
}

printSection('BITWISE OPERATORS TEST SUITE');

// ============================================================================
// Section 1: Bitwise AND (&)
// ============================================================================

console.log('\n📋 Section 1: Bitwise AND (&)\n');

await test('1.1 Basic bitwise AND', () => {
  const result = evaluateConditionString('(12 & 10) == 8');
  assertTrue(result, '12 & 10 should equal 8 (1100 & 1010 = 1000)');
});

await test('1.2 AND with zero', () => {
  const result = evaluateConditionString('(255 & 0) == 0');
  assertTrue(result, 'Any number AND 0 should equal 0');
});

await test('1.3 AND with all bits set', () => {
  const result = evaluateConditionString('(42 & 255) == 42');
  assertTrue(result, 'n & 0xFF should equal n (for n < 256)');
});

await test('1.4 AND in complex expression', () => {
  const result = evaluateConditionString('((0xFF & 0x0F) + 5) == 20');
  assertTrue(result, '(0xFF & 0x0F) = 15, + 5 = 20');
});

await test('1.5 Multiple ANDs', () => {
  const result = evaluateConditionString('(0xFF & 0xF0 & 0x30) == 0x30');
  assertTrue(result, 'Chained AND operations');
});

// ============================================================================
// Section 2: Bitwise OR (|)
// ============================================================================

console.log('\n📋 Section 2: Bitwise OR (|)\n');

await test('2.1 Basic bitwise OR', () => {
  const result = evaluateConditionString('(12 | 10) == 14');
  assertTrue(result, '12 | 10 should equal 14 (1100 | 1010 = 1110)');
});

await test('2.2 OR with zero', () => {
  const result = evaluateConditionString('(42 | 0) == 42');
  assertTrue(result, 'Any number OR 0 should equal itself');
});

await test('2.3 OR with all bits set', () => {
  const result = evaluateConditionString('(42 | 255) == 255');
  assertTrue(result, 'n | 0xFF should equal 0xFF (for n < 256)');
});

await test('2.4 OR in complex expression', () => {
  const result = evaluateConditionString('((0xF0 | 0x0F) - 5) == 250');
  assertTrue(result, '(0xF0 | 0x0F) = 255, - 5 = 250');
});

await test('2.5 Multiple ORs', () => {
  const result = evaluateConditionString('(0x01 | 0x02 | 0x04) == 0x07');
  assertTrue(result, 'Chained OR operations');
});

// ============================================================================
// Section 3: Bitwise XOR (^)
// ============================================================================

console.log('\n📋 Section 3: Bitwise XOR (^)\n');

await test('3.1 Basic bitwise XOR', () => {
  const result = evaluateConditionString('(12 ^ 10) == 6');
  assertTrue(result, '12 ^ 10 should equal 6 (1100 ^ 1010 = 0110)');
});

await test('3.2 XOR with zero', () => {
  const result = evaluateConditionString('(42 ^ 0) == 42');
  assertTrue(result, 'Any number XOR 0 should equal itself');
});

await test('3.3 XOR with itself', () => {
  const result = evaluateConditionString('(42 ^ 42) == 0');
  assertTrue(result, 'Any number XOR itself should equal 0');
});

await test('3.4 XOR all bits', () => {
  const result = evaluateConditionString('(0xAA ^ 0xFF) == 0x55');
  assertTrue(result, 'XOR with all 1s inverts bits');
});

await test('3.5 Double XOR cancels', () => {
  const result = evaluateConditionString('((42 ^ 17) ^ 17) == 42');
  assertTrue(result, 'XOR is reversible: (n ^ k) ^ k = n');
});

await test('3.6 XOR swap property', () => {
  const result = evaluateConditionString('(5 ^ 7) == (7 ^ 5)');
  assertTrue(result, 'XOR is commutative');
});

// ============================================================================
// Section 4: Bitwise NOT (~)
// ============================================================================

console.log('\n📋 Section 4: Bitwise NOT (~)\n');

await test('4.1 Basic bitwise NOT', () => {
  const result = evaluateConditionString('(~0 & 0xFF) == 0xFF');
  assertTrue(result, '~0 should have all bits set');
});

await test('4.2 NOT inverts bits', () => {
  const result = evaluateConditionString('(~0xAA & 0xFF) == 0x55');
  assertTrue(result, '~0xAA should equal 0x55 (in lower 8 bits)');
});

await test('4.3 Double NOT', () => {
  const result = evaluateConditionString('(~~42 & 0xFF) == 42');
  assertTrue(result, 'Double NOT should restore original value (in lower 8 bits)');
});

await test('4.4 NOT with AND', () => {
  const result = evaluateConditionString('(~0x0F & 0xFF) == 0xF0');
  assertTrue(result, '~0x0F should equal 0xF0 in lower 8 bits');
});

await test('4.5 NOT zero', () => {
  // ~0 in JavaScript is -1 (two's complement), but we check the bits
  const result = evaluateConditionString('(~0) == -1');
  assertTrue(result, '~0 equals -1 in two\'s complement');
});

// ============================================================================
// Section 5: Left Shift (<<)
// ============================================================================

console.log('\n📋 Section 5: Left Shift (<<)\n');

await test('5.1 Basic left shift', () => {
  const result = evaluateConditionString('(5 << 2) == 20');
  assertTrue(result, '5 << 2 should equal 20 (multiply by 4)');
});

await test('5.2 Left shift by 1', () => {
  const result = evaluateConditionString('(7 << 1) == 14');
  assertTrue(result, 'n << 1 doubles the value');
});

await test('5.3 Left shift by 0', () => {
  const result = evaluateConditionString('(42 << 0) == 42');
  assertTrue(result, 'Shifting by 0 returns same value');
});

await test('5.4 Left shift multiple times', () => {
  const result = evaluateConditionString('(1 << 8) == 256');
  assertTrue(result, '1 << 8 should equal 256');
});

await test('5.5 Left shift in expression', () => {
  const result = evaluateConditionString('((3 << 2) + 4) == 16');
  assertTrue(result, '(3 << 2) = 12, + 4 = 16');
});

await test('5.6 Chained left shifts', () => {
  const result = evaluateConditionString('((2 << 2) << 1) == 16');
  assertTrue(result, '((2 << 2) << 1) = (8 << 1) = 16');
});

// ============================================================================
// Section 6: Right Shift (>>)
// ============================================================================

console.log('\n📋 Section 6: Right Shift (>>)\n');

await test('6.1 Basic right shift', () => {
  const result = evaluateConditionString('(20 >> 2) == 5');
  assertTrue(result, '20 >> 2 should equal 5 (divide by 4)');
});

await test('6.2 Right shift by 1', () => {
  const result = evaluateConditionString('(14 >> 1) == 7');
  assertTrue(result, 'n >> 1 halves the value');
});

await test('6.3 Right shift by 0', () => {
  const result = evaluateConditionString('(42 >> 0) == 42');
  assertTrue(result, 'Shifting by 0 returns same value');
});

await test('6.4 Right shift to zero', () => {
  const result = evaluateConditionString('(5 >> 10) == 0');
  assertTrue(result, 'Shifting right more than bit width gives 0');
});

await test('6.5 Right shift in expression', () => {
  const result = evaluateConditionString('((32 >> 2) - 3) == 5');
  assertTrue(result, '(32 >> 2) = 8, - 3 = 5');
});

await test('6.6 Chained right shifts', () => {
  const result = evaluateConditionString('((64 >> 2) >> 2) == 4');
  assertTrue(result, '((64 >> 2) >> 2) = (16 >> 2) = 4');
});

// ============================================================================
// Section 7: Combined Operations
// ============================================================================

console.log('\n📋 Section 7: Combined Bitwise Operations\n');

await test('7.1 AND and OR together', () => {
  const result = evaluateConditionString('((0xFF & 0x0F) | 0xF0) == 0xFF');
  assertTrue(result, 'Combining AND and OR');
});

await test('7.2 Shift and AND mask', () => {
  const result = evaluateConditionString('((0x1234 >> 8) & 0xFF) == 0x12');
  assertTrue(result, 'Extract high byte using shift and mask');
});

await test('7.3 Shift and OR combine', () => {
  const result = evaluateConditionString('((0x12 << 8) | 0x34) == 0x1234');
  assertTrue(result, 'Combine bytes using shift and OR');
});

await test('7.4 XOR and NOT', () => {
  const result = evaluateConditionString('((~0x0F & 0xFF) ^ 0xFF) == 0x0F');
  assertTrue(result, 'Complex bitwise expression');
});

await test('7.5 All operators together', () => {
  const result = evaluateConditionString('(((5 << 2) | 3) & ~1) == 22');
  assertTrue(result, '((5 << 2) | 3) & ~1 = (20 | 3) & ~1 = 23 & 0xFFFFFFFE = 22');
});

await test('7.6 Bit extraction with shifts', () => {
  const result = evaluateConditionString('(((0xABCD >> 4) & 0x0F) == 0x0C)');
  assertTrue(result, 'Extract nibble from middle of number');
});

await test('7.7 Bit flag checking', () => {
  const result = evaluateConditionString('((0x05 & 0x01) == 0x01) and ((0x05 & 0x04) == 0x04)');
  assertTrue(result, 'Check multiple bit flags');
});

await test('7.8 Creating bitmask', () => {
  const result = evaluateConditionString('((1 << 4) - 1) == 0x0F');
  assertTrue(result, 'Create 4-bit mask using shift');
});

// ============================================================================
// Section 8: Operator Precedence
// ============================================================================

console.log('\n📋 Section 8: Operator Precedence\n');

await test('8.1 Shift has higher precedence than OR', () => {
  const result = evaluateConditionString('(1 | 2 << 2) == 9');
  assertTrue(result, '1 | (2 << 2) = 1 | 8 = 9');
});

await test('8.2 AND has higher precedence than OR', () => {
  const result = evaluateConditionString('(1 | 2 & 4) == 1');
  assertTrue(result, '1 | (2 & 4) = 1 | 0 = 1');
});

await test('8.3 XOR between AND and OR precedence', () => {
  // Precedence: & > ^ > |
  // So: 8 | 4 ^ 2 & 6 = 8 | (4 ^ (2 & 6)) = 8 | (4 ^ 2) = 8 | 6 = 14
  const result = evaluateConditionString('(8 | 4 ^ 2 & 6) == 14');
  assertTrue(result, '8 | (4 ^ (2 & 6)) = 8 | (4 ^ 2) = 8 | 6 = 14');
});

await test('8.4 Parentheses override precedence', () => {
  const result = evaluateConditionString('((1 | 2) << 2) == 12');
  assertTrue(result, '(1 | 2) << 2 = 3 << 2 = 12');
});

await test('8.5 NOT has highest precedence', () => {
  const result = evaluateConditionString('(~0 & 1) == 1');
  assertTrue(result, '(~0) & 1, NOT evaluated first');
});

await test('8.6 Arithmetic has higher precedence than bitwise', () => {
  const result = evaluateConditionString('(1 | 2 + 2) == 5');
  assertTrue(result, '1 | (2 + 2) = 1 | 4 = 5');
});

// ============================================================================
// Section 9: Real-World Use Cases
// ============================================================================

console.log('\n📋 Section 9: Real-World Use Cases\n');

await test('9.1 Check if bit flag is set', () => {
  const result = evaluateConditionString('(0x0105 & 0x0001) != 0');
  assertTrue(result, 'Check if bit 0 is set');
});

await test('9.2 Extract byte from integer', () => {
  const result = evaluateConditionString('((0x12345678 >> 16) & 0xFF) == 0x34');
  assertTrue(result, 'Extract third byte');
});

await test('9.3 Align to boundary', () => {
  const result = evaluateConditionString('(123 & ~3) == 120');
  assertTrue(result, 'Align to 4-byte boundary');
});

await test('9.4 Toggle bits', () => {
  const result = evaluateConditionString('(0xAA ^ 0xFF) == 0x55');
  assertTrue(result, 'Toggle all bits in byte');
});

await test('9.5 Power of 2 check', () => {
  const result = evaluateConditionString('(16 & (16 - 1)) == 0');
  assertTrue(result, 'Check if number is power of 2');
});

await test('9.6 Combine RGB values', () => {
  const result = evaluateConditionString('((0xFF << 16) | (0x80 << 8) | 0x40) == 0xFF8040');
  assertTrue(result, 'Combine R=255, G=128, B=64');
});

await test('9.7 Check multiple flags at once', () => {
  const result = evaluateConditionString('((0x07 & 0x05) == 0x05)');
  assertTrue(result, 'Check if bits 0 and 2 are both set in 0x07');
});

await test('9.8 Clear specific bits', () => {
  const result = evaluateConditionString('(0xFF & ~0x0F) == 0xF0');
  assertTrue(result, 'Clear lower 4 bits');
});

await test('9.9 Set specific bits', () => {
  const result = evaluateConditionString('(0xF0 | 0x05) == 0xF5');
  assertTrue(result, 'Set bits 0 and 2');
});

await test('9.10 Swap nibbles', () => {
  const result = evaluateConditionString('(((0xAB & 0x0F) << 4) | ((0xAB & 0xF0) >> 4)) == 0xBA');
  assertTrue(result, 'Swap high and low nibbles');
});

// ============================================================================
// Section 10: Edge Cases
// ============================================================================

console.log('\n📋 Section 10: Edge Cases\n');

await test('10.1 Large shift values', () => {
  const result = evaluateConditionString('(1 << 30) > 0');
  assertTrue(result, 'Large left shift');
});

await test('10.2 Negative numbers with shifts', () => {
  const result = evaluateConditionString('(-8 >> 2) == -2');
  assertTrue(result, 'Right shift on negative preserves sign');
});

await test('10.3 Multiple NOTs', () => {
  const result = evaluateConditionString('(~~~42 & 0xFF) == (~42 & 0xFF)');
  assertTrue(result, 'Odd number of NOTs');
});

await test('10.4 Zero in all operations', () => {
  const result = evaluateConditionString('((0 | 0) & 0) == 0');
  assertTrue(result, 'Operations with zero');
});

await test('10.5 Maximum shift left', () => {
  const result = evaluateConditionString('(1 << 31) < 0');
  assertTrue(result, 'Shift into sign bit makes negative');
});

// ============================================================================
// SUMMARY
// ============================================================================
printSummary();
