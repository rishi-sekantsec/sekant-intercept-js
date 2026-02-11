/**
 * Comprehensive test suite for YARA Math Module
 * 
 * Tests all mathematical and statistical functions:
 * - Entropy calculations
 * - Monte Carlo Pi estimation
 * - Serial correlation
 * - Statistical functions (mean, deviation, min, max, mode)
 * - Counting and percentage functions
 * - Utility functions (abs, to_number, in_range)
 */

import { createMathModule, math } from '../src/mathModule.mjs';
import { test, assertEquals, assertInRange, printSummary, printSection } from './testingFramework.mjs';

function assertThrows(fn, message = '') {
  try {
    fn();
    throw new Error(message || 'Expected function to throw');
  } catch (error) {
    if (error.message.includes('Expected function to throw')) {
      throw error;
    }
    // Expected error, test passes
  }
}

console.log('='.repeat(70));
console.log('YARA Math Module - Comprehensive Test Suite');
console.log('='.repeat(70));

// =============================================================================
// Section 1: Entropy Tests
// =============================================================================
console.log('\n📦 Section 1: Entropy Calculations');

await test('1.1: Entropy of all zeros (minimum entropy)', () => {
  const data = new Uint8Array(100).fill(0);
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 100);
  assertEquals(entropy, 0.0, 'All same values should have 0 entropy');
});

await test('1.2: Entropy of all same value', () => {
  const data = new Uint8Array(100).fill(255);
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 100);
  assertEquals(entropy, 0.0);
});

await test('1.3: Entropy of alternating values', () => {
  const data = new Uint8Array(100);
  for (let i = 0; i < 100; i++) {
    data[i] = i % 2 === 0 ? 0 : 255;
  }
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 100);
  // Perfect alternating pattern has entropy = 1.0
  assertEquals(entropy, 1.0);
});

await test('1.4: Entropy of random-like data', () => {
  const data = new Uint8Array(1000);
  for (let i = 0; i < 1000; i++) {
    data[i] = i % 256;
  }
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 1000);
  // Uniform distribution should have high entropy (close to 8.0)
  assertInRange(entropy, 7.9, 8.0);
});

await test('1.5: Entropy of string (standalone function)', () => {
  const entropy = math.entropy('aaaa');
  assertEquals(entropy, 0.0, 'Repeated characters have 0 entropy');
});

await test('1.6: Entropy of string with variety', () => {
  const entropy = math.entropy('abcd');
  // 4 different characters, each appearing once: -4*(0.25*log2(0.25)) = 2.0
  assertEquals(entropy, 2.0);
});

await test('1.7: Entropy of empty region', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 0);
  assertEquals(entropy, 0.0);
});

await test('1.8: Entropy of partial data', () => {
  const data = new Uint8Array([0, 0, 0, 0, 255, 255, 255, 255]);
  const mathModule = createMathModule(data);
  const entropy1 = mathModule.entropy(0, 4); // All zeros
  const entropy2 = mathModule.entropy(0, 8); // Mixed
  assertEquals(entropy1, 0.0);
  assertEquals(entropy2, 1.0);
});

// =============================================================================
// Section 2: Monte Carlo Pi Estimation
// =============================================================================
console.log('\n📦 Section 2: Monte Carlo Pi Estimation');

await test('2.1: Monte Carlo Pi with large uniform data', () => {
  const data = new Uint8Array(10000);
  for (let i = 0; i < 10000; i++) {
    data[i] = Math.floor(Math.random() * 256);
  }
  const mathModule = createMathModule(data);
  const pi = mathModule.monte_carlo_pi(0, 10000);
  // Should be approximately 3.14159, but can vary
  assertInRange(pi, 2.5, 3.8, 'Monte Carlo Pi should be close to 3.14159');
});

await test('2.2: Monte Carlo Pi with small data', () => {
  const data = new Uint8Array([128, 128, 0, 0, 255, 255]);
  const mathModule = createMathModule(data);
  const pi = mathModule.monte_carlo_pi(0, 6);
  // With small data, result will vary but should be a valid number
  assertEquals(typeof pi, 'number');
});

await test('2.3: Monte Carlo Pi with insufficient data', () => {
  const data = new Uint8Array([128]);
  const mathModule = createMathModule(data);
  const pi = mathModule.monte_carlo_pi(0, 1);
  assertEquals(pi, 0.0, 'Single byte cannot estimate Pi');
});

// =============================================================================
// Section 3: Serial Correlation
// =============================================================================
console.log('\n📦 Section 3: Serial Correlation');

await test('3.1: Serial correlation of constant data', () => {
  const data = new Uint8Array(100).fill(128);
  const mathModule = createMathModule(data);
  const corr = mathModule.serial_correlation(0, 100);
  assertEquals(corr, 0.0, 'Constant data has no correlation');
});

await test('3.2: Serial correlation of ascending sequence', () => {
  const data = new Uint8Array(100);
  for (let i = 0; i < 100; i++) {
    data[i] = i;
  }
  const mathModule = createMathModule(data);
  const corr = mathModule.serial_correlation(0, 100);
  // Ascending sequence should have positive correlation
  assertInRange(corr, 0.5, 1.0);
});

await test('3.3: Serial correlation of alternating pattern', () => {
  const data = new Uint8Array(100);
  for (let i = 0; i < 100; i++) {
    data[i] = i % 2 === 0 ? 0 : 255;
  }
  const mathModule = createMathModule(data);
  const corr = mathModule.serial_correlation(0, 100);
  // Alternating pattern should have negative correlation
  assertInRange(corr, -1.0, -0.5);
});

await test('3.4: Serial correlation with insufficient data', () => {
  const data = new Uint8Array([128]);
  const mathModule = createMathModule(data);
  const corr = mathModule.serial_correlation(0, 1);
  assertEquals(corr, 0.0);
});

// =============================================================================
// Section 4: Mean and Deviation
// =============================================================================
console.log('\n📦 Section 4: Mean and Standard Deviation');

await test('4.1: Mean of all zeros', () => {
  const data = new Uint8Array(100).fill(0);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 100);
  assertEquals(mean, 0.0);
});

await test('4.2: Mean of all 255s', () => {
  const data = new Uint8Array(100).fill(255);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 100);
  assertEquals(mean, 255.0);
});

await test('4.3: Mean of mixed values', () => {
  const data = new Uint8Array([0, 100, 200]);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 3);
  assertEquals(mean, 100.0);
});

await test('4.4: Mean of 0 to 255 sequence', () => {
  const data = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    data[i] = i;
  }
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 256);
  assertEquals(mean, 127.5);
});

await test('4.5: Deviation of constant values', () => {
  const data = new Uint8Array(100).fill(128);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 100);
  const dev = mathModule.deviation(0, 100, mean);
  assertEquals(dev, 0.0);
});

await test('4.6: Deviation of known values', () => {
  const data = new Uint8Array([0, 100, 200]);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 3);
  const dev = mathModule.deviation(0, 3, mean);
  // Mean = 100, deviations: [-100, 0, 100]
  // Variance = (10000 + 0 + 10000) / 3 = 6666.67
  // StdDev = sqrt(6666.67) ≈ 81.65
  assertEquals(dev, 81.64965809277261, 'Standard deviation', 0.001);
});

await test('4.7: Mean and deviation of empty region', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  const mean = mathModule.mean(0, 0);
  const dev = mathModule.deviation(0, 0, mean);
  assertEquals(mean, 0.0);
  assertEquals(dev, 0.0);
});

// =============================================================================
// Section 5: Min and Max
// =============================================================================
console.log('\n📦 Section 5: Minimum and Maximum');

await test('5.1: Min of two integers', () => {
  const data = new Uint8Array(100).fill(128);
  const mathModule = createMathModule(data);
  const min = mathModule.min(128, 200);
  assertEquals(min, 128);
});

await test('5.2: Max of two integers', () => {
  const data = new Uint8Array(100).fill(128);
  const mathModule = createMathModule(data);
  const max = mathModule.max(128, 200);
  assertEquals(max, 200);
});

await test('5.3: Min of negative and positive', () => {
  const data = new Uint8Array([50, 10, 200, 5, 100]);
  const mathModule = createMathModule(data);
  const min = mathModule.min(-10, 5);
  assertEquals(min, -10);
});

await test('5.4: Max of negative and positive', () => {
  const data = new Uint8Array([50, 10, 200, 5, 100]);
  const mathModule = createMathModule(data);
  const max = mathModule.max(-10, 5);
  assertEquals(max, 5);
});

await test('5.5: Min and max with same values', () => {
  const data = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    data[i] = i;
  }
  const mathModule = createMathModule(data);
  const min = mathModule.min(100, 100);
  const max = mathModule.max(100, 100);
  assertEquals(min, 100);
  assertEquals(max, 100);
});

// =============================================================================
// Section 6: Count and Percentage
// =============================================================================
console.log('\n📦 Section 6: Count and Percentage');

await test('6.1: Count of specific byte', () => {
  const data = new Uint8Array([0, 1, 2, 1, 3, 1, 4]);
  const mathModule = createMathModule(data);
  const count = mathModule.count(1, 0, 7);
  assertEquals(count, 3);
});

await test('6.2: Count of non-existent byte', () => {
  const data = new Uint8Array([0, 1, 2, 3, 4]);
  const mathModule = createMathModule(data);
  const count = mathModule.count(99, 0, 5);
  assertEquals(count, 0);
});

await test('6.3: Count of all same bytes', () => {
  const data = new Uint8Array(100).fill(255);
  const mathModule = createMathModule(data);
  const count = mathModule.count(255, 0, 100);
  assertEquals(count, 100);
});

await test('6.4: Percentage of byte', () => {
  const data = new Uint8Array([0, 1, 1, 1, 2]);
  const mathModule = createMathModule(data);
  const pct = mathModule.percentage(1, 0, 5);
  assertEquals(pct, 0.6); // 3 out of 5 = 60%
});

await test('6.5: Percentage of non-existent byte', () => {
  const data = new Uint8Array([0, 1, 2, 3, 4]);
  const mathModule = createMathModule(data);
  const pct = mathModule.percentage(99, 0, 5);
  assertEquals(pct, 0.0);
});

await test('6.6: Percentage of all bytes', () => {
  const data = new Uint8Array(100).fill(255);
  const mathModule = createMathModule(data);
  const pct = mathModule.percentage(255, 0, 100);
  assertEquals(pct, 1.0); // 100%
});

// =============================================================================
// Section 7: Mode
// =============================================================================
console.log('\n📦 Section 7: Mode (Most Common Value)');

await test('7.1: Mode of uniform data', () => {
  const data = new Uint8Array(100).fill(42);
  const mathModule = createMathModule(data);
  const mode = mathModule.mode(0, 100);
  assertEquals(mode, 42);
});

await test('7.2: Mode with clear winner', () => {
  const data = new Uint8Array([1, 2, 2, 2, 3, 4]);
  const mathModule = createMathModule(data);
  const mode = mathModule.mode(0, 6);
  assertEquals(mode, 2);
});

await test('7.3: Mode of tie (returns first)', () => {
  const data = new Uint8Array([1, 1, 2, 2]);
  const mathModule = createMathModule(data);
  const mode = mathModule.mode(0, 4);
  // Should return the first mode (1 or 2)
  assertEquals(typeof mode, 'number');
  assertInRange(mode, 0, 255);
});

await test('7.4: Mode of single value', () => {
  const data = new Uint8Array([42]);
  const mathModule = createMathModule(data);
  const mode = mathModule.mode(0, 1);
  assertEquals(mode, 42);
});

// =============================================================================
// Section 8: Utility Functions
// =============================================================================
console.log('\n📦 Section 8: Utility Functions (abs, to_number, in_range)');

await test('8.1: Absolute value - positive', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.abs(42), 42);
  assertEquals(math.abs(42), 42);
});

await test('8.2: Absolute value - negative', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.abs(-42), 42);
  assertEquals(math.abs(-42), 42);
});

await test('8.3: Absolute value - zero', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.abs(0), 0);
  assertEquals(math.abs(0), 0);
});

await test('8.4: to_number - true', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.to_number(true), 1);
  assertEquals(math.to_number(true), 1);
});

await test('8.5: to_number - false', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.to_number(false), 0);
  assertEquals(math.to_number(false), 0);
});

await test('8.6: in_range - inside', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.in_range(5, 0, 10), true);
  assertEquals(math.in_range(5, 0, 10), true);
});

await test('8.7: in_range - below', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.in_range(-1, 0, 10), false);
  assertEquals(math.in_range(-1, 0, 10), false);
});

await test('8.8: in_range - above', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.in_range(11, 0, 10), false);
  assertEquals(math.in_range(11, 0, 10), false);
});

await test('8.9: in_range - boundary lower', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.in_range(0, 0, 10), true);
  assertEquals(math.in_range(0, 0, 10), true);
});

await test('8.10: in_range - boundary upper', () => {
  const data = new Uint8Array(1);
  const mathModule = createMathModule(data);
  assertEquals(mathModule.in_range(10, 0, 10), true);
  assertEquals(math.in_range(10, 0, 10), true);
});

// =============================================================================
// Section 9: Error Handling
// =============================================================================
console.log('\n📦 Section 9: Error Handling');

await test('9.1: Invalid range - negative offset', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  assertThrows(() => mathModule.mean(-1, 10));
});

await test('9.2: Invalid range - negative size', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  assertThrows(() => mathModule.mean(0, -10));
});

await test('9.3: Invalid range - exceeds buffer (best effort)', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  // YARA does best effort, doesn't throw
  const result = mathModule.mean(0, 101);
  assertEquals(typeof result, 'number');
});

await test('9.4: Invalid range - offset + size exceeds (best effort)', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  // YARA does best effort, doesn't throw
  const result = mathModule.mean(90, 20);
  assertEquals(typeof result, 'number');
});

await test('9.5: Invalid byte value - negative', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  assertThrows(() => mathModule.count(-1, 0, 100));
});

await test('9.6: Invalid byte value - too large', () => {
  const data = new Uint8Array(100);
  const mathModule = createMathModule(data);
  assertThrows(() => mathModule.count(256, 0, 100));
});

await test('9.7: createMathModule with null', () => {
  assertThrows(() => createMathModule(null));
});

await test('9.8: createMathModule with non-Uint8Array', () => {
  assertThrows(() => createMathModule([1, 2, 3]));
});

// =============================================================================
// Section 10: Real-world Scenarios
// =============================================================================
console.log('\n📦 Section 10: Real-world Scenarios');

await test('10.1: Detect high entropy (encrypted/compressed data)', () => {
  // Simulate encrypted data with uniform distribution
  const data = new Uint8Array(1000);
  for (let i = 0; i < 1000; i++) {
    data[i] = i % 256;
  }
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 1000);
  // High entropy indicates encryption/compression
  assertInRange(entropy, 7.5, 8.0, 'Encrypted data should have high entropy');
});

await test('10.2: Detect low entropy (repetitive data)', () => {
  // Simulate repetitive data
  const data = new Uint8Array(1000);
  for (let i = 0; i < 1000; i++) {
    data[i] = i % 10; // Only 10 different values
  }
  const mathModule = createMathModule(data);
  const entropy = mathModule.entropy(0, 1000);
  // Low entropy indicates repetitive/structured data
  assertInRange(entropy, 3.0, 3.5, 'Repetitive data should have low entropy');
});

await test('10.3: Statistical analysis of file header', () => {
  // PE header: "MZ" followed by data
  const data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const mathModule = createMathModule(data);
  
  const mean = mathModule.mean(0, 8);
  const min = mathModule.min(10, 50);  // min/max take two ints
  const max = mathModule.max(10, 50);
  const entropy = mathModule.entropy(0, 8);
  
  assertEquals(typeof mean, 'number');
  assertEquals(min, 10);
  assertEquals(max, 50);
  assertInRange(entropy, 0, 8);
});

await test('10.4: Byte frequency analysis', () => {
  const data = new Uint8Array(1000).fill(0x41); // All 'A'
  const mathModule = createMathModule(data);
  
  const pct = mathModule.percentage(0x41, 0, 1000);
  const mode = mathModule.mode(0, 1000);
  
  assertEquals(pct, 1.0, 'All bytes should be 0x41');
  assertEquals(mode, 0x41, 'Mode should be 0x41');
});

// =============================================================================
// Test Summary
// =============================================================================

printSummary();
