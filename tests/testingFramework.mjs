/**
 * Unified Testing Framework for YARA Implementation
 * 
 * Provides consistent test infrastructure across all test files:
 * - Test runner with pass/fail tracking
 * - Common assertion functions
 * - Consistent output formatting
 * - Summary reporting
 * 
 * Usage:
 * ```javascript
 * import { test, assertEquals, assertTrue, printSummary } from './testingFramework.mjs';
 * 
 * await test('My test', async () => {
 *   assertEquals(1 + 1, 2, 'Math should work');
 * });
 * 
 * printSummary();
 * ```
 */

import process from 'node:process';

// Test state tracking
let testCount = 0;
let passCount = 0;
let failCount = 0;

/**
 * Reset test counters (useful for test runners)
 */
export function resetTestCounters() {
  testCount = 0;
  passCount = 0;
  failCount = 0;
}

/**
 * Get current test statistics
 */
export function getTestStats() {
  return {
    total: testCount,
    passed: passCount,
    failed: failCount,
    successRate: testCount > 0 ? (passCount / testCount * 100).toFixed(1) : '0.0'
  };
}

/**
 * Main test runner function
 * Auto-detects sync vs async functions and handles both correctly
 */
export async function test(description, fn) {
  testCount++;
  try {
    const result = fn();
    // If the function returns a promise, await it
    if (result && typeof result.then === 'function') {
      await result;
    }
    passCount++;
    console.log(`✓ ${description}`);
    return true;
  } catch (error) {
    failCount++;
    console.error(`✗ ${description}`);
    console.error(`  Error: ${error.message}`);
    if (error.expected !== undefined) {
      console.error(`  Expected: ${error.expected}`);
      console.error(`  Got: ${error.actual}`);
    }
    if (error.stack && process.env.VERBOSE_ERRORS) {
      console.error(`  Stack: ${error.stack.split('\n').slice(1, 3).join('\n')}`);
    }
    return false;
  }
}

/**
 * Async test runner function for tests with async operations
 * Must be awaited: await asyncTest('description', async () => { ... })
 */
export async function asyncTest(description, fn) {
  testCount++;
  try {
    await fn();
    passCount++;
    console.log(`✓ ${description}`);
    return true;
  } catch (error) {
    failCount++;
    console.error(`✗ ${description}`);
    console.error(`  Error: ${error.message}`);
    if (error.expected !== undefined) {
      console.error(`  Expected: ${error.expected}`);
      console.error(`  Got: ${error.actual}`);
    }
    if (error.stack && process.env.VERBOSE_ERRORS) {
      console.error(`  Stack: ${error.stack.split('\n').slice(1, 3).join('\n')}`);
    }
    return false;
  }
}

/**
 * Numbered test runner (e.g., "✓ 1. Test description")
 * Synchronous version - for async tests, wrap in asyncTest
 */
export function numberedTest(description, fn) {
  const testNum = testCount + 1;
  try {
    fn();
    passCount++;
    testCount++;
    console.log(`✓ ${testNum}. ${description}`);
    return true;
  } catch (error) {
    failCount++;
    testCount++;
    console.error(`✗ ${testNum}. ${description}`);
    console.error(`  Error: ${error.message}`);
    if (error.expected !== undefined) {
      console.error(`  Expected: ${error.expected}`);
      console.error(`  Got: ${error.actual}`);
    }
    return false;
  }
}

// ============================================================================
// ASSERTION FUNCTIONS
// ============================================================================

/**
 * Basic assertion - throws if condition is false
 */
export function assert(condition, message = 'Assertion failed') {
  if (!condition) {
    throw new Error(message);
  }
}

/**
 * Assert two values are equal (uses strict equality)
 */
export function assertEquals(actual, expected, message = '') {
  if (actual !== expected) {
    const error = new Error(message || `Expected ${expected}, got ${actual}`);
    error.expected = expected;
    error.actual = actual;
    throw error;
  }
}

/**
 * Assert two values are equal with tolerance (for floating point)
 */
export function assertEqualsWithTolerance(actual, expected, tolerance = 0.0001, message = '') {
  const diff = Math.abs(actual - expected);
  if (diff > tolerance) {
    const error = new Error(message || `Expected ${expected} ±${tolerance}, got ${actual} (diff: ${diff})`);
    error.expected = expected;
    error.actual = actual;
    throw error;
  }
}

/**
 * Assert value is true
 */
export function assertTrue(value, message = '') {
  if (!value) {
    const error = new Error(message || `Expected true, got ${value}`);
    error.expected = true;
    error.actual = value;
    throw error;
  }
}

/**
 * Assert value is false
 */
export function assertFalse(value, message = '') {
  if (value) {
    const error = new Error(message || `Expected false, got ${value}`);
    error.expected = false;
    error.actual = value;
    throw error;
  }
}

/**
 * Assert array has specific length
 */
export function assertArrayLength(arr, expectedLength, message = '') {
  if (!Array.isArray(arr)) {
    throw new Error(message || `Expected array, got ${typeof arr}`);
  }
  if (arr.length !== expectedLength) {
    const error = new Error(message || `Expected array length ${expectedLength}, got ${arr.length}`);
    error.expected = expectedLength;
    error.actual = arr.length;
    throw error;
  }
}

/**
 * Assert array contains a value
 */
export function assertContains(arr, value, message = '') {
  if (!arr.includes(value)) {
    throw new Error(message || `Array does not contain ${value}`);
  }
}

/**
 * Assert value is greater than minimum
 */
export function assertGreaterThan(actual, min, message = '') {
  if (actual <= min) {
    const error = new Error(message || `Expected > ${min}, got ${actual}`);
    error.expected = `> ${min}`;
    error.actual = actual;
    throw error;
  }
}

/**
 * Assert value is less than maximum
 */
export function assertLessThan(actual, max, message = '') {
  if (actual >= max) {
    const error = new Error(message || `Expected < ${max}, got ${actual}`);
    error.expected = `< ${max}`;
    error.actual = actual;
    throw error;
  }
}

/**
 * Assert value is within range (inclusive)
 */
export function assertInRange(actual, min, max, message = '') {
  if (actual < min || actual > max) {
    const error = new Error(message || `Expected value in range [${min}, ${max}], got ${actual}`);
    error.expected = `[${min}, ${max}]`;
    error.actual = actual;
    throw error;
  }
}

/**
 * Assert object has property
 */
export function assertHasProperty(obj, prop, message = '') {
  if (!Object.prototype.hasOwnProperty.call(obj, prop)) {
    throw new Error(message || `Missing property: ${prop}`);
  }
}

/**
 * Assert string matches regex pattern
 */
export function assertMatch(str, regex, message = '') {
  if (!regex.test(str)) {
    throw new Error(message || `String "${str}" does not match pattern ${regex}`);
  }
}

/**
 * Assert function throws an error
 */
export function assertThrows(fn, message = '') {
  try {
    fn();
    throw new Error(message || 'Expected function to throw an error');
  } catch (error) {
    if (error.message.includes('Expected function to throw')) {
      throw error;
    }
    // Expected error, test passes
  }
}

/**
 * Assert async function throws an error
 */
export async function assertThrowsAsync(fn, message = '') {
  try {
    await fn();
    throw new Error(message || 'Expected async function to throw an error');
  } catch (error) {
    if (error.message.includes('Expected async function to throw')) {
      throw error;
    }
    // Expected error, test passes
  }
}

// ============================================================================
// YARA-SPECIFIC ASSERTIONS
// ============================================================================

/**
 * Assert match count for YARA string matching
 */
export function assertMatchCount(matches, expectedCount, message = '') {
  if (matches.length !== expectedCount) {
    const error = new Error(message || `Expected ${expectedCount} matches, got ${matches.length}`);
    error.expected = expectedCount;
    error.actual = matches.length;
    throw error;
  }
}

/**
 * Assert match exists at specific offset
 */
export function assertMatchAt(matches, offset, message = '') {
  const found = matches.some(m => m.offset === offset);
  if (!found) {
    const offsets = matches.map(m => m.offset).join(', ');
    throw new Error(message || `Expected match at offset ${offset}, found at: ${offsets}`);
  }
}

/**
 * Assert minimum number of matches
 */
export function assertMinMatches(matches, minCount, message = '') {
  if (matches.length < minCount) {
    const error = new Error(message || `Expected at least ${minCount} matches, got ${matches.length}`);
    error.expected = `>= ${minCount}`;
    error.actual = matches.length;
    throw error;
  }
}

/**
 * Assert matches contain specific IDs
 */
export function assertMatchesContain(matches, expectedIds, message = '') {
  const matchIds = matches.map(m => m.id);
  const missing = expectedIds.filter(id => !matchIds.includes(id));
  if (missing.length > 0) {
    throw new Error(message || `Missing expected match IDs: ${missing.join(', ')}`);
  }
}

/**
 * Assert two values are deeply equal (for objects/arrays)
 */
export function assertDeepEquals(actual, expected, message = '') {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const error = new Error(message || 'Objects are not deeply equal');
    error.expected = expected;
    error.actual = actual;
    throw error;
  }
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

/**
 * Print a section header
 */
export function printSection(title) {
  console.log(`\n${'='.repeat(70)}`);
  console.log(`${title}`);
  console.log('='.repeat(70));
}

/**
 * Print a subsection header
 */
export function printSubsection(title) {
  console.log(`\n${title}`);
  console.log('-'.repeat(70));
}

/**
 * Print test summary at the end
 */
export function printSummary() {
  const stats = getTestStats();
  console.log('\n' + '='.repeat(70));
  console.log('TEST SUMMARY');
  console.log('='.repeat(70));
  console.log(`Total tests: ${stats.total}`);
  console.log(`Passed: ${stats.passed} (${stats.successRate}%)`);
  console.log(`Failed: ${stats.failed}`);
  console.log('='.repeat(70));
  
  if (stats.failed > 0) {
    console.log(`⚠️  ${stats.failed} test(s) failed`);
    process.exit(1);
  } else {
    console.log('✅ All tests passed!');
    process.exit(0);
  }
}

/**
 * Print test summary without exiting (for test runners)
 */
export function printSummaryNoExit() {
  const stats = getTestStats();
  console.log('\n' + '='.repeat(70));
  console.log('TEST SUMMARY');
  console.log('='.repeat(70));
  console.log(`Total tests: ${stats.total}`);
  console.log(`Passed: ${stats.passed} (${stats.successRate}%)`);
  console.log(`Failed: ${stats.failed}`);
  console.log('='.repeat(70));
  
  if (stats.failed > 0) {
    console.log(`⚠️  ${stats.failed} test(s) failed\n`);
  } else {
    console.log('✅ All tests passed!\n');
  }
  
  return stats.failed === 0;
}
