/**
 * Vitest Compatibility Wrapper for Existing YARA Tests
 *
 * Keeps your existing API:
 *   - test()
 *   - asyncTest()
 *   - assertEquals()
 *   - assertTrue()
 *   - etc.
 *
 * Internally delegates everything to Vitest.
 */

import {
  test as vitestTest,
  describe,
  expect,
  beforeEach,
  afterEach
} from 'vitest'

// ============================================================================
// TEST RUNNER WRAPPERS
// ============================================================================

export function resetTestCounters() {
  // No-op — Vitest manages state
}

export function getTestStats() {
  // Not supported in Vitest — return dummy
  return {
    total: 0,
    passed: 0,
    failed: 0,
    successRate: '100.0'
  }
}

/**
 * Main test wrapper
 */
export function test(description, fn) {
  return vitestTest(description, async () => {
    return await fn()
  })
}

/**
 * Async test wrapper (alias)
 */
export function asyncTest(description, fn) {
  return vitestTest(description, async () => {
    return await fn()
  })
}

/**
 * Numbered test wrapper
 */
let testCounter = 0
export function numberedTest(description, fn) {
  testCounter++
  return vitestTest(`${testCounter}. ${description}`, async () => {
    return await fn()
  })
}

// ============================================================================
// ASSERTION FUNCTIONS (Mapped to Vitest expect())
// ============================================================================

export function assert(condition, message = 'Assertion failed') {
  expect(condition, message).toBeTruthy()
}

export function assertEquals(actual, expected, message = '') {
  expect(actual, message).toBe(expected)
}

export function assertDeepEquals(actual, expected, message = '') {
  expect(actual, message).toEqual(expected)
}

export function assertEqualsWithTolerance(
  actual,
  expected,
  tolerance = 0.0001,
  message = ''
) {
  const precision = Math.abs(Math.log10(tolerance))
  expect(actual, message).toBeCloseTo(expected, precision)
}

export function assertTrue(value, message = '') {
  expect(value, message).toBe(true)
}

export function assertFalse(value, message = '') {
  expect(value, message).toBe(false)
}

export function assertArrayLength(arr, expectedLength, message = '') {
  expect(arr, message).toHaveLength(expectedLength)
}

export function assertContains(arr, value, message = '') {
  expect(arr, message).toContain(value)
}

export function assertGreaterThan(actual, min, message = '') {
  expect(actual, message).toBeGreaterThan(min)
}

export function assertLessThan(actual, max, message = '') {
  expect(actual, message).toBeLessThan(max)
}

export function assertInRange(actual, min, max, message = '') {
  expect(actual, message).toBeGreaterThanOrEqual(min)
  expect(actual, message).toBeLessThanOrEqual(max)
}

export function assertHasProperty(obj, prop, message = '') {
  expect(obj, message).toHaveProperty(prop)
}

export function assertMatch(str, regex, message = '') {
  expect(str, message).toMatch(regex)
}

export function assertThrows(fn, message = '') {
  expect(fn, message).toThrow()
}

export async function assertThrowsAsync(fn, message = '') {
  await expect(fn(), message).rejects.toThrow()
}

// ============================================================================
// YARA-SPECIFIC ASSERTIONS
// ============================================================================

export function assertMatchCount(matches, expectedCount, message = '') {
  expect(matches, message).toHaveLength(expectedCount)
}

export function assertMatchAt(matches, offset, message = '') {
  expect(
    matches.some(m => m.offset === offset),
    message || `Expected match at offset ${offset}`
  ).toBe(true)
}

export function assertMinMatches(matches, minCount, message = '') {
  expect(matches.length, message).toBeGreaterThanOrEqual(minCount)
}

export function assertMatchesContain(matches, expectedIds, message = '') {
  const matchIds = matches.map(m => m.id)
  for (const id of expectedIds) {
    expect(
      matchIds,
      message || `Missing expected match ID: ${id}`
    ).toContain(id)
  }
}

// ============================================================================
// OUTPUT FUNCTIONS (Now No-ops — Vitest Handles Reporting)
// ============================================================================

export function printSection(title) {
  // Optional: keep simple console output
  console.log(`\n=== ${title} ===`)
}

export function printSubsection(title) {
  console.log(`\n--- ${title} ---`)
}

export function printSummary() {
  // No-op — Vitest prints summary automatically
}

export function printSummaryNoExit() {
  return true
}