/**
 * Comprehensive tests for String Position & Offset Operators
 * Tests: at, in, @, ! operators
 *
 * These operators are critical for YARA rules - used in 65%+ of real-world rules
 */

import { InterceptScanner } from "../src/interceptScanner.mjs";
import { parseConditionToAST } from "../src/yaraConditionParser.mjs";
import { test, printSummary, printSection } from "./testingFramework.mjs";

// Test helper
function createTestData(text) {
  return new TextEncoder().encode(text);
}

printSection("STRING POSITION & OFFSET OPERATORS TEST SUITE");

// ============================================================================
// SECTION 1: Basic 'at' Operator Tests
// ============================================================================

console.log('\n📍 SECTION 1: Basic "at" Operator');
console.log("-".repeat(70));

// Test 1.1: String at specific offset
await test("1.1 String at beginning (offset 0)", async () => {
  const data = createTestData("MZThis is a test");
  const rule = `
    rule TestAtZero {
      strings:
        $sig = "MZ"
      condition:
        $sig at 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1 || results[0].rule !== "TestAtZero") {
    throw new Error(`Expected match at offset 0, got: ${JSON.stringify(results)}`);
  }
});

// Test 1.2: String at middle offset
await test("1.2 String at middle offset", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestAtMiddle {
      strings:
        $word = "World"
      condition:
        $word at 6
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match, got: ${JSON.stringify(results)}`);
  }
});

// Test 1.3: String NOT at specified offset (should not match)
await test("1.3 String NOT at specified offset", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestAtWrong {
      strings:
        $word = "World"
      condition:
        $word at 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 0) {
    throw new Error(`Should not match - wrong offset`);
  }
});

// Test 1.4: Multiple matches, checking specific occurrence
await test("1.4 String appears multiple times, at checks first", async () => {
  const data = createTestData("test test test");
  const rule = `
    rule TestMultipleAt {
      strings:
        $word = "test"
      condition:
        $word at 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match at first occurrence`);
  }
});

// Test 1.5: Using hex offset
await test("1.5 String at hex offset", async () => {
  const data = createTestData("0123456789ABCDEF");
  const rule = `
    rule TestAtHex {
      strings:
        $hex = "ABCDEF"
      condition:
        $hex at 0x0A
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match at hex offset 0x0A`);
  }
});

// ============================================================================
// SECTION 2: Range 'in' Operator Tests
// ============================================================================

console.log('\n📏 SECTION 2: Range "in" Operator');
console.log("-".repeat(70));

// Test 2.1: String in range (at start of range)
await test("2.1 String in range (at start)", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestInRangeStart {
      strings:
        $word = "World"
      condition:
        $word in (6..10)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match in range`);
  }
});

// Test 2.2: String in range (in middle of range)
await test("2.2 String in range (in middle)", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestInRangeMiddle {
      strings:
        $word = "World"
      condition:
        $word in (0..20)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match in range`);
  }
});

// Test 2.3: String NOT in range (before range)
await test("2.3 String NOT in range (before)", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestNotInRange {
      strings:
        $word = "Hello"
      condition:
        $word in (10..20)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 0) {
    throw new Error(`Should not match - outside range`);
  }
});

// Test 2.4: String in range with hex offsets
await test("2.4 String in range with hex offsets", async () => {
  const data = createTestData("0123456789ABCDEF");
  const rule = `
    rule TestInRangeHex {
      strings:
        $hex = "ABCDEF"
      condition:
        $hex in (0x00..0x10)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match in hex range`);
  }
});

// Test 2.5: Multiple matches, any in range
await test("2.5 Multiple matches, check if any in range", async () => {
  const data = createTestData("test middle test end");
  const rule = `
    rule TestMultipleInRange {
      strings:
        $word = "test"
      condition:
        $word in (10..20)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match - one occurrence in range`);
  }
});

// ============================================================================
// SECTION 3: Offset '@' Operator Tests
// ============================================================================

console.log('\n📌 SECTION 3: Offset "@" Operator');
console.log("-".repeat(70));

// Test 3.1: Get first match offset (@a)
await test("3.1 Get first match offset @a", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestOffsetFirst {
      strings:
        $word = "World"
      condition:
        @word == 6
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @word to equal 6`);
  }
});

// Test 3.2: Get second match offset (@a[2] - YARA 1-indexed)
await test("3.2 Get second match offset @a[2]", async () => {
  const data = createTestData("test and test");
  const rule = `
    rule TestOffsetSecond {
      strings:
        $word = "test"
      condition:
        @word[2] == 9
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @word[2] to equal 9`);
  }
});

// Test 3.3: Compare offsets
await test("3.3 Compare offsets (@a < @b)", async () => {
  const data = createTestData("first then second");
  const rule = `
    rule TestOffsetCompare {
      strings:
        $a = "first"
        $b = "second"
      condition:
        @a < @b
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @a < @b`);
  }
});

// Test 3.4: Offset in arithmetic expression
await test("3.4 Offset in arithmetic (@a + 5 == @b)", async () => {
  const data = createTestData("12345test");
  const rule = `
    rule TestOffsetArithmetic {
      strings:
        $a = "12345"
        $b = "test"
      condition:
        @a + 5 == @b
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @a + 5 == @b (0 + 5 == 5)`);
  }
});

// Test 3.5: Offset range check
await test("3.5 Offset in range (@a > 10 and @a < 20)", async () => {
  const data = createTestData("0123456789ABCDEF_TARGET_END");
  const rule = `
    rule TestOffsetRange {
      strings:
        $target = "TARGET"
      condition:
        @target > 10 and @target < 20
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @target in range 10-20`);
  }
});

// ============================================================================
// SECTION 4: Length '!' Operator Tests
// ============================================================================

console.log('\n📏 SECTION 4: Length "!" Operator');
console.log("-".repeat(70));

// Test 4.1: Get match length (!a)
await test("4.1 Get match length !a", async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestLength {
      strings:
        $word = "World"
      condition:
        !word == 5
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected !word to equal 5 (length of "World")`);
  }
});

// Test 4.2: Get second match length (!a[2] - YARA 1-indexed)
await test("4.2 Get second match length !a[2]", async () => {
  const data = createTestData("test and testing");
  const rule = `
    rule TestLengthSecond {
      strings:
        $word = /test(ing)?/
      condition:
        !word[2] >= 7
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected !word[2] >= 7`);
  }
});

// Test 4.3: Compare lengths
await test("4.3 Compare lengths (!a > !b)", async () => {
  const data = createTestData("longer and short");
  const rule = `
    rule TestLengthCompare {
      strings:
        $a = "longer"
        $b = "short"
      condition:
        !a > !b
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected !a (6) > !b (5)`);
  }
});

// Test 4.4: Length in arithmetic
await test("4.4 Length in arithmetic (@a + !a == @b)", async () => {
  const data = createTestData("AAAAtest");
  const rule = `
    rule TestLengthArithmetic {
      strings:
        $a = "AAAA"
        $b = "test"
      condition:
        @a + !a == @b
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @a + !a == @b (0 + 4 == 4)`);
  }
});

// ============================================================================
// SECTION 5: Combined Operator Tests
// ============================================================================

console.log("\n🔗 SECTION 5: Combined Operators");
console.log("-".repeat(70));

// Test 5.1: Combine 'at' with 'and'
await test('5.1 Combine "at" with "and"', async () => {
  const data = createTestData("MZSignature");
  const rule = `
    rule TestCombineAtAnd {
      strings:
        $mz = "MZ"
        $sig = "Signature"
      condition:
        $mz at 0 and $sig at 2
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected both conditions to match`);
  }
});

// Test 5.2: Combine '@' with 'at'
await test('5.2 Combine @ offset check with "at"', async () => {
  const data = createTestData("Header at start");
  const rule = `
    rule TestCombineOffsetAt {
      strings:
        $header = "Header"
      condition:
        $header at 0 and @header == 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected both offset checks to pass`);
  }
});

// Test 5.3: Combine 'in' with offset check
await test('5.3 Combine "in" range with offset arithmetic', async () => {
  const data = createTestData("0123456789target");
  const rule = `
    rule TestCombineInOffset {
      strings:
        $target = "target"
      condition:
        $target in (5..15) and @target == 10
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match in range with offset == 10`);
  }
});

// Test 5.4: Complex: offset, length, and position
await test('5.4 Complex: @, !, and "at" combined', async () => {
  const data = createTestData("Start123End");
  const rule = `
    rule TestComplex {
      strings:
        $start = "Start"
        $end = "End"
      condition:
        @start == 0 and !start == 5 and $end at 8
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected all conditions to match`);
  }
});

// Test 5.5: Multiple occurrences with indexed access (YARA 1-indexed)
await test("5.5 Multiple occurrences with indexed @, !", async () => {
  const data = createTestData("ab cd ef");
  const rule = `
    rule TestIndexed {
      strings:
        $pattern = /[a-z]{2}/
      condition:
        @pattern[1] == 0 and @pattern[2] == 3 and @pattern[3] == 6
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected indexed offset access`);
  }
});

// ============================================================================
// SECTION 6: Edge Cases
// ============================================================================

console.log("\n⚠️  SECTION 6: Edge Cases");
console.log("-".repeat(70));

// Test 6.1: String not found - 'at' should fail
await test('6.1 String not found - "at" returns false', async () => {
  const data = createTestData("Hello World");
  const rule = `
    rule TestNotFound {
      strings:
        $missing = "NotHere"
      condition:
        $missing at 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 0) {
    throw new Error(`Should not match - string not found`);
  }
});

// Test 6.2: Offset out of bounds (@a[99])
await test("6.2 Offset index out of bounds", async () => {
  const data = createTestData("test");
  const rule = `
    rule TestOutOfBounds {
      strings:
        $word = "test"
      condition:
        @word[99] == 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  // Should not match - index out of bounds returns undefined
  if (results.length !== 0) {
    throw new Error(`Should not match - index out of bounds`);
  }
});

// Test 6.3: Length of non-existent match
await test("6.3 Length of non-existent match", async () => {
  const data = createTestData("test");
  const rule = `
    rule TestNoMatchLength {
      strings:
        $missing = "absent"
      condition:
        !missing == 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  // undefined !== 0, so should not match
  if (results.length !== 0) {
    throw new Error(`Should not match - no match exists`);
  }
});

// Test 6.4: Zero offset (beginning of file)
await test("6.4 Zero offset handling", async () => {
  const data = createTestData("test");
  const rule = `
    rule TestZeroOffset {
      strings:
        $word = "test"
      condition:
        @word >= 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match at offset 0`);
  }
});

// Test 6.5: Large offset values
await test("6.5 Large offset values", async () => {
  const padding = "x".repeat(10000);
  const data = createTestData(padding + "target");
  const rule = `
    rule TestLargeOffset {
      strings:
        $target = "target"
      condition:
        @target > 9999
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected match at large offset`);
  }
});

// ============================================================================
// SECTION 7: Real-World YARA Patterns
// ============================================================================

console.log("\n🌍 SECTION 7: Real-World YARA Patterns");
console.log("-".repeat(70));

// Test 7.1: PE file detection (MZ at 0)
await test("7.1 PE file detection - MZ at 0", async () => {
  const data = createTestData("MZ\x90\x00\x03\x00\x00\x00");
  const rule = `
    rule TestPEDetection {
      strings:
        $mz = "MZ"
      condition:
        $mz at 0
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected PE signature at 0`);
  }
});

// Test 7.2: Check signature in header (first 1KB)
await test("7.2 Signature in header range", async () => {
  const header = "x".repeat(500) + "SECRET";
  const data = createTestData(header);
  const rule = `
    rule TestHeaderSig {
      strings:
        $sig = "SECRET"
      condition:
        $sig in (0..1024)
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected signature in header range`);
  }
});

// Test 7.3: Sequential strings (A before B)
await test("7.3 Sequential strings - A before B", async () => {
  const data = createTestData("First comes before Second");
  const rule = `
    rule TestSequential {
      strings:
        $a = "First"
        $b = "Second"
      condition:
        $a and $b and @a < @b
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected First before Second`);
  }
});

// Test 7.4: Fixed offset + fixed length check
await test("7.4 Fixed offset and fixed length", async () => {
  const data = createTestData("ABCD1234");
  const rule = `
    rule TestFixedOffsetLength {
      strings:
        $pattern = "1234"
      condition:
        $pattern at 4 and !pattern == 4
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected pattern at 4 with length 4`);
  }
});

// Test 7.5: String proximity check
await test("7.5 String proximity - within 10 bytes", async () => {
  const data = createTestData("Start12End");
  const rule = `
    rule TestProximity {
      strings:
        $a = "Start"
        $b = "End"
      condition:
        $a and $b and (@b - @a) < 10
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected strings within 10 bytes`);
  }
});

// ============================================================================
// SECTION 8: Bare #/@/! inside for..of loops, and non-YARA indexed forms
// ============================================================================
console.log('\n📍 SECTION 8: Bare #, @, ! in for..of loops');
console.log("-".repeat(70));

// Capture console output while scanning (a failing rule logs at debug level)
async function scanCapturingWarnings(rule, data) {
  const warnings = [];
  const originalWarn = console.warn;
  const originalDebug = console.debug;
  const originalTrace = console.trace;
  console.warn = (...args) => warnings.push(args.join(' '));
  console.debug = () => {};
  console.trace = () => {};
  try {
    const scanner = new InterceptScanner();
    scanner.addRules(rule);
    const results = await scanner.scan(data);
    return { results, warnings };
  } finally {
    console.warn = originalWarn;
    console.debug = originalDebug;
    console.trace = originalTrace;
  }
}

// Test 8.1: Bare ! refers to the current string's first match length
await test("8.1 Bare ! in for..of (match length)", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule BareLength {
      strings:
        $m = "password: "
      condition:
        for any of them : ( ! == 10 )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected bare "!" to resolve to the current string's length (10)`);
  }
});

// Test 8.2: Bare @ and # still work alongside bare !
await test("8.2 Bare @, # and ! in one for..of loop", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule BareAll {
      strings:
        $m = "password: "
      condition:
        for all of them : ( # == 2 and @ >= 0 and ! == 10 )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected bare #, @ and ! to all resolve for each string`);
  }
});

// Test 8.3: Indexed ! with the loop variable
await test("8.3 Indexed !a[i] with a loop variable", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule IndexedLengthLoop {
      strings:
        $m = "password: "
      condition:
        for all i in (1..#m) : ( !m[i] == 10 )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected !m[i] to return each occurrence's length`);
  }
});

// Test 8.4: Indexed @ with the loop variable
await test("8.4 Indexed @a[i] with a loop variable", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule IndexedOffsetLoop {
      strings:
        $m = "password: "
      condition:
        for all i in (1..#m) : ( @m[i] == (i - 1) * 10 )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @m[i] to return each occurrence's offset`);
  }
});

// Test 8.5: Indexed ! past the last match is undefined, so the rule does not match
await test("8.5 Indexed !a[i] out of range", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule IndexedLengthOutOfRange {
      strings:
        $m = "password: "
      condition:
        !m[3] == 10
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 0) {
    throw new Error(`Expected !m[3] on 2 matches to be undefined (no match)`);
  }
});

// Test 8.6: !a reports byte length, including for wide strings
await test("8.6 Length of a wide match is in bytes", async () => {
  const data = createTestData("a\u0000b\u0000");
  const rule = `
    rule WideLength {
      strings:
        $m = "ab" wide
      condition:
        $m and !m == 4
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected a wide "ab" match to report a length of 4 bytes`);
  }
});

// Test 8.7: $m[i] parses to a string occurrence (extension - YARA rejects the syntax)
await test("8.7 Extension: $m[i] parses to a string occurrence", async () => {
  const ast = parseConditionToAST("$m[2]");

  if (ast.type !== "stringOccurrence" || ast.identifier !== "$m" || ast.index !== 2) {
    throw new Error(`Expected { type: "stringOccurrence", identifier: "$m", index: 2 }; got ${JSON.stringify(ast)}`);
  }
});

// Test 8.8: #m[i] is not YARA - reported, and the rule fails closed
await test("8.8 #m[i] is rejected with a clear warning", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule UnsupportedCountIndex {
      strings:
        $m = "password: "
      condition:
        #m[1] == 2
    }
  `;

  const { results, warnings } = await scanCapturingWarnings(rule, data);

  if (results.length !== 0) {
    throw new Error(`Expected "#m[1]" to fail closed`);
  }
  if (!warnings.some((w) => w.includes('is not valid YARA') && w.includes('"#m[1]"'))) {
    throw new Error(`Expected a warning naming "#m[1]"; got: ${warnings.join(' | ')}`);
  }
});

// Test 8.9: Extension - !$ means the current string's length (YARA rejects this syntax)
await test("8.9 Extension: !$ resolves to the current string", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule AnonymousDollarLength {
      strings:
        $m = "password: "
      condition:
        for all of them : ( !$ == 10 )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected !$ to resolve to the current string's length (extension; YARA errors)`);
  }
});

// Test 8.10: Extension - index 0 means the first match (YARA makes @a[0] / !a[0] undefined)
await test("8.10 Extension: index 0 is the first match", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule IndexZeroFirstMatch {
      strings:
        $m = "password: "
      condition:
        @m[0] == 0 and !m[0] == 10
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected @m[0] / !m[0] to resolve to the first match (extension; YARA: undefined)`);
  }
});

// ============================================================================
// SECTION 9: $a[i] - the i-th matched substring (documented extension, not YARA)
// ============================================================================
console.log('\n📍 SECTION 9: $a[i] occurrence extension');
console.log("-".repeat(70));

// Test 9.1: The occurrence is the matched text
await test("9.1 $m[1] is the matched substring", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule OccurrenceText {
      strings:
        $m = "password: "
      condition:
        $m[1] == "password: "
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected $m[1] to equal the matched substring`);
  }
});

// Test 9.2: Occurrences compose with the string operators
await test("9.2 $m[i] composes with contains / matches / iequals", async () => {
  const checks = [
    { rule: '$m = "password: "', condition: '$m[2] contains "word"', data: "password: password: " },
    { rule: '$m = /password: v[0-9]/', condition: '$m[2] == "password: v1"', data: "password: v0\npassword: v1\n" },
    { rule: '$m = "ab" nocase', condition: '$m[2] iequals "AB"', data: "xxABxxab" },
  ];

  for (const check of checks) {
    const scanner = new InterceptScanner();
    scanner.addRules(`
      rule OccurrenceOps {
        strings:
          ${check.rule}
        condition:
          ${check.condition}
      }
    `);
    const results = await scanner.scan(createTestData(check.data));
    if (results.length !== 1) {
      throw new Error(`Expected ${check.rule} + ${check.condition} to match`);
    }
  }
});

// Test 9.3: Out-of-range occurrences are undefined
await test("9.3 $m[i] past the last match is undefined", async () => {
  const data = createTestData("password: password: ");
  const defined = `
    rule OccurrenceUndefined {
      strings:
        $m = "password: "
      condition:
        not defined $m[3]
    }
  `;
  const compared = `
    rule OccurrenceOutOfRange {
      strings:
        $m = "password: "
      condition:
        $m[3] == "password: "
    }
  `;

  const definedResult = await scanCapturingWarnings(defined, data);
  const comparedResult = await scanCapturingWarnings(compared, data);

  if (definedResult.results.length !== 1) {
    throw new Error(`Expected "not defined $m[3]" to match`);
  }
  if (comparedResult.results.length !== 0) {
    throw new Error(`Expected $m[3] to be undefined, so the comparison cannot match`);
  }
});

// Test 9.4: Bare $[i] addresses the current string, like bare @ / ! / #
await test("9.4 $[i] inside for..of uses the current string", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule OccurrenceInLoop {
      strings:
        $m = "password: "
      condition:
        for all of them : ( $[1] == "password: " )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected $[1] to resolve to the current string's first occurrence`);
  }
});

// Test 9.5: The index may be the loop variable
await test("9.5 $m[i] with a loop variable index", async () => {
  const data = createTestData("password: password: ");
  const rule = `
    rule OccurrenceLoopIndex {
      strings:
        $m = "password: "
      condition:
        for any i in (1..#m) : ( $m[i] matches /^password:/ )
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected $m[i] to accept the loop variable as its index`);
  }
});

// Test 9.6: Occurrences are byte-exact for wide matches
await test("9.6 $m[1] of a wide match returns the raw bytes", async () => {
  const data = createTestData("a\u0000b\u0000a\u0000b\u0000");
  const rule = `
    rule OccurrenceWide {
      strings:
        $m = "ab" wide
      condition:
        $m[2] matches /a.b/s
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected the second wide occurrence to match /a.b/s`);
  }
});

// Test 9.7: Occurrences work for hex strings, including wildcards
await test("9.7 $m[1] of a hex match includes wildcard bytes", async () => {
  const data = createTestData("ABXD");
  const rule = `
    rule OccurrenceHex {
      strings:
        $m = { 41 42 ?? 44 }
      condition:
        $m[1] == "ABXD" and !m[1] == 4
    }
  `;

  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(data);

  if (results.length !== 1) {
    throw new Error(`Expected the hex occurrence to be "ABXD" with length 4`);
  }
});

// ============================================================================
// Summary
// ============================================================================
printSummary();
