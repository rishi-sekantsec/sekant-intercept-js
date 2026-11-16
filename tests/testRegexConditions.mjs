/**
 * Comprehensive Test Suite for Regex Literals and the `matches` / `iequals` Operators
 *
 * Covers:
 * - Phase 1 literal masking of `/regex/flags` in condition expressions
 * - `matches` evaluation (case sensitivity, `i` and `s` modifiers, undefined operands)
 * - `iequals` evaluation
 * - Word-operator whitespace flexibility (tabs / newlines / multiple spaces)
 * - Loud failure for invalid regex literals and stray `/`
 * - End-to-end rule compilation with multi-line, tab-indented conditions
 */

import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { ConditionEvaluator, createScanFacts } from '../src/yaraConditionsMatch.mjs';
import { InterceptScanner } from '../src/interceptScanner.mjs';
import {
  test,
  assertTrue,
  assertFalse,
  assertEquals,
  printSection,
  printSummary,
} from './testingFramework.mjs';

const DATA = new TextEncoder().encode('sample');
const MODULES = {
  webmod: {
    url: 'HTTP://Evil.Example/path',
    multiline: 'a\nb',
    count: 3,
  },
};

function evaluateAst(ast) {
  return new ConditionEvaluator(createScanFacts(DATA, {}, MODULES)).evaluate(ast);
}

function evaluateCondition(condition) {
  return evaluateAst(parseConditionToAST(condition));
}

/**
 * Run `fn` while collecting console.warn output.
 * @returns {Promise<{warnings: string[], result: any}>}
 */
async function captureWarnings(fn) {
  const original = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  try {
    return { warnings, result: await fn() };
  } finally {
    console.warn = original;
  }
}

/**
 * Collect the error thrown by `fn`, or null when it did not throw.
 */
async function captureError(fn) {
  try {
    await fn();
    return null;
  } catch (error) {
    return error;
  }
}

function createScannerWithWebmod() {
  const scanner = new InterceptScanner();
  scanner.setModules({
    webmod: {
      getName: () => 'webmod',
      isLoaded: () => true,
      load: async () => {},
      initialize: async () => ({ url: MODULES.webmod.url }),
      createModule: (results) => ({ url: results.url }),
    },
  });
  return scanner;
}

/** Scan `ruleText` against `content`, returning matched rule names. */
async function scanRuleNames(ruleText, content = 'sample') {
  const scanner = createScannerWithWebmod();
  scanner.compile(ruleText);
  const originalDebug = console.debug;
  const originalTrace = console.trace;
  console.debug = () => {};
  console.trace = () => {};
  try {
    const results = await scanner.scan(Buffer.from(content));
    return results.map((result) => result.rule);
  } finally {
    console.debug = originalDebug;
    console.trace = originalTrace;
  }
}

printSection('REGEX LITERALS & matches/iequals TEST SUITE');

// ============================================================================
// Section 1: Parsing of `/regex/flags` operands
// ============================================================================

console.log('\n📋 Section 1: Parsing regex literals\n');

await test('1.1 `matches` produces a regex node with its flags', () => {
  const ast = parseConditionToAST('webmod.url matches /evil\\.example/i');
  assertEquals(ast.type, 'matches', 'operator node type');
  assertEquals(ast.right.type, 'regex', 'right operand node type');
  assertEquals(ast.right.pattern, 'evil\\.example', 'pattern text');
  assertEquals(ast.right.flags, 'i', 'flags');
  assertEquals(ast.right.error, undefined, 'valid literal carries no error');
});

await test('1.2 `i` and `s` modifiers can be combined', () => {
  const ast = parseConditionToAST('webmod.url matches /^http/is');
  assertEquals(ast.right.flags, 'is', 'combined flags');
});

await test('1.3 Operators inside a pattern stay part of the pattern', () => {
  const ast = parseConditionToAST('webmod.url matches /a and b \\^ c \\/ d/');
  assertEquals(ast.type, 'matches', 'and inside the pattern must not split the expression');
  assertEquals(ast.right.pattern, 'a and b \\^ c \\/ d', 'pattern preserved verbatim');
});

await test('1.4 Two regex literals on one line keep distinct patterns', () => {
  const ast = parseConditionToAST('webmod.url matches /a\\/b/ and webmod.url matches /c/i');
  assertEquals(ast.type, 'and', 'top level expression');
  assertEquals(ast.left.right.pattern, 'a\\/b', 'first pattern');
  assertEquals(ast.right.right.pattern, 'c', 'second pattern');
});

await test('1.5 A quote inside a pattern does not start a string literal', () => {
  const ast = parseConditionToAST('webmod.url matches /[a-z"]+/');
  assertEquals(ast.right.type, 'regex', 'right operand stays a regex');
  assertEquals(ast.right.pattern, '[a-z"]+', 'pattern keeps the quote');
});

// ============================================================================
// Section 2: Evaluating `matches`
// ============================================================================

console.log('\n📋 Section 2: Evaluating `matches`\n');

await test('2.1 Case-insensitive match succeeds', async () => {
  assertTrue(await evaluateCondition('webmod.url matches /evil\\.example/i'), 'case-insensitive match');
});

await test('2.2 Case-sensitive match fails on different case', async () => {
  assertFalse(await evaluateCondition('webmod.url matches /evil/'), 'case-sensitive mismatch');
});

await test('2.3 `s` modifier makes the dot match newlines', async () => {
  assertTrue(await evaluateCondition('webmod.multiline matches /a.b/s'), 'dotall');
  assertFalse(await evaluateCondition('webmod.multiline matches /a.b/'), 'without `s` the dot must not cross the newline');
});

await test('2.4 Non-string operand yields false', async () => {
  assertFalse(await evaluateCondition('webmod.count matches /3/'), 'numeric left operand');
});

await test('2.5 Undefined operand yields undefined', async () => {
  const result = await evaluateCondition('webmod.missing matches /x/');
  assertTrue(result === undefined, `expected undefined, got ${result}`);
});

await test('2.6 Repeated evaluation of one node stays stateless', async () => {
  // A single node is reused for every iteration; a stateful regex would fail from the 2nd on.
  assertTrue(await evaluateCondition('for all i in (0..3) : ( webmod.url matches /evil/i )'), 'all iterations match');
});

// ============================================================================
// Section 3: `iequals`
// ============================================================================

console.log('\n📋 Section 3: `iequals`\n');

await test('3.1 Case-insensitive equality succeeds', async () => {
  assertTrue(await evaluateCondition('webmod.url iequals "http://evil.example/PATH"'), 'iequals match');
});

await test('3.2 Different content fails', async () => {
  assertFalse(await evaluateCondition('webmod.url iequals "http://evil.example/other"'), 'different path');
});

await test('3.3 `iequals` parses to the expected node type', () => {
  const ast = parseConditionToAST('webmod.url iequals "x"');
  assertEquals(ast.type, 'iequals', 'node type');
});

// ============================================================================
// Section 4: Word-operator whitespace flexibility
// ============================================================================

console.log('\n📋 Section 4: Whitespace around word operators\n');

await test('4.1 Multiple spaces around `matches`', async () => {
  assertTrue(await evaluateCondition('webmod.url   matches   /evil/i'), 'multiple spaces');
});

await test('4.2 Tab-indented continuation before `matches`', async () => {
  assertTrue(await evaluateCondition('webmod.url\n\t\t\tmatches /evil/i'), 'tab indentation');
});

await test('4.3 Newline directly before `matches`', async () => {
  assertTrue(await evaluateCondition('webmod.url\nmatches /evil/i'), 'bare newline');
});

await test('4.4 Tab-indented `contains` (previously unparseable)', async () => {
  assertTrue(await evaluateCondition('webmod.url\n\t\t\ticontains "evil"'), 'tab indentation around icontains');
});

await test('4.5 Tabs around `iequals`', async () => {
  assertTrue(await evaluateCondition('webmod.url\n\tiequals\t"HTTP://EVIL.EXAMPLE/PATH"'), 'tabs around iequals');
});

await test('4.6 Tabs and newlines after `not` / `defined`', () => {
  const notAst = parseConditionToAST('not\n\twebmod.count == 3');
  assertEquals(notAst.type, 'not', '"not" recognized across a newline');
  const definedAst = parseConditionToAST('defined\twebmod.url');
  assertEquals(definedAst.type, 'defined', '"defined" recognized across a tab');
});

// ============================================================================
// Section 5: Invalid literals fail loudly
// ============================================================================

console.log('\n📋 Section 5: Invalid regex literals\n');

await test('5.1 Unsupported flag warns at parse time and fails evaluation', async () => {
  let ast;
  const { warnings } = await captureWarnings(() => {
    ast = parseConditionToAST('webmod.url matches /evil/z');
  });
  assertEquals(warnings.length, 1, 'exactly one warning');
  assertTrue(warnings[0].includes('unsupported flag'), `warning mentions the flag: ${warnings[0]}`);

  const error = await captureError(() => evaluateAst(ast));
  assertTrue(error !== null, 'evaluation must throw');
  assertTrue(error.message.includes('Invalid regex literal'), `clear message, got: ${error.message}`);
});

await test('5.2 Invalid pattern warns at parse time and fails evaluation', async () => {
  let ast;
  const { warnings } = await captureWarnings(() => {
    ast = parseConditionToAST('webmod.url matches /a{2,1}/');
  });
  assertEquals(warnings.length, 1, 'exactly one warning');

  const error = await captureError(() => evaluateAst(ast));
  assertTrue(error !== null, 'evaluation must throw');
  assertTrue(error.message.includes('Invalid regex literal'), `clear message, got: ${error.message}`);
});

await test('5.3 A stray `/` warns once and does not swallow the rest of the condition', async () => {
  let ast;
  const { warnings } = await captureWarnings(() => {
    ast = parseConditionToAST('$a and filesize / 2 > 1');
  });
  assertEquals(warnings.length, 1, 'exactly one warning');
  assertTrue(warnings[0].includes('integer division'), `warning explains division: ${warnings[0]}`);
  assertEquals(ast.type, 'and', 'expression still parses as a conjunction');
  assertEquals(ast.right.type, 'greaterThan', 'right side keeps its comparison');
});

await test('5.4 Comment markers do not warn for raw programmatic callers', async () => {
  const lineComment = await captureWarnings(() => parseConditionToAST('$a and filesize > 1 // note'));
  assertEquals(lineComment.warnings.length, 0, 'line comments must not be reported as stray slashes');
  const blockComment = await captureWarnings(() => parseConditionToAST('$a and filesize > 1 /* note */'));
  assertEquals(blockComment.warnings.length, 0, 'block comments must not be reported as stray slashes');
});

await test('5.5 A string literal on the right of `matches` is rejected', async () => {
  let ast;
  const { warnings } = await captureWarnings(() => {
    ast = parseConditionToAST('webmod.url matches "evil"');
  });
  assertEquals(warnings.length, 1, 'exactly one warning');
  assertTrue(warnings[0].includes('must be a regex literal'), `warning explains the requirement: ${warnings[0]}`);
  assertTrue(typeof ast.error === 'string', 'node carries the reason');

  const error = await captureError(() => evaluateAst(ast));
  assertTrue(error !== null, 'evaluation must throw');
  assertTrue(error.message.includes('regex literal'), `clear message, got: ${error.message}`);
});

await test('5.6 A computed pattern on the right of `matches` is rejected', async () => {
  let ast;
  const { warnings } = await captureWarnings(() => {
    ast = parseConditionToAST('webmod.url matches webmod.multiline');
  });
  assertEquals(warnings.length, 1, 'exactly one warning');
  assertTrue(warnings[0].includes('must be a regex literal'), `warning names the operand: ${warnings[0]}`);

  const error = await captureError(() => evaluateAst(ast));
  assertTrue(error !== null, 'evaluation must throw');
  assertTrue(error.message.includes('regex literal'), `clear message, got: ${error.message}`);
});

await test('5.7 A hand-built AST with a string pattern fails closed', async () => {
  const ast = {
    type: 'matches',
    left: { type: 'memberAccess', object: { type: 'identifier', name: 'webmod' }, property: 'url' },
    right: { type: 'string', value: 'evil' },
  };
  const error = await captureError(() => evaluateAst(ast));
  assertTrue(error !== null, 'evaluation must throw');
  assertTrue(error.message.includes('regex literal'), `clear message, got: ${error.message}`);
});

await test('5.8 A rule using a string pattern fails closed without breaking other rules', async () => {
  const { result } = await captureWarnings(() => scanRuleNames(`
rule BadPattern {
  strings:
    $a = "sample"
  condition:
    $a and webmod.url matches "evil"
}
rule GoodPattern {
  strings:
    $a = "sample"
  condition:
    $a and webmod.url matches /evil/i
}`));
  assertEquals(result.join(','), 'GoodPattern', 'only the rule with a regex literal matches');
});

// ============================================================================
// Section 6: String literal regressions
// ============================================================================

console.log('\n📋 Section 6: String literal extraction\n');

await test('6.1 Single-quoted string may contain double quotes', () => {
  const ast = parseConditionToAST(`webmod.url contains 'say "hi"'`);
  assertEquals(ast.right.value, 'say "hi"', 'quotes preserved inside the literal');
});

await test('6.2 A slash inside a string is not treated as a regex', () => {
  const ast = parseConditionToAST('webmod.url contains "http://host/path"');
  assertEquals(ast.right.type, 'string', 'right operand is a string');
  assertEquals(ast.right.value, 'http://host/path', 'string content preserved');
});

await test('6.3 Two string literals in one condition', () => {
  const ast = parseConditionToAST('webmod.url contains "a" and webmod.url contains "b"');
  assertEquals(ast.left.right.value, 'a', 'first literal');
  assertEquals(ast.right.right.value, 'b', 'second literal');
});

// ============================================================================
// Section 7: End-to-end rule scanning
// ============================================================================

console.log('\n📋 Section 7: End-to-end rules\n');

await test('7.1 Single-line rule using `matches`', async () => {
  const names = await scanRuleNames(`
rule SingleLineRegex {
  strings:
    $a = "sample"
  condition:
    $a and webmod.url matches /evil\\.example/i
}`);
  assertEquals(names.join(','), 'SingleLineRegex', 'rule matches');
});

await test('7.2 Tab-indented multi-line rule using `matches`', async () => {
  const names = await scanRuleNames(
    'rule TabIndentedRegex {\n' +
    '\tstrings:\n' +
    '\t\t$a = "sample"\n' +
    '\tcondition:\n' +
    '\t\t$a and\n' +
    '\t\twebmod.url\n' +
    '\t\t\tmatches /evil\\.example/i\n' +
    '}'
  );
  assertEquals(names.join(','), 'TabIndentedRegex', 'tab-indented multi-line rule matches');
});

await test('7.3 A rule with an invalid regex fails closed without breaking other rules', async () => {
  const { warnings, result } = await captureWarnings(() => scanRuleNames(`
rule BadRegex {
  strings:
    $a = "sample"
  condition:
    $a and webmod.url matches /evil/z
}
rule GoodRegex {
  strings:
    $a = "sample"
  condition:
    $a and webmod.url matches /evil/i
}`));
  assertEquals(result.join(','), 'GoodRegex', 'only the valid rule matches');
  assertTrue(warnings.some((warning) => warning.includes('unsupported flag')), 'invalid literal is reported');
});

// ============================================================================
// SUMMARY
// ============================================================================
printSummary();
