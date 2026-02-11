/**
 * Test dependent rule support in YARA conditions
 */

import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { ConditionEvaluator, createScanFacts } from '../src/yaraConditionsMatch.mjs';

async function testDependentRules() {
  console.log('Testing Dependent Rules Support\n');
  console.log('='.repeat(50));
  
  // Test data
  const data = new Uint8Array([0x4D, 0x5A, 0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "MZHello"
  
  // String matches for the rules
  const strings = {
    '$mz': {
      identifier: '$mz',
      matched: true,
      count: 1,
      matches: [{ offset: 0, length: 2 }],
      offsets: [0],
      length: 2
    },
    '$hello': {
      identifier: '$hello',
      matched: true,
      count: 1,
      matches: [{ offset: 2, length: 5 }],
      offsets: [2],
      length: 5
    }
  };
  
  const tests = [
    // Simple rule reference
    {
      name: 'Simple rule reference - matched rule',
      condition: 'BaseRule',
      matchedRules: { BaseRule: true },
      expected: true
    },
    {
      name: 'Simple rule reference - unmatched rule',
      condition: 'BaseRule',
      matchedRules: { BaseRule: false },
      expected: false
    },
    {
      name: 'Simple rule reference - undefined rule',
      condition: 'UnknownRule',
      matchedRules: {},
      expected: false
    },
    
    // Rule with logical operators
    {
      name: 'Rule AND operator',
      condition: 'RuleA and RuleB',
      matchedRules: { RuleA: true, RuleB: true },
      expected: true
    },
    {
      name: 'Rule AND operator - one false',
      condition: 'RuleA and RuleB',
      matchedRules: { RuleA: true, RuleB: false },
      expected: false
    },
    {
      name: 'Rule OR operator',
      condition: 'RuleA or RuleB',
      matchedRules: { RuleA: false, RuleB: true },
      expected: true
    },
    {
      name: 'Rule OR operator - both false',
      condition: 'RuleA or RuleB',
      matchedRules: { RuleA: false, RuleB: false },
      expected: false
    },
    {
      name: 'Rule NOT operator',
      condition: 'not BadRule',
      matchedRules: { BadRule: false },
      expected: true
    },
    
    // Combining rules with strings
    {
      name: 'Rule and string match',
      condition: 'BaseRule and $mz',
      matchedRules: { BaseRule: true },
      expected: true
    },
    {
      name: 'Rule and string match - rule false',
      condition: 'BaseRule and $mz',
      matchedRules: { BaseRule: false },
      expected: false
    },
    {
      name: 'Rule or string match',
      condition: 'BaseRule or $mz',
      matchedRules: { BaseRule: false },
      expected: true
    },
    
    // Complex conditions
    {
      name: 'Complex: (RuleA and RuleB) or $hello',
      condition: '(RuleA and RuleB) or $hello',
      matchedRules: { RuleA: false, RuleB: true },
      expected: true
    },
    {
      name: 'Complex: RuleA and (RuleB or RuleC)',
      condition: 'RuleA and (RuleB or RuleC)',
      matchedRules: { RuleA: true, RuleB: false, RuleC: true },
      expected: true
    },
    {
      name: 'Complex: not (RuleA and RuleB)',
      condition: 'not (RuleA and RuleB)',
      matchedRules: { RuleA: true, RuleB: false },
      expected: true
    },
    
    // Multiple rules
    {
      name: 'Three rules with AND',
      condition: 'RuleA and RuleB and RuleC',
      matchedRules: { RuleA: true, RuleB: true, RuleC: true },
      expected: true
    },
    {
      name: 'Three rules with mixed operators',
      condition: 'RuleA and RuleB or RuleC',
      matchedRules: { RuleA: false, RuleB: false, RuleC: true },
      expected: true // (false AND false) OR true = false OR true = true
    },
    {
      name: 'Three rules with mixed operators - AND binds tighter',
      condition: 'RuleA and RuleB or RuleC',
      matchedRules: { RuleA: true, RuleB: false, RuleC: false },
      expected: false // (true AND false) OR false = false OR false = false
    },
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const [index, test] of tests.entries()) {
    try {
      const scanFacts = createScanFacts(data, strings, {}, {
        matchedRules: test.matchedRules
      });
      const evaluator = new ConditionEvaluator(scanFacts);
      
      const ast = parseConditionToAST(test.condition);
      const result = await evaluator.evaluateNode(ast);
      
      if (result === test.expected) {
        console.log(`✓ Test ${index + 1}: PASSED`);
        console.log(`  ${test.name}`);
        console.log(`  Condition: ${test.condition}`);
        console.log(`  Result: ${result}\n`);
        passed++;
      } else {
        console.log(`✗ Test ${index + 1}: FAILED`);
        console.log(`  ${test.name}`);
        console.log(`  Condition: ${test.condition}`);
        console.log(`  Expected: ${test.expected}`);
        console.log(`  Got: ${result}\n`);
        failed++;
      }
    } catch (error) {
      console.log(`✗ Test ${index + 1}: ERROR`);
      console.log(`  ${test.name}`);
      console.log(`  Condition: ${test.condition}`);
      console.log(`  Error: ${error.message}\n`);
      failed++;
    }
  }
  
  console.log('='.repeat(50));
  console.log(`\nResults: ${passed} passed, ${failed} failed out of ${tests.length} tests`);
  
  if (failed === 0) {
    console.log('\n✓ All tests passed!');
    process.exit(0);
  } else {
    console.log('\n✗ Some tests failed');
    process.exit(1);
  }
}

testDependentRules();
