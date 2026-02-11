/**
 * Test boolean literal support in YARA conditions
 */

import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { ConditionEvaluator, createScanFacts } from '../src/yaraConditionsMatch.mjs';

async function testBooleanLiterals() {
  console.log('Testing Boolean Literals Support\n');
  console.log('='.repeat(50));
  
  // Test data
  const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
  const strings = {
    '$a': {
      identifier: '$a',
      matched: true,
      count: 1,
      matches: [{ offset: 0, length: 5 }],
      offsets: [0],
      length: 5
    }
  };
  
  const scanFacts = createScanFacts(data, strings, {}, {});
  const evaluator = new ConditionEvaluator(scanFacts);
  
  const tests = [
    // Simple boolean literals
    { condition: 'true', expected: true },
    { condition: 'false', expected: false },
    
    // Boolean with logical operators
    { condition: 'true and true', expected: true },
    { condition: 'true and false', expected: false },
    { condition: 'false and false', expected: false },
    { condition: 'true or false', expected: true },
    { condition: 'false or false', expected: false },
    { condition: 'not true', expected: false },
    { condition: 'not false', expected: true },
    
    // Boolean with string matches
    { condition: 'true and $a', expected: true },
    { condition: 'false and $a', expected: false },
    { condition: 'true or $a', expected: true },
    { condition: 'false or $a', expected: true },
    { condition: '$a and true', expected: true },
    { condition: '$a and false', expected: false },
    
    // Boolean in comparisons
    { condition: 'true == true', expected: true },
    { condition: 'true == false', expected: false },
    { condition: 'false == false', expected: true },
    { condition: 'true != false', expected: true },
    { condition: 'true != true', expected: false },
    
    // Complex expressions with booleans
    { condition: '(true and $a) or false', expected: true },
    { condition: '(false or $a) and true', expected: true },
    { condition: 'not (false or false)', expected: true },
    { condition: 'true and (filesize > 0)', expected: true },
    { condition: 'false or (filesize > 0)', expected: true },
    { condition: 'true and (filesize == 0)', expected: false },
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const [index, test] of tests.entries()) {
    try {
      const ast = parseConditionToAST(test.condition);
      const result = await evaluator.evaluateNode(ast);
      
      if (result === test.expected) {
        console.log(`✓ Test ${index + 1}: PASSED`);
        console.log(`  Condition: ${test.condition}`);
        console.log(`  Result: ${result}\n`);
        passed++;
      } else {
        console.log(`✗ Test ${index + 1}: FAILED`);
        console.log(`  Condition: ${test.condition}`);
        console.log(`  Expected: ${test.expected}`);
        console.log(`  Got: ${result}\n`);
        failed++;
      }
    } catch (error) {
      console.log(`✗ Test ${index + 1}: ERROR`);
      console.log(`  Condition: ${test.condition}`);
      console.log(`  Error: ${error.message}\n`);
      failed++;
    }
  }
  
  console.log('='.repeat(50));
  console.log(`\nResults: ${passed} passed, ${failed} failed out of ${tests.length} tests`);
}

testBooleanLiterals();
