import { parseConditionToAST } from '../yaraConditionParser.mjs';

console.log('Testing refactored parser...\n');

const tests = [
  { name: 'Quantifier: any of them', cond: 'any of them', expected: 'any' },
  { name: 'Quantifier: 2 of them', cond: '2 of them', expected: 'quantified' },
  { name: 'Quantifier: 50% of them', cond: '50% of them', expected: 'quantified' },
  { name: 'Binary: AND', cond: '$a and $b', expected: 'and' },
  { name: 'Binary: OR', cond: '$a or $b', expected: 'or' },
  { name: 'For-loop: any', cond: 'for any of them : ( $ at 0 )', expected: 'for' },
  { name: 'For-loop: range', cond: 'for all i in (1..3) : ( @a[i] < 100 )', expected: 'for' },
  { name: 'Data access: uint8', cond: 'uint8(0) == 0x4D', expected: 'equal' },
  { name: 'Data access: uint16be', cond: 'uint16be(0) == 0x4D5A', expected: 'equal' },
  { name: 'String offset: indexed', cond: '@a[1] < 100', expected: 'lessThan' },
  { name: 'String length: indexed', cond: '!a[1] > 5', expected: 'greaterThan' }
];

let passed = 0;
let failed = 0;

tests.forEach(test => {
  try {
    const ast = parseConditionToAST(test.cond, {});
    if (ast.type === test.expected) {
      console.log(`✓ ${test.name}`);
      passed++;
    } else {
      console.log(`✗ ${test.name} - Expected '${test.expected}', got '${ast.type}'`);
      failed++;
    }
  } catch (e) {
    console.log(`✗ ${test.name} - Error: ${e.message}`);
    failed++;
  }
});

console.log(`\n${passed}/${tests.length} tests passed`);
process.exit(failed > 0 ? 1 : 0);
