/**
 * Example: Direct demonstration of dependent rules evaluation
 * 
 * Shows how the condition evaluator handles rule dependencies
 */

import { parseConditionToAST } from '../src/yaraConditionParser.mjs';
import { ConditionEvaluator, createScanFacts } from '../src/yaraConditionsMatch.mjs';

function demonstrateDependentRules() {
  console.log('Dependent Rules - Direct Evaluation Example\n');
  console.log('='.repeat(70));
  
  // Simulate scan data
  const data = new Uint8Array([0x4D, 0x5A, 0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "MZHello"
  
  // Simulate string matches
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
  
  console.log('\n--- Scenario 1: Simple Rule Dependency ---');
  console.log('Rule IsPE: condition = $mz at 0');
  console.log('Rule HasText: condition = $hello');
  console.log('Rule CombinedCheck: condition = IsPE and HasText\n');
  
  // Simulate that IsPE and HasText have already been evaluated
  const matchedRules1 = {
    IsPE: true,
    HasText: true
  };
  
  const scanFacts1 = createScanFacts(data, strings, {}, { matchedRules: matchedRules1 });
  const evaluator1 = new ConditionEvaluator(scanFacts1);
  
  const condition1 = 'IsPE and HasText';
  const ast1 = parseConditionToAST(condition1);
  const result1 = evaluator1.evaluateNode(ast1);
  
  console.log(`Evaluating: ${condition1}`);
  console.log(`  IsPE = ${matchedRules1.IsPE}`);
  console.log(`  HasText = ${matchedRules1.HasText}`);
  console.log(`  Result: ${result1} ✓\n`);
  
  console.log('\n--- Scenario 2: Complex Rule Dependencies ---');
  console.log('Rule BaseDetection: condition = $mz or $hello');
  console.log('Rule AdvancedCheck: condition = filesize < 100');
  console.log('Rule FinalRule: condition = BaseDetection and not AdvancedCheck\n');
  
  const matchedRules2 = {
    BaseDetection: true,
    AdvancedCheck: false
  };
  
  const scanFacts2 = createScanFacts(data, strings, {}, { matchedRules: matchedRules2 });
  const evaluator2 = new ConditionEvaluator(scanFacts2);
  
  const condition2 = 'BaseDetection and not AdvancedCheck';
  const ast2 = parseConditionToAST(condition2);
  const result2 = evaluator2.evaluateNode(ast2);
  
  console.log(`Evaluating: ${condition2}`);
  console.log(`  BaseDetection = ${matchedRules2.BaseDetection}`);
  console.log(`  AdvancedCheck = ${matchedRules2.AdvancedCheck}`);
  console.log(`  Result: ${result2} ✓\n`);
  
  console.log('\n--- Scenario 3: Multiple Rule Dependencies with OR ---');
  console.log('Rule TypeA: condition = $mz');
  console.log('Rule TypeB: condition = $hello');
  console.log('Rule TypeC: condition = filesize > 5');
  console.log('Rule AnyType: condition = TypeA or TypeB or TypeC\n');
  
  const matchedRules3 = {
    TypeA: true,
    TypeB: false,
    TypeC: true
  };
  
  const scanFacts3 = createScanFacts(data, strings, {}, { matchedRules: matchedRules3 });
  const evaluator3 = new ConditionEvaluator(scanFacts3);
  
  const condition3 = 'TypeA or TypeB or TypeC';
  const ast3 = parseConditionToAST(condition3);
  const result3 = evaluator3.evaluateNode(ast3);
  
  console.log(`Evaluating: ${condition3}`);
  console.log(`  TypeA = ${matchedRules3.TypeA}`);
  console.log(`  TypeB = ${matchedRules3.TypeB}`);
  console.log(`  TypeC = ${matchedRules3.TypeC}`);
  console.log(`  Result: ${result3} ✓\n`);
  
  console.log('\n--- Scenario 4: Mixing Rule References and String Matches ---');
  console.log('Rule BaseRule: condition = $mz');
  console.log('Rule ExtendedRule: condition = BaseRule and $hello\n');
  
  const matchedRules4 = {
    BaseRule: true
  };
  
  const scanFacts4 = createScanFacts(data, strings, {}, { matchedRules: matchedRules4 });
  const evaluator4 = new ConditionEvaluator(scanFacts4);
  
  const condition4 = 'BaseRule and $hello';
  const ast4 = parseConditionToAST(condition4);
  const result4 = evaluator4.evaluateNode(ast4);
  
  console.log(`Evaluating: ${condition4}`);
  console.log(`  BaseRule = ${matchedRules4.BaseRule}`);
  console.log(`  $hello matched = ${strings.$hello.matched}`);
  console.log(`  Result: ${result4} ✓\n`);
  
  console.log('='.repeat(70));
  console.log('\nKey Points:');
  console.log('  • Rule names are uppercase identifiers (e.g., IsPE, BaseRule)');
  console.log('  • Rules can reference other rules in their conditions');
  console.log('  • Dependent rules are evaluated after their dependencies');
  console.log('  • Can combine rule references with string matches and operators');
  console.log('  • Enables modular, hierarchical rule design');
}

demonstrateDependentRules();
