/**
 * Example: Using Boolean Literals in YARA Conditions
 * 
 * This example demonstrates how boolean literals can be used in YARA rule conditions
 * for debugging, testing, and conditional logic.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';

async function demonstrateBooleanLiterals() {
  console.log('Boolean Literals in YARA Conditions\n');
  console.log('='.repeat(60));
  
  // Sample data to scan
  const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00Hello World!');
  
  // Example 1: Always-true rule (useful for testing infrastructure)
  console.log('\n1. Always-true rule (testing/debugging):');
  const scanner1 = new InterceptScanner();
  scanner1.addRules(`
    rule AlwaysMatch {
      strings:
        $hello = "Hello"
      condition:
        true
    }
  `);
  
  const result1 = await scanner1.scan(testData);
  console.log(`   Matched: ${result1.length > 0}`);
  console.log(`   Rule: ${result1[0]?.rule || 'none'}`);
  console.log('   Use case: Testing scanner infrastructure\n');
  
  // Example 2: Always-false rule (disable a rule temporarily)
  console.log('2. Always-false rule (disable temporarily):');
  const scanner2 = new InterceptScanner();
  scanner2.addRules(`
    rule NeverMatch {
      strings:
        $hello = "Hello"
      condition:
        false
    }
  `);
  
  const result2 = await scanner2.scan(testData);
  console.log(`   Matched: ${result2.length > 0}`);
  console.log('   Use case: Temporarily disable a rule without removing it\n');
  
  // Example 3: Boolean in conditional logic
  console.log('3. Boolean with AND logic:');
  const scanner3 = new InterceptScanner();
  scanner3.addRules(`
    rule ConditionalMatch {
      strings:
        $mz = "MZ"
        $hello = "Hello"
      condition:
        true and $mz and $hello
    }
  `);
  
  const result3 = await scanner3.scan(testData);
  console.log(`   Matched: ${result3.length > 0}`);
  console.log(`   Rule: ${result3[0]?.rule || 'none'}`);
  console.log('   Use case: Ensure rule is enabled before checking strings\n');
  
  // Example 4: Boolean comparison
  console.log('4. Boolean comparison (equality):');
  const scanner4 = new InterceptScanner();
  scanner4.addRules(`
    rule BooleanComparison {
      strings:
        $hello = "Hello"
      condition:
        ($hello == true) and (filesize > 0)
    }
  `);
  
  const result4 = await scanner4.scan(testData);
  console.log(`   Matched: ${result4.length > 0}`);
  console.log(`   Rule: ${result4[0]?.rule || 'none'}`);
  console.log('   Use case: Explicit boolean checks\n');
  
  // Example 5: Complex conditional with boolean
  console.log('5. Complex conditional with boolean flags:');
  const scanner5 = new InterceptScanner();
  scanner5.addRules(`
    rule ComplexWithFlags {
      strings:
        $mz = "MZ"
        $hello = "Hello"
      condition:
        (true and $mz) or (false and $hello)
    }
  `);
  
  const result5 = await scanner5.scan(testData);
  console.log(`   Matched: ${result5.length > 0}`);
  console.log(`   Rule: ${result5[0]?.rule || 'none'}`);
  console.log('   Use case: Feature flags or conditional logic branches\n');
  
  // Example 6: Not operator with boolean
  console.log('6. NOT operator with boolean:');
  const scanner6 = new InterceptScanner();
  scanner6.addRules(`
    rule NotBooleanExample {
      strings:
        $hello = "Hello"
      condition:
        not false and $hello
    }
  `);
  
  const result6 = await scanner6.scan(testData);
  console.log(`   Matched: ${result6.length > 0}`);
  console.log(`   Rule: ${result6[0]?.rule || 'none'}`);
  console.log('   Use case: Negation logic with explicit booleans\n');
  
  console.log('='.repeat(60));
  console.log('\nBoolean literals are useful for:');
  console.log('  • Testing and debugging rule infrastructure');
  console.log('  • Temporarily disabling rules');
  console.log('  • Feature flags and conditional logic');
  console.log('  • Explicit boolean state representation');
  console.log('  • Complex conditional expressions');
}

demonstrateBooleanLiterals().catch(console.error);
