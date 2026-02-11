/**
 * Quick test for String Position & Offset Operators
 * Tests: at, in, @, ! operators
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, printSummary, printSection } from './testingFramework.mjs';

// Create clean test data with known offsets
// MZ at 0-1, Hello at 2-6, World at 8-12, test at 14-17, and at 19-21, test at 23-26
const dataStr = 'MZHello World test and test';
const data = new TextEncoder().encode(dataStr);

async function testPositionOp(name, rule, shouldMatch) {
  await test(name, async () => {
    const scanner = new InterceptScanner();
    scanner.addRules(rule);
    const results = await scanner.scan(data);
    const matched = results.length > 0;
    
    if (matched !== shouldMatch) {
      throw new Error(`Expected ${shouldMatch ? 'match' : 'no match'}, got ${matched ? 'match' : 'no match'}`);
    }
  });
}

printSection('STRING POSITION & OFFSET OPERATORS - QUICK TEST');

  // Test 'at' operator
  console.log('\n📍 Testing "at" operator:');
  await testPositionOp('String at offset 0', `
    rule Test { strings: $a = "MZ" condition: $a at 0 }
  `, true);

  await testPositionOp('String at offset 2', `
    rule Test { strings: $a = "Hello" condition: $a at 2 }
  `, true);

  await testPositionOp('String NOT at offset 0', `
    rule Test { strings: $a = "Hello" condition: $a at 0 }
  `, false);

  // Test 'in' operator  
  console.log('\n📏 Testing "in" range operator:');
  await testPositionOp('String in range (0..10)', `
    rule Test { strings: $a = "MZ" condition: $a in (0..10) }
  `, true);

  await testPositionOp('String in range (0..15)', `
    rule Test { strings: $a = "Hello" condition: $a in (0..15) }
  `, true);

  await testPositionOp('String NOT in range (10..20)', `
    rule Test { strings: $a = "Hello" condition: $a in (10..20) }
  `, false);

  // Test '@' operator
  console.log('\n📌 Testing "@" offset operator:');
  await testPositionOp('Check first offset @a', `
    rule Test { strings: $a = "MZ" condition: @a == 0 }
  `, true);

  await testPositionOp('Check second offset @a[2]', `
    rule Test { strings: $a = "test" condition: @a[2] == 23 }
  `, true);

  await testPositionOp('Compare offsets @a < @b', `
    rule Test { 
      strings: 
        $a = "MZ"
        $b = "Hello"
      condition: 
        @a < @b 
    }
  `, true);

  // Test '!' operator
  console.log('\n📏 Testing "!" length operator:');
  await testPositionOp('Check match length !a', `
    rule Test { strings: $a = "MZ" condition: !a == 2 }
  `, true);

  await testPositionOp('Check match length !a == 5', `
    rule Test { strings: $a = "Hello" condition: !a == 5 }
  `, true);

  await testPositionOp('Compare lengths', `
    rule Test { 
      strings: 
        $a = "MZ"
        $b = "Hello"
      condition: 
        !b > !a 
    }
  `, true);

  // Combined operators
  console.log('\n🔗 Testing combined operators:');
  await testPositionOp('Combined: at and @', `
    rule Test { 
      strings: $a = "MZ"
      condition: $a at 0 and @a == 0
    }
  `, true);

  await testPositionOp('Combined: in and offset arithmetic', `
    rule Test { 
      strings: $a = "Hello"
      condition: $a in (0..10) and @a == 2
    }
  `, true);

  await testPositionOp('Combined: offset + length', `
    rule Test { 
      strings: 
        $a = "MZ"
        $b = "Hello"
      condition: 
        @a + 2 == @b and !a + !b == 7
    }
  `, true);

  printSummary();
