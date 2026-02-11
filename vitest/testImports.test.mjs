#!/usr/bin/env node
/**
 * Test YARA Import Statement Support
 * 
 * Tests parsing and validation of import statements in YARA rules.
 * All supported modules are automatically available, but imports are validated.
 */

import { parseYaraRuleGroup, parseYaraRule } from '../src/yaraRuleCompiler.mjs';

// Test results tracking
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

/**
 * Test helper function
 */
function test(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`✓ ${name}`);
  } catch (error) {
    failedTests++;
    console.log(`✗ ${name}`);
    console.log(`  Error: ${error.message}`);
  }
}

/**
 * Assert helper functions
 */
function assertDoesNotThrow(fn, message) {
  try {
    fn();
  } catch (error) {
    throw new Error(`${message}: ${error.message}`);
  }
}

function assertThrows(fn, expectedMessage, testMessage) {
  try {
    fn();
    throw new Error(`${testMessage}: Expected error but none was thrown`);
  } catch (error) {
    if (!error.message.includes(expectedMessage)) {
      throw new Error(
        `${testMessage}: Expected error containing "${expectedMessage}" ` +
        `but got "${error.message}"`
      );
    }
  }
}

function assertEquals(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

console.log('======================================================================');
console.log('YARA Import Statement Tests');
console.log('======================================================================\n');

// ============================================================================
// Valid Import Tests
// ============================================================================
console.log('✅ Valid Import Tests');
console.log('----------------------------------------------------------------------');

test('Import PE module', () => {
  const rule = `
    import "pe"
    
    rule TestPE {
      condition:
        pe.is_pe
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse PE import successfully'
  );
});

test('Import ELF module', () => {
  const rule = `
    import "elf"
    
    rule TestELF {
      condition:
        elf.type == elf.ET_EXEC
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse ELF import successfully'
  );
});

test('Import math module', () => {
  const rule = `
    import "math"
    
    rule TestMath {
      condition:
        math.entropy(0, filesize) > 7.0
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse math import successfully'
  );
});

test('Import hash module', () => {
  const rule = `
    import "hash"
    
    rule TestHash {
      condition:
        hash.md5(0, filesize) == "5d41402abc4b2a76b9719d911017c592"
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse hash import successfully'
  );
});

test('Import string module', () => {
  const rule = `
    import "string"
    
    rule TestString {
      condition:
        string.length("test") == 4
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse string import successfully'
  );
});

test('Import time module', () => {
  const rule = `
    import "time"
    
    rule TestTime {
      condition:
        time.now() > 0
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse time import successfully'
  );
});

test('Multiple imports', () => {
  const rule = `
    import "pe"
    import "hash"
    import "math"
    
    rule TestMultiple {
      condition:
        pe.is_pe and math.entropy(0, filesize) > 5.0
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should parse multiple imports successfully'
  );
});

test('Import with whitespace variations', () => {
  const rule = `
import "pe"
  import   "elf"  
    import "math"
    
    rule TestWhitespace {
      condition:
        pe.is_pe or elf.type == elf.ET_EXEC
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should handle various whitespace in imports'
  );
});

test('Import before multiple rules', () => {
  const rule = `
    import "pe"
    import "math"
    
    rule Rule1 {
      condition:
        pe.is_pe
    }
    
    rule Rule2 {
      condition:
        math.entropy(0, filesize) > 6.0
    }
  `;
  
  const rules = parseYaraRuleGroup(rule);
  assertEquals(rules.length, 2, 'Should parse both rules');
});

// ============================================================================
// Invalid Import Tests
// ============================================================================
console.log('\n❌ Invalid Import Tests');
console.log('----------------------------------------------------------------------');

test('Unsupported module - cuckoo', () => {
  const rule = `
    import "cuckoo"
    
    rule TestUnsupported {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "cuckoo"',
    'Should reject unsupported cuckoo module'
  );
});

test('Unsupported module - dotnet', () => {
  const rule = `
    import "dotnet"
    
    rule TestDotnet {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "dotnet"',
    'Should reject unsupported dotnet module'
  );
});

test('Unsupported module - magic', () => {
  const rule = `
    import "magic"
    
    rule TestMagic {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "magic"',
    'Should reject unsupported magic module'
  );
});

test('Unsupported module - androguard', () => {
  const rule = `
    import "androguard"
    
    rule TestAndroguard {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "androguard"',
    'Should reject unsupported androguard module'
  );
});

test('Multiple imports with one unsupported', () => {
  const rule = `
    import "pe"
    import "hash"
    import "vt"
    import "math"
    
    rule TestMixed {
      condition:
        pe.is_pe
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "vt"',
    'Should reject when any import is unsupported'
  );
});

test('Error message includes supported modules list', () => {
  const rule = `
    import "unsupported_module"
    
    rule TestError {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Supported modules are: pe, elf, math, hash, time, string',
    'Error message should list supported modules'
  );
});

// ============================================================================
// Edge Cases
// ============================================================================
console.log('\n🔍 Edge Case Tests');
console.log('----------------------------------------------------------------------');

test('No imports - should work normally', () => {
  const rule = `
    rule NoImports {
      strings:
        $a = "test"
      condition:
        $a
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should work without any imports'
  );
});

test('Duplicate imports - should be allowed', () => {
  const rule = `
    import "pe"
    import "pe"
    
    rule DuplicateImport {
      condition:
        pe.is_pe
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should allow duplicate imports'
  );
});

test('Import after rule - should still validate', () => {
  const rule = `
    rule FirstRule {
      condition:
        true
    }
    
    import "pe"
    
    rule SecondRule {
      condition:
        pe.is_pe
    }
  `;
  
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Should validate imports regardless of position'
  );
});

test('Modules work without explicit import', () => {
  const rule = `
    rule NoExplicitImport {
      condition:
        pe.is_pe and math.entropy(0, filesize) > 5.0
    }
  `;
  
  // Should not throw during parsing (modules are auto-available)
  // Actual module functionality is tested during execution
  assertDoesNotThrow(
    () => parseYaraRuleGroup(rule),
    'Modules should work without explicit import'
  );
});

test('Case sensitive module names', () => {
  const rule = `
    import "PE"
    
    rule TestCase {
      condition:
        true
    }
  `;
  
  assertThrows(
    () => parseYaraRuleGroup(rule),
    'Unsupported module import: "PE"',
    'Module names should be case-sensitive'
  );
});

// ============================================================================
// Summary
// ============================================================================
console.log('\n======================================================================');
console.log('TEST SUMMARY');
console.log('======================================================================');
console.log(`Total tests: ${totalTests}`);
console.log(`Passed: ${passedTests} (${((passedTests / totalTests) * 100).toFixed(1)}%)`);
console.log(`Failed: ${failedTests}`);
console.log('======================================================================');

if (failedTests === 0) {
  console.log('✅ All tests passed!');
  process.exit(0);
} else {
  console.log(`❌ ${failedTests} test(s) failed`);
  process.exit(1);
}
