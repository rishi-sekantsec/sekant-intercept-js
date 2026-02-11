/**
 * Test Suite for Anonymous String Support
 * 
 * Tests YARA's anonymous string feature where strings can be defined without identifiers:
 * $ = "pattern" instead of $var = "pattern"
 * 
 * Anonymous strings:
 * - Are automatically assigned internal names (.anon_0, .anon_1, etc.)
 * - Work with all string types (text, hex, regex)
 * - Work with all modifiers (nocase, wide, xor, base64, etc.)
 * - Work with all quantifiers (any of them, all of them, etc.)
 * - Are NOT shown in match output
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { test, assertEquals, assertTrue, assertFalse, printSummary, printSection } from './testingFramework.mjs';

// Helper to create test data
function createTestData(content) {
  if (typeof content === 'string') {
    return new TextEncoder().encode(content);
  }
  return content;
}

printSection('Anonymous String Support Tests');

// ============================================================================
// Section 1: Basic Anonymous Strings
// ============================================================================

await test('1.1 Single anonymous text string', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "malware"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This file contains malware code');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match rule');
  assertEquals(results[0].rule, 'Test', 'Rule name should match');
  
  // Anonymous strings should not appear in output
  const stringKeys = Object.keys(results[0].strings);
  assertTrue(stringKeys.length === 0 || !stringKeys.some(k => k.includes('.anon_')), 
    'Anonymous strings should not appear in match output');
});

await test('1.2 Multiple anonymous strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "evil"
        $ = "malware"
        $ = "virus"
      condition:
        2 of them
    }
  `);
  
  const data = createTestData('This is evil malware');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match rule');
  const stringKeys = Object.keys(results[0].strings);
  assertTrue(stringKeys.length === 0 || !stringKeys.some(k => k.includes('.anon_')), 
    'Anonymous strings should not appear in match output');
});

await test('1.3 Mix of anonymous and named strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $named = "important"
        $ = "hidden1"
        $ = "hidden2"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This is important with hidden1');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match rule');
  const stringKeys = Object.keys(results[0].strings);
  
  // Should have the named string
  assertTrue(stringKeys.includes('$named'), 'Named string should appear');
  assertTrue(results[0].strings['$named'].matched, 'Named string should be matched');
  
  // Anonymous strings should not appear
  assertTrue(!stringKeys.some(k => k.includes('.anon_')), 
    'Anonymous strings should not appear in output');
});

// ============================================================================
// Section 2: Anonymous Strings with Modifiers
// ============================================================================

await test('2.1 Anonymous string with nocase', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "MALWARE" nocase
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This file contains malware code');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with nocase modifier');
});

await test('2.2 Anonymous string with wide', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "test" wide
      condition:
        any of them
    }
  `);
  
  const data = new Uint8Array([0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]); // "test" in wide
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match wide string');
});

await test('2.3 Anonymous string with multiple modifiers', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "MALWARE" nocase wide
      condition:
        any of them
    }
  `);
  
  // "malware" in lowercase wide
  const data = new Uint8Array([
    0x6d, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x77, 0x00, 
    0x61, 0x00, 0x72, 0x00, 0x65, 0x00
  ]);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with multiple modifiers');
});

// ============================================================================
// Section 3: Anonymous Hex Patterns
// ============================================================================

await test('3.1 Anonymous hex pattern', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = { 4D 5A }
      condition:
        any of them
    }
  `);
  
  const data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00]);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match hex pattern');
});

await test('3.2 Anonymous hex with wildcards', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = { 4D ?? 90 }
      condition:
        any of them
    }
  `);
  
  const data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00]);
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match hex with wildcards');
});

// ============================================================================
// Section 4: Anonymous Regular Expressions
// ============================================================================

await test('4.1 Anonymous regex', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = /evil[0-9]+/
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This contains evil123 code');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match regex');
});

await test('4.2 Anonymous regex with case-insensitive flag', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = /MALWARE/i
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This contains malware');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match case-insensitive regex');
});

// ============================================================================
// Section 5: Quantifiers with Anonymous Strings
// ============================================================================

await test('5.1 "any of them" with anonymous strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "pattern1"
        $ = "pattern2"
        $ = "pattern3"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('This has pattern2 in it');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with any of them');
});

await test('5.2 "all of them" with anonymous strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "pattern1"
        $ = "pattern2"
      condition:
        all of them
    }
  `);
  
  const data = createTestData('This has pattern1 and pattern2');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with all of them');
});

await test('5.3 "N of them" with anonymous strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "pattern1"
        $ = "pattern2"
        $ = "pattern3"
        $ = "pattern4"
      condition:
        2 of them
    }
  `);
  
  const data = createTestData('Has pattern1 and pattern3');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match with 2 of them');
});

await test('5.4 "N of them" fails when threshold not met', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "pattern1"
        $ = "pattern2"
        $ = "pattern3"
      condition:
        3 of them
    }
  `);
  
  const data = createTestData('Only has pattern1');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match when threshold not met');
});

// ============================================================================
// Section 6: Real-World Patterns
// ============================================================================

await test('6.1 Malware IOC list with anonymous strings', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Malware_IOCs {
      strings:
        $ = "CreateRemoteThread"
        $ = "VirtualAllocEx"
        $ = "WriteProcessMemory"
        $ = "http://evil.com"
        $ = "C:\\\\Windows\\\\Temp\\\\payload.exe"
      condition:
        3 of them
    }
  `);
  
  const data = createTestData(
    'CreateRemoteThread and VirtualAllocEx and WriteProcessMemory detected'
  );
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should detect malware IOCs');
});

await test('6.2 Mixed anonymous and named for important markers', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Ransomware {
      strings:
        $encrypt = "CryptEncrypt" nocase
        $ = "FindFirstFile"
        $ = "FindNextFile"
        $ = "MoveFile"
        $ = "DeleteFile"
      condition:
        $encrypt and 2 of them
    }
  `);
  
  const data = createTestData(
    'Uses CryptEncrypt and FindFirstFile and MoveFile'
  );
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should detect ransomware pattern');
  assertTrue(results[0].strings['$encrypt'].matched, 'Named encrypt string should be tracked');
});

// ============================================================================
// Section 7: Edge Cases
// ============================================================================

await test('7.1 Only anonymous strings in rule', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "test1"
        $ = "test2"
        $ = "test3"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('Contains test2');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should work with only anonymous strings');
  const stringKeys = Object.keys(results[0].strings);
  assertEquals(stringKeys.length, 0, 'No strings should be in output');
});

await test('7.2 No match should have empty strings object', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $ = "notfound"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('Different content here');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 0, 'Should not match');
});

await test('7.3 Anonymous string at different positions', async () => {
  const scanner = new YaraScanner();
  scanner.addRule(`
    rule Test {
      strings:
        $a = "start"
        $ = "middle"
        $b = "end"
      condition:
        any of them
    }
  `);
  
  const data = createTestData('start middle end');
  const results = await scanner.scan(data);
  
  assertEquals(results.length, 1, 'Should match');
  assertTrue(results[0].strings['$a'].matched, 'First named string matched');
  assertTrue(results[0].strings['$b'].matched, 'Last named string matched');
  assertFalse(Object.keys(results[0].strings).includes('$..anon_'), 
    'Anonymous string should not appear');
});

printSummary();
