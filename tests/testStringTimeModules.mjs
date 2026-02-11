/**
 * Tests for String and Time Module Integration
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { string } from '../yaraStringModule.mjs';
import { time } from '../yaraTimeModule.mjs';
import { test, assertEquals, assertTrue, assertArrayLength, printSummary, printSection } from './testingFramework.mjs';

// ============================================================================
// Main execution
// ============================================================================

printSection('String Module Tests');
  
  // String Module Direct API Tests
  await test('string.to_int() - decimal number', async () => {
    assertEquals(string.to_int("42"), 42);
  });
  
  await test('string.to_int() - hex number with 0x prefix', async () => {
    assertEquals(string.to_int("0x1234"), 0x1234);
  });
  
  await test('string.to_int() - hex number with 0X prefix', async () => {
    assertEquals(string.to_int("0X1234"), 0x1234);
  });
  
  await test('string.to_int() - octal number with o prefix', async () => {
    assertEquals(string.to_int("o755"), 493);
  });
  
  await test('string.to_int() - with explicit base', async () => {
    assertEquals(string.to_int("FF", 16), 255);
  });
  
  await test('string.to_int() - invalid string returns undefined', async () => {
    let result;
    try { result = string.to_int("not a number"); } catch (e) { result = undefined; }
    assertEquals(result, undefined);
  });
  
  await test('string.to_int() - non-string input returns undefined', async () => {
        let result;
    try { result = string.to_int(null); } catch (e) { result = undefined; }
    assertEquals(result, undefined);
  });
  
  await test('string.length() - normal string', async () => {
    assertEquals(string.length("Hello World"), 11);
  });
  
  await test('string.length() - empty string', async () => {
    assertEquals(string.length(""), 0);
  });
  
  await test('string.length() - non-string returns 0', async () => {
    assertEquals(string.length(null), 0);
  });
  
  // String Module in YARA Rules Tests
  await test('YARA rule with string.to_int() on hex string', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string });
    
    scanner.addRules(`
      rule HexValue {
        strings:
          $hex = "0x5000"
        condition:
          string.to_int($hex) > 0x4000
      }
    `);
    
    const data = new TextEncoder().encode('Value: 0x5000');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
    assertEquals(results[0].rule, 'HexValue');
  });
  
  await test('YARA rule with string.to_int() on decimal string', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string });
    
    scanner.addRules(`
      rule DecimalValue {
        strings:
          $num = "12345"
        condition:
          string.to_int($num) == 12345
      }
    `);
    
    const data = new TextEncoder().encode('Number: 12345');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule with string.length() check', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string });
    
    scanner.addRules(`
      rule LongString {
        strings:
          $path = "C:\\\\Windows\\\\System32\\\\config\\\\system"
        condition:
          string.length($path) > 30
      }
    `);
    
    const data = new TextEncoder().encode('Path: C:\\Windows\\System32\\config\\system');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule with string.length() comparison', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string });
    
    scanner.addRules(`
      rule ShortString {
        strings:
          $name = "test"
        condition:
          string.length($name) == 4
      }
    `);
    
    const data = new TextEncoder().encode('Name: test');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule with multiple string module functions', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string });
    
    scanner.addRules(`
      rule MultipleStringChecks {
        strings:
          $ver = "0x100"
          $name = "Application"
        condition:
          string.to_int($ver) > 0xFF and string.length($name) > 5
      }
    `);
    
    const data = new TextEncoder().encode('Version: 0x100 Name: Application');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  console.log('\n=== Time Module Tests ===\n');
  
  // Time Module Direct API Tests
  await test('time.now() returns a number', async () => {
    const now = time.now();
    assertTrue(typeof now === 'number');
  });
  
  await test('time.now() returns current timestamp', async () => {
    const before = Date.now();
    const now = time.now();
    const after = Date.now();
    
    assertTrue(now >= before && now <= after);
  });
  
  // Time Module in YARA Rules Tests
  await test('YARA rule with time.now() check', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ time });
    
    scanner.addRules(`
      rule TimestampCheck {
        condition:
          time.now() > 0
      }
    `);
    
    const data = new TextEncoder().encode('Sample data');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule with time.now() comparison', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ time });
    
    scanner.addRules(`
      rule FutureTimestamp {
        condition:
          time.now() < 9999999999999
      }
    `);
    
    const data = new TextEncoder().encode('Sample data');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule combining string match with time check', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ time });
    
    scanner.addRules(`
      rule StringWithTime {
        strings:
          $sig = "malware"
        condition:
          $sig and time.now() > 0
      }
    `);
    
    const data = new TextEncoder().encode('This is malware code');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  console.log('\n=== Combined Module Tests ===\n');
  
  // Combined String and Time Module Tests
  await test('YARA rule with both string and time modules', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string, time });
    
    scanner.addRules(`
      rule CombinedCheck {
        strings:
          $version = "v2.0"
        condition:
          string.length($version) == 4 and time.now() > 0
      }
    `);
    
    const data = new TextEncoder().encode('Version: v2.0');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('YARA rule with complex condition using both modules', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string, time });
    
    scanner.addRules(`
      rule ComplexModuleCheck {
        strings:
          $num = "100"
          $text = "sample"
        condition:
          (string.to_int($num) > 50 and string.length($text) < 10) and 
          time.now() > 0
      }
    `);
    
    const data = new TextEncoder().encode('Number: 100 Text: sample');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  
  await test('Multi-line condition with string and time modules', async () => {
    const scanner = new YaraScanner();
    scanner.setModules({ string, time });
    
    scanner.addRules(`
      rule MultiLineCondition {
        strings:
          $a = "test"
          $b = "123"
        condition:
          $a and 
          string.to_int($b) == 123 and
          time.now() > 0
      }
    `);
    
    const data = new TextEncoder().encode('test 123');
    const results = await scanner.scan(data);
    
    assertArrayLength(results, 1);
  });
  

printSummary();