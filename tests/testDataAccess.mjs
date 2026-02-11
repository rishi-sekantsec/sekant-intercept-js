import { YaraScanner } from '../yaraScanner.mjs';
import { test, printSummary, printSection } from './testingFramework.mjs';

/**
 * Comprehensive test suite for data access functions
 * Tests uint8, uint16, uint32, int8, int16, int32
 */

printSection('Data Access Functions Test Suite');

async function runTests() {
  // Test 1: uint8 - unsigned 8-bit integer
  await test('1.1 uint8() reads single byte', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(0) == 0x4D
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x4D, 0x5A, 0x00, 0x00]);
    const result = await scanner.scan(data);
    if (result.length !== 1 || result[0].rule !== 'Test') {
      throw new Error('Expected rule to match');
    }
  });

  await test('1.2 uint8() at different offsets', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(0) == 0x4D and uint8(1) == 0x5A and uint8(2) == 0x90
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('1.3 uint8() range check (0-255)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(0) >= 0 and uint8(0) <= 255
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 2: uint16 - unsigned 16-bit integer (little-endian)
  await test('2.1 uint16() reads two bytes (little-endian)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint16(0) == 0x5A4D
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x4D, 0x5A, 0x00, 0x00]); // MZ signature
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.2 uint16() at different offsets', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint16(0) == 0x5A4D and uint16(2) == 0xFFFF
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x4D, 0x5A, 0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.3 uint16() with large values', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint16(0) == 65535
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 3: uint32 - unsigned 32-bit integer (little-endian)
  await test('3.1 uint32() reads four bytes (little-endian)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint32(0) == 0x00004D5A
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x5A, 0x4D, 0x00, 0x00]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.2 uint32() PE signature check', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint32(0) == 0x00004550
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x50, 0x45, 0x00, 0x00]); // PE\0\0
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.3 uint32() with large values', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint32(0) == 4294967295
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 4: int8 - signed 8-bit integer
  await test('4.1 int8() reads signed byte (positive)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int8(0) == 127
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x7F]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.2 int8() reads signed byte (negative)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int8(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.3 int8() reads signed byte (negative -128)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int8(0) == -128
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x80]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 5: int16 - signed 16-bit integer (little-endian)
  await test('5.1 int16() reads signed 16-bit (positive)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int16(0) == 32767
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0x7F]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('5.2 int16() reads signed 16-bit (negative)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int16(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('5.3 int16() reads signed 16-bit (negative -32768)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int16(0) == -32768
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x80]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 6: int32 - signed 32-bit integer (little-endian)
  await test('6.1 int32() reads signed 32-bit (positive)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int32(0) == 2147483647
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF, 0xFF, 0x7F]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('6.2 int32() reads signed 32-bit (negative)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int32(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('6.3 int32() reads signed 32-bit (negative -2147483648)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: int32(0) == -2147483648
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x80]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 7: Combined data access
  await test('7.1 Combined uint8, uint16, uint32 check', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition:
          uint8(0) == 0x4D and
          uint16(0) == 0x5A4D and
          uint32(0) == 0x5A4D
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x4D, 0x5A, 0x00, 0x00]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('7.2 Mixed signed and unsigned checks', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition:
          uint8(0) == 255 and
          int8(0) == -1 and
          uint16(0) == 65535 and
          int16(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 8: Offset calculations
  await test('8.1 Data access with calculated offset', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(2 + 1) == 0xAA
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x00, 0x00, 0xAA]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('8.2 Data access with variable offset', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint16(uint8(0)) == 0x5A4D
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x02, 0x00, 0x4D, 0x5A]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 9: Boundary checks
  await test('9.1 Access at end of data', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(3) == 0xFF
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x00, 0x00, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('9.2 Out of bounds access returns no match', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule Test {
        condition: uint8(10) == 0xFF
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 0) throw new Error('Expected no match for out of bounds');
  });

  // Test 10: Real-world patterns
  await test('10.1 PE file signature check (MZ + PE)', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule IsPE {
        condition:
          uint16(0) == 0x5A4D and
          uint32(uint32(0x3c)) == 0x00004550
      }
    `;
    scanner.addRules(rule);
    // Create simplified PE structure
    const data = new Uint8Array(256);
    data[0] = 0x4D; // M
    data[1] = 0x5A; // Z
    data[0x3c] = 0x80; // PE offset at 0x80
    data[0x80] = 0x50; // P
    data[0x81] = 0x45; // E
    data[0x82] = 0x00;
    data[0x83] = 0x00;
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected PE signature match');
  });

  await test('10.2 ELF file signature check', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule IsELF {
        condition:
          uint32(0) == 0x464C457F
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x7F, 0x45, 0x4C, 0x46]); // ELF magic
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected ELF signature match');
  });

  await test('10.3 ZIP file signature check', async () => {
    const scanner = new YaraScanner();
    const rule = `
      rule IsZIP {
        condition: uint32(0) == 0x04034b50
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x50, 0x4B, 0x03, 0x04]); // PK\3\4
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected ZIP signature match');
  });

  printSummary();
}

runTests();
