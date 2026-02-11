import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, printSummary, printSection } from './testingFramework.mjs';

printSection('Testing Big-Endian Data Access Functions');

(async () => {
  // Test 1: uint16be() - Big-endian 16-bit unsigned
  await test('1.1 uint16be() reads two bytes (big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint16be(0) == 0x1234
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('1.2 uint16be() vs uint16() - endianness difference', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint16(0) == 0x3412 and
          uint16be(0) == 0x1234
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('1.3 uint16be() network byte order', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint16be(0) == 0x8080
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x80, 0x80]); // HTTP port in network byte order
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 2: uint32be() - Big-endian 32-bit unsigned
  await test('2.1 uint32be() reads four bytes (big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint32be(0) == 0x12345678
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.2 uint32be() vs uint32() - endianness difference', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint32(0) == 0x78563412 and
          uint32be(0) == 0x12345678
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.3 uint32be() ELF magic number', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint32be(0) == 0x7F454C46
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x7F, 0x45, 0x4C, 0x46]); // ELF magic
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 3: int16be() - Big-endian 16-bit signed
  await test('3.1 int16be() reads signed 16-bit (positive, big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: int16be(0) == 0x1234
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.2 int16be() reads signed 16-bit (negative, big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: int16be(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.3 int16be() vs int16() - endianness difference', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          int16(0) == 0x3412 and
          int16be(0) == 0x1234
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 4: int32be() - Big-endian 32-bit signed
  await test('4.1 int32be() reads signed 32-bit (positive, big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: int32be(0) == 0x12345678
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.2 int32be() reads signed 32-bit (negative, big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: int32be(0) == -1
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.3 int32be() vs int32() - endianness difference', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          int32(0) == 0x78563412 and
          int32be(0) == 0x12345678
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 5: Mixed endianness
  await test('5.1 Mixed little and big-endian in one rule', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint16(0) == 0x3412 and
          uint16be(2) == 0x5678
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('5.2 All data types mixed', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint8(0) == 0x12 and
          int8(1) == 0x34 and
          uint16(2) == 0x7856 and
          uint16be(2) == 0x5678 and
          int16(4) == 0x10EF and
          int16be(4) == -4336
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0xEF, 0x10]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 6: Real-world scenarios
  await test('6.1 Network protocol detection (big-endian port)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule HTTPPort {
        condition: uint16be(0) == 80 or uint16be(0) == 443
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x50]); // Port 80 in network byte order
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('6.2 Java class file magic (big-endian)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule JavaClass {
        condition: uint32be(0) == 0xCAFEBABE
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('6.3 Nested big-endian access', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint32be(uint16be(0)) == 0x12345678
      }
    `;
    scanner.addRules(rule);
    // uint16be(0) = 0x0004, so we check uint32be(4)
    const data = new Uint8Array([0x00, 0x04, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  printSummary();
})();
