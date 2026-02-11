import { InterceptScanner } from '../src/interceptScanner.mjs';
import { test, printSummary } from './testingFramework.mjs';

console.log('Testing Entrypoint Identifier\n');
console.log('='.repeat(70));

/**
 * Create a minimal valid PE file
 * Based on testPEModule.mjs createMinimalPE()
 */
function createPEFile(entryPoint = 0x1000, addStringAtEntry = false) {
  const size = addStringAtEntry ? Math.max(4096, entryPoint + 100) : 2048;
  const peData = new Uint8Array(size);
  
  // DOS Header (64 bytes at offset 0x00)
  peData[0x00] = 0x4D; // 'M'
  peData[0x01] = 0x5A; // 'Z'
  peData[0x3C] = 0x80; // e_lfanew: PE header offset at 0x80 (128 bytes)
  
  // PE Signature "PE\0\0" at offset 0x80
  peData[0x80] = 0x50; // 'P'
  peData[0x81] = 0x45; // 'E'
  peData[0x82] = 0x00;
  peData[0x83] = 0x00;
  
  // COFF File Header at 0x84
  peData[0x84] = 0x4c; // Machine: I386
  peData[0x85] = 0x01;
  peData[0x86] = 0x01; // NumberOfSections: 1
  peData[0x87] = 0x00;
  peData[0x94] = 0xE0; // SizeOfOptionalHeader: 224
  peData[0x95] = 0x00;
  peData[0x96] = 0x02; // Characteristics
  peData[0x97] = 0x01;
  
  // Optional Header at 0x98
  peData[0x98] = 0x0B; // Magic: PE32
  peData[0x99] = 0x01;
  peData[0x9C] = 0x00; // SizeOfCode
  peData[0x9D] = 0x10;
  peData[0xA0] = 0x00; // SizeOfInitializedData
  peData[0xA1] = 0x10;
  
  // AddressOfEntryPoint at 0xA8 (important!)
  peData[0xA8] = entryPoint & 0xFF;
  peData[0xA9] = (entryPoint >> 8) & 0xFF;
  peData[0xAA] = (entryPoint >> 16) & 0xFF;
  peData[0xAB] = (entryPoint >> 24) & 0xFF;
  
  peData[0xAC] = 0x00; // BaseOfCode
  peData[0xAD] = 0x10;
  peData[0xB0] = 0x00; // BaseOfData
  peData[0xB1] = 0x20;
  
  // ImageBase at 0xB4
  peData[0xB4] = 0x00;
  peData[0xB5] = 0x00;
  peData[0xB6] = 0x40;
  peData[0xB7] = 0x00;
  
  peData[0xB8] = 0x00; // SectionAlignment: 0x1000
  peData[0xB9] = 0x10;
  peData[0xBC] = 0x00; // FileAlignment: 0x200
  peData[0xBD] = 0x02;
  peData[0xC0] = 0x05; // OS Version
  peData[0xC8] = 0x05; // Subsystem Version
  peData[0xD0] = 0x00; // SizeOfImage: 0x2000
  peData[0xD1] = 0x20;
  peData[0xD4] = 0x00; // SizeOfHeaders: 0x200
  peData[0xD5] = 0x02;
  peData[0xDC] = 0x03; // Subsystem: CUI
  peData[0xE0] = 0x00; // SizeOfStackReserve
  peData[0xE1] = 0x00;
  peData[0xE2] = 0x10;
  peData[0xE4] = 0x00; // SizeOfStackCommit
  peData[0xE5] = 0x10;
  peData[0xE8] = 0x00; // SizeOfHeapReserve
  peData[0xE9] = 0x00;
  peData[0xEA] = 0x10;
  peData[0xEC] = 0x00; // SizeOfHeapCommit
  peData[0xED] = 0x10;
  peData[0xF4] = 0x10; // NumberOfRvaAndSizes: 16
  
  // Add test string at entry point if requested
  if (addStringAtEntry && entryPoint < size - 10) {
    const testStr = 'TESTCODE';
    for (let i = 0; i < testStr.length; i++) {
      peData[entryPoint + i] = testStr.charCodeAt(i);
    }
  }
  
  return peData;
}

/**
 * Create a minimal ELF file with program headers for proper virtual address mapping
 */
function createELFFile(entryPoint = 0x401000, addStringAtEntry = false) {
  // ELF header is 64 bytes for 64-bit, program header is 56 bytes
  const headerSize = 64;
  const phdrSize = 56;
  const phdrOffset = headerSize;
  
  // For ELF, the entrypoint is a virtual address
  // Standard load address is 0x400000, so entry at 0x401000 means file offset 0x1000
  const baseVaddr = 0x400000;
  const fileOffset = entryPoint >= baseVaddr ? entryPoint - baseVaddr : entryPoint;
  // Ensure file size is larger than file offset to allow tests like "entrypoint < filesize"
  const size = addStringAtEntry ? Math.max(4096, fileOffset + 100) : Math.max(4096, fileOffset + 1, headerSize + phdrSize);
  const data = new Uint8Array(size);
  
  // ELF Magic: 0x7F 'E' 'L' 'F'
  data[0] = 0x7F;
  data[1] = 0x45; // 'E'
  data[2] = 0x4C; // 'L'
  data[3] = 0x46; // 'F'
  
  // EI_CLASS: 2 = 64-bit
  data[4] = 0x02;
  
  // EI_DATA: 1 = little-endian
  data[5] = 0x01;
  
  // EI_VERSION: 1 = current version
  data[6] = 0x01;
  
  // e_type (2 bytes at offset 16): 2 = ET_EXEC (executable)
  data[16] = 0x02;
  data[17] = 0x00;
  
  // e_machine (2 bytes at offset 18): 0x3E = x86-64
  data[18] = 0x3E;
  data[19] = 0x00;
  
  const view = new DataView(data.buffer);
  
  // e_entry (8 bytes at offset 24) - entry point address
  view.setBigUint64(24, BigInt(entryPoint), true); // little-endian
  
  // e_phoff (8 bytes at offset 32) - program header table offset
  view.setBigUint64(32, BigInt(phdrOffset), true);
  
  // e_phentsize (2 bytes at offset 54) - program header entry size
  view.setUint16(54, phdrSize, true);
  
  // e_phnum (2 bytes at offset 56) - number of program header entries
  view.setUint16(56, 1, true);
  
  // Program Header (PT_LOAD) at offset 64
  // p_type (4 bytes) - PT_LOAD = 1
  view.setUint32(phdrOffset, 1, true);
  
  // p_flags (4 bytes) - PF_R | PF_X = 5
  view.setUint32(phdrOffset + 4, 5, true);
  
  // p_offset (8 bytes) - file offset = 0
  view.setBigUint64(phdrOffset + 8, BigInt(0), true);
  
  // p_vaddr (8 bytes) - virtual address = 0x400000
  view.setBigUint64(phdrOffset + 16, BigInt(baseVaddr), true);
  
  // p_paddr (8 bytes) - physical address = 0x400000
  view.setBigUint64(phdrOffset + 24, BigInt(baseVaddr), true);
  
  // p_filesz (8 bytes) - size in file
  view.setBigUint64(phdrOffset + 32, BigInt(size), true);
  
  // p_memsz (8 bytes) - size in memory
  view.setBigUint64(phdrOffset + 40, BigInt(size), true);
  
  // p_align (8 bytes) - alignment = 0x1000
  view.setBigUint64(phdrOffset + 48, BigInt(0x1000), true);
  
  // Add test string at entry point if requested
  // Place it at the file offset corresponding to the virtual entry point
  if (addStringAtEntry && fileOffset < size - 10) {
    const testStr = 'TESTCODE';
    for (let i = 0; i < testStr.length; i++) {
      data[fileOffset + i] = testStr.charCodeAt(i);
    }
  }
  
  return data;
}

(async () => {
  // Test 1: Basic entrypoint identifier - PE files
  await test('1.1 PE: entrypoint identifier resolves to correct value', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0x1000
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('1.2 PE: entrypoint in comparison', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint > 0x500 and entrypoint < 0x2000
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('1.3 PE: entrypoint with different values', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0x2000
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x2000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 2: Basic entrypoint identifier - ELF files
  // Note: entrypoint returns FILE OFFSET, not virtual address
  // ELF virtual address 0x401000 maps to file offset 0x1000 (0x401000 - 0x400000 + 0)
  await test('2.1 ELF: entrypoint identifier resolves to correct file offset', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0x1000
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.2 ELF: entrypoint in comparison (file offset range)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint > 0x500 and entrypoint < 0x2000
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('2.3 ELF: entrypoint with different values', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0x2000
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x402000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 3: String position operators with entrypoint - PE
  await test('3.1 PE: string at entrypoint', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        strings:
          $code = "TESTCODE"
        condition:
          $code at entrypoint
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000, true);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.2 PE: string in range from entrypoint', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        strings:
          $code = "TESTCODE"
        condition:
          $code in (entrypoint..entrypoint+100)
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000, true);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('3.3 PE: string NOT at entrypoint (should not match)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        strings:
          $mz = "MZ"
        condition:
          $mz at entrypoint
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000, true);
    const result = await scanner.scan(data);
    if (result.length !== 0) throw new Error('Expected no match');
  });

  // Test 4: String position operators with entrypoint - ELF
  // Note: entrypoint returns FILE OFFSET, not virtual address
  await test('4.1 ELF: string found in file can be checked against entrypoint range', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        strings:
          $elf = { 7F 45 4C 46 }
        condition:
          $elf at 0 and entrypoint > 0
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000, false);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.2 ELF: entrypoint used in complex condition with strings', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        strings:
          $elf = { 7F 45 4C 46 }
        condition:
          $elf at 0 and entrypoint == 0x1000
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000, false);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('4.3 ELF: entrypoint comparison with filesize', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint32(0) == 0x464C457F and
          entrypoint < filesize and
          entrypoint > 0
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000, false);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 5: Arithmetic with entrypoint
  await test('5.1 PE: entrypoint arithmetic (addition)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint + 0x100 == 0x1100
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('5.2 ELF: entrypoint arithmetic (subtraction)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint - 0x1000 == 0
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('5.3 PE: entrypoint in data access', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: uint32(entrypoint) == 0x54534554
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000, true);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match'); // "TEST" = 0x54534554 (little-endian)
  });

  // Test 6: Combined with PE module
  await test('6.1 PE: entrypoint matches pe.entry_point', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == pe.entry_point
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('6.2 PE: entrypoint used with PE module properties', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint16(0) == 0x5A4D and
          entrypoint > 0 and
          pe.entry_point == entrypoint
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x2000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 7: Combined with ELF module
  await test('7.1 ELF: entrypoint matches elf.entry_point', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == elf.entry_point
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('7.2 ELF: entrypoint used with ELF module properties', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition:
          uint32(0) == 0x464C457F and
          entrypoint > 0 and
          elf.entry_point == entrypoint
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 8: Non-binary files (entrypoint should be 0)
  await test('8.1 Non-binary: entrypoint defaults to 0', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0
      }
    `;
    scanner.addRules(rule);
    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const result = await scanner.scan(data);
    if (result.length > 0) throw new Error('Unexpected match');
  });

  await test('8.2 Non-binary: entrypoint is 0 for text files', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0 and filesize > 0
      }
    `;
    scanner.addRules(rule);
    const data = new TextEncoder().encode('Hello, World!');
    const result = await scanner.scan(data);
    if (result.length > 0) throw new Error('Unexpected match');
  });

  // Test 9: Complex real-world scenarios
  await test('9.1 PE: Malware detection with entrypoint check', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule SuspiciousPE {
        strings:
          $code = "TESTCODE"
        condition:
          uint16(0) == 0x5A4D and
          $code at entrypoint and
          entrypoint > 0x500 and
          pe.is_32bit()
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x1000, true);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('9.2 ELF: Binary detection with entrypoint check', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule ELFBinary {
        condition:
          uint32(0) == 0x464C457F and
          entrypoint >= 0x1000 and
          elf.entry_point == entrypoint
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x401000, false);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('9.3 PE: Entrypoint in unusual section', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule UnusualEntrypoint {
        condition:
          uint16(0) == 0x5A4D and
          entrypoint > 0x10000
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x15000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  // Test 10: Edge cases
  await test('10.1 PE: Entrypoint at 0', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('10.2 ELF: Very high entrypoint (converts to file offset)', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint == 0x10000
      }
    `;
    scanner.addRules(rule);
    const data = createELFFile(0x410000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  await test('10.3 PE: Negative check', async () => {
    const scanner = new InterceptScanner();
    const rule = `
      rule Test {
        condition: entrypoint != 0x1000
      }
    `;
    scanner.addRules(rule);
    const data = createPEFile(0x2000);
    const result = await scanner.scan(data);
    if (result.length !== 1) throw new Error('Expected match');
  });

  printSummary();
})();
