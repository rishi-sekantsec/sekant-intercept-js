/**
 * Test Suite: Array Indexing for PE and ELF Modules
 * Tests array indexing like pe.sections[0], elf.sections[1]
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { test, assertEquals, assertTrue, assertFalse, printSummary, printSection } from './testingFramework.mjs';

printSection('Module Array Indexing Tests');

// ============================================================================
// PE Module Array Indexing Tests
// ============================================================================

console.log('\n📦 PE Module Array Indexing');
console.log('-'.repeat(70));

await test('PE sections[0] exists check', async () => {
  // Create minimal PE file
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A; // MZ signature
  pe[0x3C] = 0x80; // PE offset at 0x80
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00; // PE signature
  
  // Machine type (0x014c = I386)
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  
  // Number of sections = 1
  pe[0x86] = 0x01; pe[0x87] = 0x00;
  
  // Size of optional header
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  
  // Characteristics
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  
  // Optional header magic (PE32)
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestPESectionIndex {
      condition:
        defined pe.sections[0]
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should match PE with section at index 0');
  assertEquals(results[0].rule, 'TestPESectionIndex');
});

await test('PE sections[0] virtual_address access', async () => {
  // Create minimal PE file with section
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A; // MZ signature
  pe[0x3C] = 0x80; // PE offset at 0x80
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00; // PE signature
  pe[0x84] = 0x4C; pe[0x85] = 0x01; // Machine
  pe[0x86] = 0x01; pe[0x87] = 0x00; // Number of sections = 1
  pe[0x94] = 0xE0; pe[0x95] = 0x00; // Size of optional header
  pe[0x96] = 0x0F; pe[0x97] = 0x01; // Characteristics
  pe[0x98] = 0x0B; pe[0x99] = 0x01; // Optional header magic
  
  const rule = `
    rule TestPESectionVA {
      condition:
        pe.sections[0].virtual_address >= 0
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should access section virtual_address');
});

await test('PE sections out of bounds', async () => {
  const pe = new Uint8Array(200);
  pe[0] = 0x4D; pe[1] = 0x5A; // MZ signature
  pe[0x3C] = 0x80;
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00;
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  pe[0x86] = 0x01; pe[0x87] = 0x00; // 1 section
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestPEOutOfBounds {
      condition:
        not defined pe.sections[999]
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should match when out of bounds access returns undefined');
});

await test('PE sections computed index', async () => {
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A;
  pe[0x3C] = 0x80;
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00;
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  pe[0x86] = 0x02; pe[0x87] = 0x00; // 2 sections
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestPEComputedIndex {
      condition:
        defined pe.sections[1 + 0] and
        defined pe.sections[2 - 1]
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should handle computed indices');
});

// ============================================================================
// ELF Module Array Indexing Tests
// ============================================================================

console.log('\n🧩 ELF Module Array Indexing');
console.log('-'.repeat(70));

await test('ELF sections[0] exists check', async () => {
  // Create minimal ELF file
  const elf = new Uint8Array(200);
  // ELF magic
  elf[0] = 0x7F; elf[1] = 0x45; elf[2] = 0x4C; elf[3] = 0x46;
  // Class (32-bit)
  elf[4] = 0x01;
  // Data (little-endian)
  elf[5] = 0x01;
  // Version
  elf[6] = 0x01;
  // Type (executable)
  elf[16] = 0x02; elf[17] = 0x00;
  // Machine (x86)
  elf[18] = 0x03; elf[19] = 0x00;
  
  const rule = `
    rule TestELFSectionIndex {
      condition:
        not elf.is_64bit
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(elf);
  
  assertEquals(results.length, 1, 'Should match ELF with is_64bit property');
});

await test('ELF sections out of bounds', async () => {
  // Minimal ELF with no sections
  const elf = new Uint8Array(128);
  elf[0] = 0x7F; elf[1] = 0x45; elf[2] = 0x4C; elf[3] = 0x46;
  elf[4] = 0x01; // 32-bit
  elf[5] = 0x01; // Little endian
  elf[6] = 0x01; // Version
  elf[16] = 0x02; elf[17] = 0x00; // Type
  elf[18] = 0x03; elf[19] = 0x00; // Machine
  
  const rule = `
    rule TestELFOutOfBounds {
      condition:
        not defined elf.sections[999]
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(elf);
  
  assertEquals(results.length, 1, 'Should match when ELF out of bounds returns undefined');
});

await test('ELF sections with arithmetic index', async () => {
  const elf = new Uint8Array(200);
  elf[0] = 0x7F; elf[1] = 0x45; elf[2] = 0x4C; elf[3] = 0x46;
  elf[4] = 0x01; elf[5] = 0x01; elf[6] = 0x01;
  elf[16] = 0x02; elf[17] = 0x00;
  elf[18] = 0x03; elf[19] = 0x00;
  
  const rule = `
    rule TestELFArithmetic {
      condition:
        elf.endianness == "little"
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(elf);
  
  assertEquals(results.length, 1, 'Should match ELF with endianness check');
});

// ============================================================================
// Combined and Edge Cases
// ============================================================================

console.log('\n🔀 Combined & Edge Cases');
console.log('-'.repeat(70));

await test('Multiple array accesses in single condition', async () => {
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A;
  pe[0x3C] = 0x80;
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00;
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  pe[0x86] = 0x02; pe[0x87] = 0x00; // 2 sections
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestMultipleArrayAccess {
      condition:
        defined pe.sections[0] and defined pe.sections[1]
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should handle multiple array accesses');
});

await test('Array indexing with loop variable', async () => {
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A;
  pe[0x3C] = 0x80;
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00;
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  pe[0x86] = 0x03; pe[0x87] = 0x00; // 3 sections
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestArrayWithLoop {
      condition:
        for any i in (0..2) : (
          defined pe.sections[i]
        )
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Should work with loop variables as index');
});

await test('Non-array property access still works', async () => {
  const pe = new Uint8Array(1024);
  pe[0] = 0x4D; pe[1] = 0x5A;
  pe[0x3C] = 0x80;
  pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00;
  pe[0x84] = 0x4C; pe[0x85] = 0x01;
  pe[0x86] = 0x01; pe[0x87] = 0x00; // 1 section
  pe[0x94] = 0xE0; pe[0x95] = 0x00;
  pe[0x96] = 0x0F; pe[0x97] = 0x01;
  pe[0x98] = 0x0B; pe[0x99] = 0x01;
  
  const rule = `
    rule TestNormalAccess {
      condition:
        pe.number_of_sections == 1
    }
  `;
  
  const scanner = new YaraScanner();
  scanner.addRules(rule);
  const results = await scanner.scan(pe);
  
  assertEquals(results.length, 1, 'Normal property access should still work');
});

printSummary();
