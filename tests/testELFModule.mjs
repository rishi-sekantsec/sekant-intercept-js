/**
 * Comprehensive ELF Module Integration Tests
 * Tests automatic detection, properties, helper methods, and condition evaluation
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { parseELFYaraFull as parseELFYara, createELFModule } from '../yaraELFModule.mjs';
import { test, asyncTest, printSummary, printSection } from './testingFramework.mjs';

// Helper to create minimal valid ELF file
function createMinimalELF64() {
  const elf = new Uint8Array(1024);
  
  // ELF Header
  // Magic: 0x7F 'E' 'L' 'F'
  elf[0] = 0x7F;
  elf[1] = 0x45; // 'E'
  elf[2] = 0x4C; // 'L'
  elf[3] = 0x46; // 'F'
  
  // Class: 64-bit
  elf[4] = 2;
  
  // Data encoding: Little-endian
  elf[5] = 1;
  
  // Version
  elf[6] = 1;
  
  // Entry point at offset 0x18 (8 bytes for 64-bit)
  const entryPoint = 0x400000;
  const view = new DataView(elf.buffer);
  view.setBigUint64(0x18, BigInt(entryPoint), true);
  
  // Program header offset at 0x20 (8 bytes)
  view.setBigUint64(0x20, BigInt(64), true); // Start after header
  
  // Section header offset at 0x28 (8 bytes)
  view.setBigUint64(0x28, BigInt(512), true);
  
  // Program header entry size at 0x36 (2 bytes)
  view.setUint16(0x36, 56, true);
  
  // Number of program headers at 0x38 (2 bytes)
  view.setUint16(0x38, 1, true);
  
  // Section header entry size at 0x3A (2 bytes)
  view.setUint16(0x3A, 64, true);
  
  // Number of section headers at 0x3C (2 bytes)
  view.setUint16(0x3C, 3, true);
  
  // Section name string table index at 0x3E (2 bytes)
  view.setUint16(0x3E, 2, true);
  
  // Add minimal program header at offset 64
  // PT_LOAD type
  view.setUint32(64, 1, true);
  
  // Minimal section headers at offset 512
  // Section 0 (null section)
  // Section 1 (.text)
  view.setBigUint64(512 + 64 + 24, BigInt(256), true); // offset
  view.setBigUint64(512 + 64 + 32, BigInt(128), true); // size
  
  // Section 2 (.data)
  view.setBigUint64(512 + 128 + 24, BigInt(384), true); // offset
  view.setBigUint64(512 + 128 + 32, BigInt(64), true); // size
  
  return elf;
}

printSection('ELF MODULE INTEGRATION TEST SUITE');

// ============================================================================
// SECTION 1: Basic ELF Parsing
// ============================================================================

console.log('\n📦 SECTION 1: Basic ELF Parsing');
console.log('-'.repeat(70));

await asyncTest('1.1 Parse minimal 64-bit ELF', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  
  if (!parsed || parsed.error) {
    throw new Error('Failed to parse ELF');
  }
  if (!parsed.is_64bit) {
    throw new Error('Expected 64-bit ELF');
  }
});

await asyncTest('1.2 ELF entry point', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  
  if (parsed.entry_point !== 0x400000) {
    throw new Error(`Expected entry point 0x400000, got ${parsed.entry_point}`);
  }
});

await asyncTest('1.3 ELF endianness', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  
  if (parsed.endianness !== 'little') {
    throw new Error(`Expected little endian, got ${parsed.endianness}`);
  }
});

await asyncTest('1.4 ELF sections array', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  
  if (!Array.isArray(parsed.sections)) {
    throw new Error('Expected sections to be an array');
  }
  if (parsed.sections.length !== 3) {
    throw new Error(`Expected 3 sections, got ${parsed.sections.length}`);
  }
});

await asyncTest('1.5 ELF program headers', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  
  if (!Array.isArray(parsed.program_headers)) {
    throw new Error('Expected program_headers to be an array');
  }
  if (parsed.program_headers.length !== 1) {
    throw new Error(`Expected 1 program header, got ${parsed.program_headers.length}`);
  }
});

await asyncTest('1.6 Invalid data returns error', async () => {
  const data = new Uint8Array([1, 2, 3, 4]);
  const parsed = await parseELFYara(data);
  
  if (!parsed.error) {
    throw new Error('Expected error for invalid ELF');
  }
});

// ============================================================================
// SECTION 2: ELF Module Creation
// ============================================================================

console.log('\n🏗️  SECTION 2: ELF Module Creation');
console.log('-'.repeat(70));

await asyncTest('2.1 Create ELF module from parsed data', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  const module = createELFModule(parsed);
  
  if (!module) {
    throw new Error('Failed to create ELF module');
  }
  if (module.entry_point !== 0x400000) {
    throw new Error('Module entry point incorrect');
  }
});

await asyncTest('2.2 ELF module has helper methods', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  const module = createELFModule(parsed);
  
  if (typeof module.is_32bit !== 'function') {
    throw new Error('Expected is_32bit to be a function');
  }
  if (typeof module.is_little_endian !== 'function') {
    throw new Error('Expected is_little_endian to be a function');
  }
  if (typeof module.imports_library !== 'function') {
    throw new Error('Expected imports_library to be a function');
  }
});

await asyncTest('2.3 ELF module helper methods work', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  const module = createELFModule(parsed);
  
  if (module.is_64bit !== true) {
    throw new Error('Expected is_64bit to be true');
  }
  if (module.is_32bit() !== false) {
    throw new Error('Expected is_32bit() to return false');
  }
  if (module.is_little_endian() !== true) {
    throw new Error('Expected is_little_endian() to return true');
  }
});

await asyncTest('2.4 ELF module number_of_sections', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  const module = createELFModule(parsed);
  
  if (module.number_of_sections !== 3) {
    throw new Error(`Expected 3 sections, got ${module.number_of_sections}`);
  }
});

await asyncTest('2.5 ELF module number_of_segments', async () => {
  const data = createMinimalELF64();
  const parsed = await parseELFYara(data);
  const module = createELFModule(parsed);
  
  if (module.number_of_segments !== 1) {
    throw new Error(`Expected 1 segment, got ${module.number_of_segments}`);
  }
});

// ============================================================================
// SECTION 3: Scanner Integration with Automatic Detection
// ============================================================================

console.log('\n🔍 SECTION 3: Scanner Integration');
console.log('-'.repeat(70));

await asyncTest('3.1 Automatic ELF detection', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Detected {
      condition:
        uint32(0) == 0x464C457F
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('Expected ELF to be detected');
  }
});

await asyncTest('3.2 ELF module automatically available', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Entry_Point {
      condition:
        elf.entry_point > 0
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('ELF module not available in conditions');
  }
});

await asyncTest('3.3 ELF is_64bit property', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_64bit {
      condition:
        elf.is_64bit
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('elf.is_64bit not working');
  }
});

await asyncTest('3.4 ELF number_of_sections', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Sections {
      condition:
        elf.number_of_sections == 3
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('elf.number_of_sections not working');
  }
});

await asyncTest('3.5 Non-ELF file has no ELF module', async () => {
  const data = new TextEncoder().encode('Not an ELF file');
  const scanner = new YaraScanner();
  
  const rule = `
    rule Not_ELF {
      condition:
        not elf.is_64bit
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  // Should not match because elf module isn't available
  if (results.length !== 0) {
    throw new Error('Expected no match for non-ELF file');
  }
});

// ============================================================================
// SECTION 4: Combined ELF Conditions
// ============================================================================

console.log('\n🔗 SECTION 4: Combined ELF Conditions');
console.log('-'.repeat(70));

await asyncTest('4.1 Multiple ELF properties (AND)', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Multi_Check {
      condition:
        elf.is_64bit and elf.entry_point > 0
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('Combined ELF properties failed');
  }
});

await asyncTest('4.2 Multiple ELF properties (complex)', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Complex {
      condition:
        elf.entry_point == 0x400000 and
        elf.number_of_sections == 3 and
        elf.number_of_segments == 1
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('Complex ELF condition failed');
  }
});

await asyncTest('4.3 ELF with magic bytes check', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule ELF_Magic_Check {
      condition:
        uint32(0) == 0x464C457F and elf.is_64bit
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('ELF magic bytes + module check failed');
  }
});

// ============================================================================
// SECTION 5: ELF Module Properties
// ============================================================================

console.log('\n📊 SECTION 5: ELF Module Properties');
console.log('-'.repeat(70));

await asyncTest('5.1 Access entry_point property', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule Entry_Point_Check {
      condition:
        elf.entry_point == 0x400000
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('entry_point property access failed');
  }
});

await asyncTest('5.2 Access is_64bit property', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule Is_64bit_Check {
      condition:
        elf.is_64bit
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('is_64bit property access failed');
  }
});

await asyncTest('5.3 Access number_of_sections property', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule Sections_Count {
      condition:
        elf.number_of_sections > 0
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('number_of_sections property access failed');
  }
});

await asyncTest('5.4 Access number_of_segments property', async () => {
  const data = createMinimalELF64();
  const scanner = new YaraScanner();
  
  const rule = `
    rule Segments_Count {
      condition:
        elf.number_of_segments == 1
    }
  `;
  
  scanner.addRules(rule);
  const results = await scanner.scan(data);
  
  if (results.length !== 1) {
    throw new Error('number_of_segments property access failed');
  }
});

// ============================================================================
// Summary
// ============================================================================

printSummary();
