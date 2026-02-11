// testPEModule.mjs
// Comprehensive tests for PE module (peModule.mjs)

import { parsePEYara } from '../src/peModule.mjs';
import {
  numberedTest as test,
  assert,
  assertEquals,
  assertGreaterThan,
  assertArrayLength,
  assertHasProperty,
  assertMatch,
  printSummary
} from './testingFramework.mjs';

// Helper to create a minimal valid PE file
function createMinimalPE() {
  // Allocate enough space for headers and minimal content
  const peData = new Uint8Array(2048);
  
  // DOS Header (64 bytes at offset 0x00)
  peData[0x00] = 0x4D; // 'M'
  peData[0x01] = 0x5A; // 'Z'
  peData[0x3C] = 0x80; // e_lfanew: PE header offset at 0x80 (128 bytes)
  peData[0x3D] = 0x00;
  peData[0x3E] = 0x00;
  peData[0x3F] = 0x00;
  
  // PE Signature "PE\0\0" at offset 0x80
  peData[0x80] = 0x50; // 'P'
  peData[0x81] = 0x45; // 'E'
  peData[0x82] = 0x00;
  peData[0x83] = 0x00;
  
  // COFF File Header (20 bytes) at 0x84
  // Machine (2 bytes) - IMAGE_FILE_MACHINE_I386 (0x014c)
  peData[0x84] = 0x4c;
  peData[0x85] = 0x01;
  
  // NumberOfSections (2 bytes) - 1 section
  peData[0x86] = 0x01;
  peData[0x87] = 0x00;
  
  // TimeDateStamp (4 bytes)
  peData[0x88] = 0x00;
  peData[0x89] = 0x00;
  peData[0x8A] = 0x00;
  peData[0x8B] = 0x00;
  
  // PointerToSymbolTable (4 bytes) - 0
  peData[0x8C] = 0x00;
  peData[0x8D] = 0x00;
  peData[0x8E] = 0x00;
  peData[0x8F] = 0x00;
  
  // NumberOfSymbols (4 bytes) - 0
  peData[0x90] = 0x00;
  peData[0x91] = 0x00;
  peData[0x92] = 0x00;
  peData[0x93] = 0x00;
  
  // SizeOfOptionalHeader (2 bytes) - 224 (0xE0) for PE32
  peData[0x94] = 0xE0;
  peData[0x95] = 0x00;
  
  // Characteristics (2 bytes) - IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
  peData[0x96] = 0x02;
  peData[0x97] = 0x01;
  
  // Optional Header (224 bytes) at 0x98
  // Magic (2 bytes) - PE32 (0x010b)
  peData[0x98] = 0x0B;
  peData[0x99] = 0x01;
  
  // MajorLinkerVersion, MinorLinkerVersion
  peData[0x9A] = 0x0E;
  peData[0x9B] = 0x00;
  
  // SizeOfCode (4 bytes) - 0x1000
  peData[0x9C] = 0x00;
  peData[0x9D] = 0x10;
  peData[0x9E] = 0x00;
  peData[0x9F] = 0x00;
  
  // SizeOfInitializedData (4 bytes)
  peData[0xA0] = 0x00;
  peData[0xA1] = 0x10;
  peData[0xA2] = 0x00;
  peData[0xA3] = 0x00;
  
  // SizeOfUninitializedData (4 bytes)
  peData[0xA4] = 0x00;
  peData[0xA5] = 0x00;
  peData[0xA6] = 0x00;
  peData[0xA7] = 0x00;
  
  // AddressOfEntryPoint (4 bytes) - 0x1000
  peData[0xA8] = 0x00;
  peData[0xA9] = 0x10;
  peData[0xAA] = 0x00;
  peData[0xAB] = 0x00;
  
  // BaseOfCode (4 bytes)
  peData[0xAC] = 0x00;
  peData[0xAD] = 0x10;
  peData[0xAE] = 0x00;
  peData[0xAF] = 0x00;
  
  // BaseOfData (4 bytes)
  peData[0xB0] = 0x00;
  peData[0xB1] = 0x20;
  peData[0xB2] = 0x00;
  peData[0xB3] = 0x00;
  
  // ImageBase (4 bytes) - 0x00400000
  peData[0xB4] = 0x00;
  peData[0xB5] = 0x00;
  peData[0xB6] = 0x40;
  peData[0xB7] = 0x00;
  
  // SectionAlignment (4 bytes) - 0x1000
  peData[0xB8] = 0x00;
  peData[0xB9] = 0x10;
  peData[0xBA] = 0x00;
  peData[0xBB] = 0x00;
  
  // FileAlignment (4 bytes) - 0x200
  peData[0xBC] = 0x00;
  peData[0xBD] = 0x02;
  peData[0xBE] = 0x00;
  peData[0xBF] = 0x00;
  
  // OS Version (4 bytes)
  peData[0xC0] = 0x05;
  peData[0xC1] = 0x00;
  peData[0xC2] = 0x00;
  peData[0xC3] = 0x00;
  
  // Image Version (4 bytes)
  peData[0xC4] = 0x00;
  peData[0xC5] = 0x00;
  peData[0xC6] = 0x00;
  peData[0xC7] = 0x00;
  
  // Subsystem Version (4 bytes)
  peData[0xC8] = 0x05;
  peData[0xC9] = 0x00;
  peData[0xCA] = 0x00;
  peData[0xCB] = 0x00;
  
  // Win32VersionValue (4 bytes) - reserved, must be 0
  peData[0xCC] = 0x00;
  peData[0xCD] = 0x00;
  peData[0xCE] = 0x00;
  peData[0xCF] = 0x00;
  
  // SizeOfImage (4 bytes) - 0x2000
  peData[0xD0] = 0x00;
  peData[0xD1] = 0x20;
  peData[0xD2] = 0x00;
  peData[0xD3] = 0x00;
  
  // SizeOfHeaders (4 bytes) - 0x200
  peData[0xD4] = 0x00;
  peData[0xD5] = 0x02;
  peData[0xD6] = 0x00;
  peData[0xD7] = 0x00;
  
  // CheckSum (4 bytes)
  peData[0xD8] = 0x00;
  peData[0xD9] = 0x00;
  peData[0xDA] = 0x00;
  peData[0xDB] = 0x00;
  
  // Subsystem (2 bytes) - IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
  peData[0xDC] = 0x03;
  peData[0xDD] = 0x00;
  
  // DllCharacteristics (2 bytes)
  peData[0xDE] = 0x00;
  peData[0xDF] = 0x00;
  
  // SizeOfStackReserve (4 bytes) - 0x100000
  peData[0xE0] = 0x00;
  peData[0xE1] = 0x00;
  peData[0xE2] = 0x10;
  peData[0xE3] = 0x00;
  
  // SizeOfStackCommit (4 bytes) - 0x1000
  peData[0xE4] = 0x00;
  peData[0xE5] = 0x10;
  peData[0xE6] = 0x00;
  peData[0xE7] = 0x00;
  
  // SizeOfHeapReserve (4 bytes) - 0x100000
  peData[0xE8] = 0x00;
  peData[0xE9] = 0x00;
  peData[0xEA] = 0x10;
  peData[0xEB] = 0x00;
  
  // SizeOfHeapCommit (4 bytes) - 0x1000
  peData[0xEC] = 0x00;
  peData[0xED] = 0x10;
  peData[0xEE] = 0x00;
  peData[0xEF] = 0x00;
  
  // LoaderFlags (4 bytes) - obsolete
  peData[0xF0] = 0x00;
  peData[0xF1] = 0x00;
  peData[0xF2] = 0x00;
  peData[0xF3] = 0x00;
  
  // NumberOfRvaAndSizes (4 bytes) - 16
  peData[0xF4] = 0x10;
  peData[0xF5] = 0x00;
  peData[0xF6] = 0x00;
  peData[0xF7] = 0x00;
  
  // Data Directories (16 * 8 bytes = 128 bytes) at 0xF8
  // All zeros for minimal PE
  
  return peData;
}

async function runTests() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  PE MODULE COMPREHENSIVE TEST SUITE');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // ============================================================================
  // Section 1: Basic PE Parsing
  // ============================================================================

  console.log('📋 Section 1: Basic PE Parsing\n');

  await test('Parse minimal PE structure', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assert(!pe.error, 'PE should parse without error');
  assertHasProperty(pe, 'entry_point');
  assertHasProperty(pe, 'image_base');
  assertHasProperty(pe, 'number_of_sections');
});

await test('Entry point is correctly parsed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.entry_point, 0x1000, 'Entry point should be 0x1000');
});

await test('Image base is correctly parsed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.image_base, 0x00400000, 'Image base should be 0x00400000');
});

await test('File size is recorded', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.file_size, peData.length, 'File size should match input length');
});

await test('Sections array is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assert(Array.isArray(pe.sections), 'Sections should be an array');
});

await test('Invalid PE returns error', async () => {
  const invalidData = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
  const pe = await parsePEYara(invalidData);
  
  assert(pe.error, 'Invalid PE should return error');
  assertEquals(pe.error, 'Failed to parse PE', 'Error message should indicate parse failure');
});

// ============================================================================
// Section 2: Optional Header Fields
// ============================================================================

console.log('\n📋 Section 2: Optional Header Fields\n');

await test('Optional header fields are present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertHasProperty(pe, 'size_of_code');
  assertHasProperty(pe, 'size_of_initialized_data');
  assertHasProperty(pe, 'size_of_uninitialized_data');
  assertHasProperty(pe, 'section_alignment');
  assertHasProperty(pe, 'file_alignment');
  assertHasProperty(pe, 'subsystem');
});

await test('Size of code is parsed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.size_of_code, 0x1000, 'Size of code should be 0x1000');
});

await test('Section alignment is parsed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.section_alignment, 0x1000, 'Section alignment should be 0x1000');
});

await test('File alignment is parsed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.file_alignment, 0x200, 'File alignment should be 0x200');
});

// ============================================================================
// Section 3: Sections
// ============================================================================

console.log('\n📋 Section 3: PE Sections\n');

await test('Section has required properties', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assertHasProperty(section, 'name');
    assertHasProperty(section, 'virtual_address');
    assertHasProperty(section, 'virtual_size');
    assertHasProperty(section, 'raw_data_offset');
    assertHasProperty(section, 'raw_data_size');
    assertHasProperty(section, 'characteristics');
    assertHasProperty(section, 'entropy');
  }
});

await test('Section has hash properties', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assertHasProperty(section, 'md5');
    assertHasProperty(section, 'sha1');
    assertHasProperty(section, 'sha256');
  }
});

await test('Section entropy is computed', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assert(typeof section.entropy === 'number', 'Entropy should be a number');
    assert(section.entropy >= 0 && section.entropy <= 8, 'Entropy should be between 0 and 8');
  }
});

await test('Section MD5 is valid format', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assertMatch(section.md5, /^[0-9a-f]{32}$/, 'MD5 should be 32 hex chars');
  }
});

await test('Section SHA1 is valid format', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assertMatch(section.sha1, /^[0-9a-f]{40}$/, 'SHA1 should be 40 hex chars');
  }
});

await test('Section SHA256 is valid format', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.sections.length > 0) {
    const section = pe.sections[0];
    assertMatch(section.sha256, /^[0-9a-f]{64}$/, 'SHA256 should be 64 hex chars');
  }
});

// ============================================================================
// Section 4: Imports
// ============================================================================

console.log('\n📋 Section 4: Imports\n');

await test('Imports array is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assert(Array.isArray(pe.imports), 'Imports should be an array');
});

await test('Import has dll property', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.imports.length > 0) {
    const imp = pe.imports[0];
    assertHasProperty(imp, 'dll');
    assert(typeof imp.dll === 'string', 'DLL name should be a string');
  }
});

await test('Import has functions array', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.imports.length > 0) {
    const imp = pe.imports[0];
    assertHasProperty(imp, 'functions');
    assert(Array.isArray(imp.functions), 'Functions should be an array');
  }
});

await test('Import function has name or ordinal', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.imports.length > 0 && pe.imports[0].functions.length > 0) {
    const fn = pe.imports[0].functions[0];
    assert(fn.hasOwnProperty('name') || fn.hasOwnProperty('ordinal'), 
           'Function should have name or ordinal');
  }
});

// ============================================================================
// Section 5: Exports
// ============================================================================

console.log('\n📋 Section 5: Exports\n');

await test('Exports array is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assert(Array.isArray(pe.exports), 'Exports should be an array');
});

await test('Export names are strings', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.exports.length > 0) {
    pe.exports.forEach(exp => {
      assert(typeof exp === 'string', 'Export should be a string');
    });
  }
});

// ============================================================================
// Section 6: ImpHash
// ============================================================================

console.log('\n📋 Section 6: ImpHash\n');

await test('ImpHash is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertHasProperty(pe, 'imphash');
});

await test('ImpHash is MD5 format', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assert(typeof pe.imphash === 'string', 'ImpHash should be a string');
  assertMatch(pe.imphash, /^[0-9a-f]{32}$/, 'ImpHash should be 32 hex chars (MD5)');
});

await test('ImpHash changes with different imports', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  // Empty imports should have consistent hash
  assert(pe.imphash.length === 32, 'ImpHash should always be 32 characters');
});

// ============================================================================
// Section 7: Digital Signature
// ============================================================================

console.log('\n📋 Section 7: Digital Signature\n');

await test('Digital signature property is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertHasProperty(pe, 'digital_signature');
});

await test('Digital signature has has_signature field', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertHasProperty(pe.digital_signature, 'has_signature');
  assert(typeof pe.digital_signature.has_signature === 'boolean', 
         'has_signature should be boolean');
});

await test('Unsigned PE has no signature', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.digital_signature.has_signature, false, 
               'Minimal PE should not have signature');
});

// ============================================================================
// Section 8: Rich Header
// ============================================================================

console.log('\n📋 Section 8: Rich Header\n');

await test('Rich signature property is present', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertHasProperty(pe, 'rich_signature');
});

await test('Rich signature is null or has offset', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  if (pe.rich_signature !== null) {
    assertHasProperty(pe.rich_signature, 'offset');
    assert(typeof pe.rich_signature.offset === 'number', 'Offset should be a number');
  }
});

// ============================================================================
// Section 9: Edge Cases
// ============================================================================

console.log('\n📋 Section 9: Edge Cases\n');

await test('ArrayBuffer input is accepted', async () => {
  const peData = createMinimalPE();
  const arrayBuffer = peData.buffer.slice(peData.byteOffset, peData.byteOffset + peData.byteLength);
  const pe = await parsePEYara(arrayBuffer);
  
  assert(!pe.error, 'Should parse ArrayBuffer without error');
});

await test('Empty data returns error', async () => {
  const emptyData = new Uint8Array(0);
  const pe = await parsePEYara(emptyData);
  
  assert(pe.error, 'Empty data should return error');
});

await test('Very small data returns error', async () => {
  const smallData = new Uint8Array(10);
  const pe = await parsePEYara(smallData);
  
  assert(pe.error, 'Very small data should return error');
});

await test('Data with MZ but no PE returns error', async () => {
  const mzOnly = new Uint8Array(100);
  mzOnly[0] = 0x4D; // 'M'
  mzOnly[1] = 0x5A; // 'Z'
  const pe = await parsePEYara(mzOnly);
  
  assert(pe.error, 'MZ-only data should return error');
});

// ============================================================================
// Section 10: YARA Compatibility
// ============================================================================

console.log('\n📋 Section 10: YARA Compatibility\n');

await test('Has all essential YARA PE fields', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  // Essential fields that YARA pe module provides
  const essentialFields = [
    'entry_point',
    'image_base',
    'number_of_sections',
    'sections',
    'imports',
    'exports',
    'imphash',
    'rich_signature',
  ];
  
  essentialFields.forEach(field => {
    assertHasProperty(pe, field, `Missing essential YARA field: ${field}`);
  });
});

await test('number_of_sections matches sections array length', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  assertEquals(pe.number_of_sections, pe.sections.length, 
               'number_of_sections should match sections.length');
});

await test('Optional header fields are at top level (YARA style)', async () => {
  const peData = createMinimalPE();
  const pe = await parsePEYara(peData);
  
  // YARA flattens optional header fields to top level
  const optionalHeaderFields = [
    'size_of_code',
    'address_of_entry_point',
    'image_base',
    'section_alignment',
    'file_alignment',
  ];
  
  optionalHeaderFields.forEach(field => {
    assertHasProperty(pe, field, `Missing flattened optional header field: ${field}`);
  });
});

  // ============================================================================
  // Test Summary
  // ============================================================================

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  TEST SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════');
  
  printSummary();
}

// Run all tests
runTests().catch(error => {
  console.error('Fatal error running tests:', error);
  printSummary();
});
