/**
 * Generate minimal valid PE (Portable Executable) test files
 * Creates both 32-bit and 64-bit PE executables for testing
 */

import { writeFileSync } from 'fs';

function createMinimalPE32() {
  const buf = new Uint8Array(1024);
  const view = new DataView(buf.buffer);
  
  // DOS Header
  buf[0] = 0x4D; buf[1] = 0x5A; // "MZ" magic
  view.setUint32(0x3C, 0x80, true); // e_lfanew (PE offset at 0x80)
  
  // DOS Stub (minimal)
  const dosStub = "This program cannot be run in DOS mode.\r\r\n$";
  for (let i = 0; i < dosStub.length; i++) {
    buf[0x40 + i] = dosStub.charCodeAt(i);
  }
  
  // PE Signature at offset 0x80
  buf[0x80] = 0x50; buf[0x81] = 0x45; // "PE"
  buf[0x82] = 0x00; buf[0x83] = 0x00;
  
  // COFF Header (20 bytes starting at 0x84)
  view.setUint16(0x84, 0x014c, true); // Machine = IMAGE_FILE_MACHINE_I386
  view.setUint16(0x86, 2, true); // NumberOfSections = 2
  view.setUint32(0x88, 0x60000000, true); // TimeDateStamp
  view.setUint32(0x8C, 0, true); // PointerToSymbolTable
  view.setUint32(0x90, 0, true); // NumberOfSymbols
  view.setUint16(0x94, 224, true); // SizeOfOptionalHeader = 224 (0xE0)
  view.setUint16(0x96, 0x010F, true); // Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED
  
  // Optional Header (PE32) starting at 0x98
  view.setUint16(0x98, 0x010b, true); // Magic = PE32
  buf[0x9A] = 14; buf[0x9B] = 0; // MajorLinkerVersion, MinorLinkerVersion
  view.setUint32(0x9C, 0x200, true); // SizeOfCode
  view.setUint32(0xA0, 0x200, true); // SizeOfInitializedData
  view.setUint32(0xA4, 0, true); // SizeOfUninitializedData
  view.setUint32(0xA8, 0x1000, true); // AddressOfEntryPoint
  view.setUint32(0xAC, 0x1000, true); // BaseOfCode
  view.setUint32(0xB0, 0x2000, true); // BaseOfData
  view.setUint32(0xB4, 0x400000, true); // ImageBase
  view.setUint32(0xB8, 0x1000, true); // SectionAlignment
  view.setUint32(0xBC, 0x200, true); // FileAlignment
  view.setUint16(0xC0, 6, true); // MajorOperatingSystemVersion
  view.setUint16(0xC2, 0, true); // MinorOperatingSystemVersion
  view.setUint16(0xC4, 0, true); // MajorImageVersion
  view.setUint16(0xC6, 0, true); // MinorImageVersion
  view.setUint16(0xC8, 6, true); // MajorSubsystemVersion
  view.setUint16(0xCA, 0, true); // MinorSubsystemVersion
  view.setUint32(0xCC, 0, true); // Win32VersionValue
  view.setUint32(0xD0, 0x4000, true); // SizeOfImage
  view.setUint32(0xD4, 0x200, true); // SizeOfHeaders
  view.setUint32(0xD8, 0, true); // CheckSum
  view.setUint16(0xDC, 3, true); // Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
  view.setUint16(0xDE, 0x8000, true); // DllCharacteristics
  view.setUint32(0xE0, 0x100000, true); // SizeOfStackReserve
  view.setUint32(0xE4, 0x1000, true); // SizeOfStackCommit
  view.setUint32(0xE8, 0x100000, true); // SizeOfHeapReserve
  view.setUint32(0xEC, 0x1000, true); // SizeOfHeapCommit
  view.setUint32(0xF0, 0, true); // LoaderFlags
  view.setUint32(0xF4, 16, true); // NumberOfRvaAndSizes
  
  // Data Directories (16 entries, 8 bytes each = 128 bytes)
  // All zeros for minimal PE
  for (let i = 0; i < 128; i++) {
    buf[0xF8 + i] = 0;
  }
  
  // Section Table (2 sections, 40 bytes each)
  // Section 1: .text
  const textName = ".text\0\0\0";
  for (let i = 0; i < 8; i++) {
    buf[0x178 + i] = textName.charCodeAt(i);
  }
  view.setUint32(0x180, 0x100, true); // VirtualSize
  view.setUint32(0x184, 0x1000, true); // VirtualAddress
  view.setUint32(0x188, 0x200, true); // SizeOfRawData
  view.setUint32(0x18C, 0x200, true); // PointerToRawData
  view.setUint32(0x190, 0, true); // PointerToRelocations
  view.setUint32(0x194, 0, true); // PointerToLinenumbers
  view.setUint16(0x198, 0, true); // NumberOfRelocations
  view.setUint16(0x19A, 0, true); // NumberOfLinenumbers
  view.setUint32(0x19C, 0x60000020, true); // Characteristics = CODE | EXECUTE | READ
  
  // Section 2: .data
  const dataName = ".data\0\0\0";
  for (let i = 0; i < 8; i++) {
    buf[0x1A0 + i] = dataName.charCodeAt(i);
  }
  view.setUint32(0x1A8, 0x100, true); // VirtualSize
  view.setUint32(0x1AC, 0x2000, true); // VirtualAddress
  view.setUint32(0x1B0, 0x200, true); // SizeOfRawData
  view.setUint32(0x1B4, 0x400, true); // PointerToRawData
  view.setUint32(0x1B8, 0, true); // PointerToRelocations
  view.setUint32(0x1BC, 0, true); // PointerToLinenumbers
  view.setUint16(0x1C0, 0, true); // NumberOfRelocations
  view.setUint16(0x1C2, 0, true); // NumberOfLinenumbers
  view.setUint32(0x1C4, 0xC0000040, true); // Characteristics = INITIALIZED_DATA | READ | WRITE
  
  // .text section data at 0x200
  buf[0x200] = 0xC3; // RET instruction
  
  // .data section data at 0x400
  buf[0x400] = 0x48; // Some data
  buf[0x401] = 0x65;
  buf[0x402] = 0x6C;
  buf[0x403] = 0x6C;
  buf[0x404] = 0x6F; // "Hello"
  
  return buf;
}

function createMinimalPE64() {
  const buf = new Uint8Array(1024);
  const view = new DataView(buf.buffer);
  
  // DOS Header
  buf[0] = 0x4D; buf[1] = 0x5A; // "MZ" magic
  view.setUint32(0x3C, 0x80, true); // e_lfanew
  
  // DOS Stub
  const dosStub = "This program cannot be run in DOS mode.\r\r\n$";
  for (let i = 0; i < dosStub.length; i++) {
    buf[0x40 + i] = dosStub.charCodeAt(i);
  }
  
  // PE Signature at offset 0x80
  buf[0x80] = 0x50; buf[0x81] = 0x45;
  buf[0x82] = 0x00; buf[0x83] = 0x00;
  
  // COFF Header
  view.setUint16(0x84, 0x8664, true); // Machine = IMAGE_FILE_MACHINE_AMD64
  view.setUint16(0x86, 3, true); // NumberOfSections = 3
  view.setUint32(0x88, 0x60000000, true); // TimeDateStamp
  view.setUint32(0x8C, 0, true); // PointerToSymbolTable
  view.setUint32(0x90, 0, true); // NumberOfSymbols
  view.setUint16(0x94, 240, true); // SizeOfOptionalHeader = 240 (0xF0) for PE32+
  view.setUint16(0x96, 0x0022, true); // Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
  
  // Optional Header (PE32+) starting at 0x98
  view.setUint16(0x98, 0x020b, true); // Magic = PE32+
  buf[0x9A] = 14; buf[0x9B] = 0;
  view.setUint32(0x9C, 0x200, true); // SizeOfCode
  view.setUint32(0xA0, 0x200, true); // SizeOfInitializedData
  view.setUint32(0xA4, 0, true); // SizeOfUninitializedData
  view.setUint32(0xA8, 0x1000, true); // AddressOfEntryPoint
  view.setUint32(0xAC, 0x1000, true); // BaseOfCode
  // Note: PE32+ doesn't have BaseOfData
  view.setBigUint64(0xB0, 0x140000000n, true); // ImageBase (64-bit)
  view.setUint32(0xB8, 0x1000, true); // SectionAlignment
  view.setUint32(0xBC, 0x200, true); // FileAlignment
  view.setUint16(0xC0, 6, true); // MajorOperatingSystemVersion
  view.setUint16(0xC2, 0, true);
  view.setUint16(0xC4, 0, true);
  view.setUint16(0xC6, 0, true);
  view.setUint16(0xC8, 6, true); // MajorSubsystemVersion
  view.setUint16(0xCA, 0, true);
  view.setUint32(0xCC, 0, true);
  view.setUint32(0xD0, 0x5000, true); // SizeOfImage
  view.setUint32(0xD4, 0x200, true); // SizeOfHeaders
  view.setUint32(0xD8, 0, true); // CheckSum
  view.setUint16(0xDC, 3, true); // Subsystem = WINDOWS_CUI
  view.setUint16(0xDE, 0x8160, true); // DllCharacteristics
  view.setBigUint64(0xE0, 0x100000n, true); // SizeOfStackReserve (64-bit)
  view.setBigUint64(0xE8, 0x1000n, true); // SizeOfStackCommit (64-bit)
  view.setBigUint64(0xF0, 0x100000n, true); // SizeOfHeapReserve (64-bit)
  view.setBigUint64(0xF8, 0x1000n, true); // SizeOfHeapCommit (64-bit)
  view.setUint32(0x100, 0, true); // LoaderFlags
  view.setUint32(0x104, 16, true); // NumberOfRvaAndSizes
  
  // Data Directories (16 entries)
  for (let i = 0; i < 128; i++) {
    buf[0x108 + i] = 0;
  }
  
  // Section Table (3 sections)
  // Section 1: .text
  const textName = ".text\0\0\0";
  for (let i = 0; i < 8; i++) {
    buf[0x188 + i] = textName.charCodeAt(i);
  }
  view.setUint32(0x190, 0x100, true); // VirtualSize
  view.setUint32(0x194, 0x1000, true); // VirtualAddress
  view.setUint32(0x198, 0x200, true); // SizeOfRawData
  view.setUint32(0x19C, 0x200, true); // PointerToRawData
  view.setUint32(0x1A0, 0, true);
  view.setUint32(0x1A4, 0, true);
  view.setUint16(0x1A8, 0, true);
  view.setUint16(0x1AA, 0, true);
  view.setUint32(0x1AC, 0x60000020, true); // Characteristics
  
  // Section 2: .data
  const dataName = ".data\0\0\0";
  for (let i = 0; i < 8; i++) {
    buf[0x1B0 + i] = dataName.charCodeAt(i);
  }
  view.setUint32(0x1B8, 0x100, true);
  view.setUint32(0x1BC, 0x2000, true);
  view.setUint32(0x1C0, 0x200, true);
  view.setUint32(0x1C4, 0x400, true);
  view.setUint32(0x1C8, 0, true);
  view.setUint32(0x1CC, 0, true);
  view.setUint16(0x1D0, 0, true);
  view.setUint16(0x1D2, 0, true);
  view.setUint32(0x1D4, 0xC0000040, true);
  
  // Section 3: .rdata
  const rdataName = ".rdata\0\0";
  for (let i = 0; i < 8; i++) {
    buf[0x1D8 + i] = rdataName.charCodeAt(i);
  }
  view.setUint32(0x1E0, 0x100, true);
  view.setUint32(0x1E4, 0x3000, true);
  view.setUint32(0x1E8, 0x200, true);
  view.setUint32(0x1EC, 0x600, true);
  view.setUint32(0x1F0, 0, true);
  view.setUint32(0x1F4, 0, true);
  view.setUint16(0x1F8, 0, true);
  view.setUint16(0x1FA, 0, true);
  view.setUint32(0x1FC, 0x40000040, true); // INITIALIZED_DATA | READ
  
  // .text section data
  buf[0x200] = 0xC3; // RET
  
  // .data section data
  buf[0x400] = 0x54; buf[0x401] = 0x65; buf[0x402] = 0x73; buf[0x403] = 0x74; // "Test"
  
  // .rdata section data
  buf[0x600] = 0x52; buf[0x601] = 0x65; buf[0x602] = 0x61; buf[0x603] = 0x64; // "Read"
  
  return buf;
}

console.log('Generating PE test files...');

const pe32 = createMinimalPE32();
writeFileSync('test_files/test_pe32.exe', pe32);
console.log('✓ Created test_files/test_pe32.exe (32-bit PE)');

const pe64 = createMinimalPE64();
writeFileSync('test_files/test_pe64.exe', pe64);
console.log('✓ Created test_files/test_pe64.exe (64-bit PE)');

console.log('\nPE test files generated successfully!');
