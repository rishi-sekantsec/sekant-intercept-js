import { YaraScanner } from '../yaraScanner.mjs';

function createELFFile(entryPoint = 0x400000, addStringAtEntry = false) {
  const headerSize = 64;
  const size = addStringAtEntry ? Math.max(4096, entryPoint - 0x400000 + 100) : headerSize;
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
  
  // e_entry (8 bytes at offset 24) - entry point address
  const view = new DataView(data.buffer);
  view.setBigUint64(24, BigInt(entryPoint), true); // little-endian
  
  // Add test string at entry point if requested
  if (addStringAtEntry) {
    const fileOffset = entryPoint - 0x400000; // Typical load address
    if (fileOffset >= 0 && fileOffset < size - 10) {
      const testStr = 'TESTCODE';
      for (let i = 0; i < testStr.length; i++) {
        data[fileOffset + i] = testStr.charCodeAt(i);
      }
    }
  }
  
  return data;
}

const scanner = new YaraScanner();
const rule = `
  rule PackedELF {
    strings:
      $code = "TESTCODE"
    condition:
      uint32(0) == 0x464C457F and
      $code in (entrypoint..entrypoint+200) and
      elf.is_64bit() and
      entrypoint >= 0x400000
  }
`;

console.log('Testing ELF packed binary detection...');

try {
  scanner.addRules(rule);
  const data = createELFFile(0x400000, true);
  
  console.log('ELF file created, size:', data.length);
  console.log('ELF magic:', data[0].toString(16), data[1].toString(16), data[2].toString(16), data[3].toString(16));
  console.log('Entry point in file: 0x400000 - 0x400000 = 0');
  console.log('String "TESTCODE" at offset 0');
  
  const result = await scanner.scan(data);
  
  console.log('\nScan result:', result);
  console.log('Number of matches:', result.length);
  
  if (result.length > 0) {
    console.log('Match details:', JSON.stringify(result[0], null, 2));
  }
} catch (err) {
  console.error('Error:', err.message);
  console.error(err.stack);
}
