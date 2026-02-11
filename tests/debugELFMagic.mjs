import { YaraScanner } from '../yaraScanner.mjs';

// Same createELFFile from testEntrypoint.mjs
function createELFFile(entryPoint = 0x401000, addStringAtEntry = false) {
  const size = addStringAtEntry ? 4096 : 64;
  const buffer = Buffer.alloc(size);
  
  // ELF magic: 0x7F 'E' 'L' 'F'
  buffer.writeUInt32LE(0x464C457F, 0);
  
  // EI_CLASS (offset 4): 2 = 64-bit
  buffer[4] = 2;
  
  // EI_DATA (offset 5): 1 = little endian
  buffer[5] = 1;
  
  // EI_VERSION (offset 6): 1 = current version
  buffer[6] = 1;
  
  // e_type (offset 16): 2 = ET_EXEC
  buffer.writeUInt16LE(2, 16);
  
  // e_machine (offset 18): 0x3E = x86-64
  buffer.writeUInt16LE(0x3E, 18);
  
  // e_version (offset 20): 1
  buffer.writeUInt32LE(1, 20);
  
  // e_entry (offset 24): entry point address (8 bytes for 64-bit)
  buffer.writeBigUInt64LE(BigInt(entryPoint), 24);
  
  // If requested, add string at calculated file offset
  if (addStringAtEntry) {
    const fileOffset = entryPoint >= 0x400000 ? entryPoint - 0x400000 : entryPoint;
    const str = 'TESTCODE';
    if (fileOffset + str.length <= size) {
      buffer.write(str, fileOffset, 'ascii');
    }
  }
  
  return buffer;
}

async function testELFMagic() {
  console.log('\n=== Testing ELF Magic Matching ===\n');
  
  const data = createELFFile(0x401000, false);
  
  // Check first 16 bytes
  console.log('First 16 bytes of ELF file:');
  for (let i = 0; i < 16; i++) {
    console.log(`  Offset ${i}: 0x${data[i].toString(16).padStart(2, '0').toUpperCase()}`);
  }
  
  // Test 1: Check uint32(0)
  const magic = data.readUInt32LE(0);
  console.log(`\nuint32(0) = 0x${magic.toString(16).toUpperCase()}`);
  console.log(`Expected: 0x464C457F (matches: ${magic === 0x464C457F})`);
  
  // Test 2: Check hex pattern
  console.log('\nChecking hex pattern { 7F 45 4C 46 }:');
  const matches = (
    data[0] === 0x7F &&
    data[1] === 0x45 &&
    data[2] === 0x4C &&
    data[3] === 0x46
  );
  console.log(`  Bytes match: ${matches}`);
  
  // Test 3: Try scanning with YARA
  console.log('\n=== YARA Scanner Tests ===\n');
  
  // Test simple hex pattern
  const scanner1 = new YaraScanner();
  const rule1 = `
    rule TestHex {
      strings:
        $elf = { 7F 45 4C 46 }
      condition:
        $elf
    }
  `;
  scanner1.addRules(rule1);
  const result1 = await scanner1.scan(data);
  console.log('Test 1 - Simple hex pattern:');
  console.log(`  Matches: ${result1.length}`);
  if (result1.length > 0) {
    console.log(`  Rule: ${result1[0].rule}`);
    console.log(`  Strings found: ${result1[0].strings?.length || 0}`);
  }
  
  // Test hex pattern at position
  const scanner2 = new YaraScanner();
  const rule2 = `
    rule TestHexAt {
      strings:
        $elf = { 7F 45 4C 46 }
      condition:
        $elf at 0
    }
  `;
  scanner2.addRules(rule2);
  const result2 = await scanner2.scan(data);
  console.log('\nTest 2 - Hex pattern at 0:');
  console.log(`  Matches: ${result2.length}`);
  if (result2.length > 0) {
    console.log(`  Rule: ${result2[0].rule}`);
    console.log(`  Strings found: ${result2[0].strings?.length || 0}`);
  }
  
  // Test with entrypoint
  const scanner3 = new YaraScanner();
  const rule3 = `
    rule TestWithEntrypoint {
      strings:
        $elf = { 7F 45 4C 46 }
      condition:
        $elf at 0 and entrypoint > 0
    }
  `;
  scanner3.addRules(rule3);
  const result3 = await scanner3.scan(data);
  console.log('\nTest 3 - Hex pattern at 0 with entrypoint check:');
  console.log(`  Matches: ${result3.length}`);
  if (result3.length > 0) {
    console.log(`  Rule: ${result3[0].rule}`);
  }
  
  // Test just entrypoint
  const scanner4 = new YaraScanner();
  const rule4 = `
    rule TestEntrypointOnly {
      condition:
        entrypoint > 0
    }
  `;
  scanner4.addRules(rule4);
  const result4 = await scanner4.scan(data);
  console.log('\nTest 4 - Just entrypoint > 0:');
  console.log(`  Matches: ${result4.length}`);
  if (result4.length > 0) {
    console.log(`  Rule: ${result4[0].rule}`);
  }
}

testELFMagic().catch(console.error);
