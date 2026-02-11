/**
 * Test ELF Module Integration with Scanner
 * 
 * Demonstrates automatic ELF file detection and module usage in YARA rules.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';

console.log('='.repeat(70));
console.log('ELF MODULE INTEGRATION TEST');
console.log('='.repeat(70));

// Create a minimal ELF file header for testing
// ELF magic: 0x7F 'E' 'L' 'F'
function createMinimalELF() {
  const buffer = new Uint8Array(1024);
  
  // ELF magic
  buffer[0] = 0x7F;
  buffer[1] = 0x45; // 'E'
  buffer[2] = 0x4C; // 'L'
  buffer[3] = 0x46; // 'F'
  
  // ELF class (1 = 32-bit, 2 = 64-bit)
  buffer[4] = 0x02; // 64-bit
  
  // Data encoding (1 = little-endian, 2 = big-endian)
  buffer[5] = 0x01; // Little-endian
  
  // ELF version
  buffer[6] = 0x01;
  
  // OS/ABI
  buffer[7] = 0x00; // SYSV
  
  // Padding bytes (8-15)
  for (let i = 8; i < 16; i++) {
    buffer[i] = 0;
  }
  
  // e_type (16-17): 2 = ET_EXEC, 3 = ET_DYN
  buffer[16] = 0x02;
  buffer[17] = 0x00;
  
  // e_machine (18-19): 0x3E = x86-64
  buffer[18] = 0x3E;
  buffer[19] = 0x00;
  
  // e_version (20-23)
  buffer[20] = 0x01;
  buffer[21] = 0x00;
  buffer[22] = 0x00;
  buffer[23] = 0x00;
  
  // e_entry (24-31): Entry point address - 0x400000
  buffer[24] = 0x00;
  buffer[25] = 0x00;
  buffer[26] = 0x40;
  buffer[27] = 0x00;
  buffer[28] = 0x00;
  buffer[29] = 0x00;
  buffer[30] = 0x00;
  buffer[31] = 0x00;
  
  // e_phoff (32-39): Program header offset - 64
  buffer[32] = 0x40;
  buffer[33] = 0x00;
  for (let i = 34; i < 40; i++) buffer[i] = 0x00;
  
  // e_shoff (40-47): Section header offset - 200
  buffer[40] = 0xC8;
  buffer[41] = 0x00;
  for (let i = 42; i < 48; i++) buffer[i] = 0x00;
  
  // e_flags (48-51)
  for (let i = 48; i < 52; i++) buffer[i] = 0x00;
  
  // e_ehsize (52-53): ELF header size - 64
  buffer[52] = 0x40;
  buffer[53] = 0x00;
  
  // e_phentsize (54-55): Program header entry size - 56
  buffer[54] = 0x38;
  buffer[55] = 0x00;
  
  // e_phnum (56-57): Number of program headers - 1
  buffer[56] = 0x01;
  buffer[57] = 0x00;
  
  // e_shentsize (58-59): Section header entry size - 64
  buffer[58] = 0x40;
  buffer[59] = 0x00;
  
  // e_shnum (60-61): Number of section headers - 3
  buffer[60] = 0x03;
  buffer[61] = 0x00;
  
  // e_shstrndx (62-63): Section header string table index - 2
  buffer[62] = 0x02;
  buffer[63] = 0x00;
  
  // Fill rest with zeros
  for (let i = 64; i < 1024; i++) {
    buffer[i] = 0;
  }
  
  return buffer;
}

// Example 1: Automatic ELF detection
console.log('\n📋 Example 1: Automatic ELF File Detection\n');

(async () => {
  const elfData = createMinimalELF();
  
  const rule = `
    rule ELF_File_Detection {
      condition:
        uint32(0) == 0x464c457f  // ELF magic in little-endian
    }
  `;
  
  const scanner = new InterceptScanner();
  scanner.addRules(rule);
  
  const results = await scanner.scan(elfData);
  
  if (results.length > 0) {
    console.log('✅ ELF file detected successfully!');
    console.log('   Matched rule:', results[0].rule);
  } else {
    console.log('❌ ELF detection failed');
  }

  // Example 2: Using ELF module properties
  console.log('\n📋 Example 2: ELF Module Properties\n');
  
  const elfModuleRule = `
    import "elf"
    
    rule ELF_Entry_Point_Check {
      condition:
        elf.entry_point > 0
    }
  `;
  
  scanner.clear();
  scanner.addRules(elfModuleRule);
  
  const elfResults = await scanner.scan(elfData);
  
  if (elfResults.length > 0) {
    console.log('✅ ELF entry point check successful!');
    console.log('   Rule:', elfResults[0].rule);
  } else {
    console.log('❌ ELF module check failed');
  }

  // Example 3: Manual ELF module usage
  console.log('\n📋 Example 3: Manual ELF Module Properties\n');
  
  const { parseELFYaraFull, createELFModule } = await import('../src/elfModule.mjs');
  
  try {
    const parsedELF = await parseELFYaraFull(elfData);
    
    if (parsedELF.error) {
      console.log('❌ ELF parsing error:', parsedELF.error);
    } else {
      const elfModule = createELFModule(parsedELF);
      
      console.log('ELF Properties:');
      console.log('  Entry point:', '0x' + elfModule.entry_point.toString(16));
      console.log('  Is 64-bit:', elfModule.is_64bit);
      console.log('  Is 32-bit:', elfModule.is_32bit());
      console.log('  Endianness:', elfModule.endianness);
      console.log('  File size:', elfModule.file_size, 'bytes');
      console.log('  Number of sections:', elfModule.number_of_sections);
      console.log('  Number of segments:', elfModule.number_of_segments);
      
      console.log('\nELF Helper Methods:');
      console.log('  is_little_endian():', elfModule.is_little_endian());
      console.log('  is_big_endian():', elfModule.is_big_endian());
      
      console.log('\n✅ Manual ELF module access successful!');
    }
  } catch (error) {
    console.log('❌ ELF parsing exception:', error.message);
  }

  // Example 4: Non-ELF file (should not trigger ELF module)
  console.log('\n📋 Example 4: Non-ELF File Handling\n');
  
  const nonELFData = new TextEncoder().encode('This is not an ELF file');
  
  const anyFileRule = `
    rule Any_File {
      strings:
        $text = "not an ELF"
      condition:
        $text
    }
  `;
  
  scanner.clear();
  scanner.addRules(anyFileRule);
  
  const nonELFResults = await scanner.scan(nonELFData);
  
  if (nonELFResults.length > 0) {
    console.log('✅ Non-ELF file processed correctly!');
    console.log('   Scanner works with regular files too');
  } else {
    console.log('❌ Non-ELF file test failed');
  }

  // Example 5: ELF with string patterns
  console.log('\n📋 Example 5: ELF File with String Patterns\n');
  
  const elfWithStrings = createMinimalELF();
  const textData = new TextEncoder().encode('/lib64/ld-linux.so');
  elfWithStrings.set(textData, 100); // Add string at offset 100
  
  const elfStringRule = `
    import "elf"
    
    rule ELF_With_Dynamic_Linker {
      strings:
        $linker = "/lib64/ld-linux"
      condition:
        elf.entry_point > 0 and $linker
    }
  `;
  
  scanner.clear();
  scanner.addRules(elfStringRule);
  
  const elfStringResults = await scanner.scan(elfWithStrings);
  
  if (elfStringResults.length > 0) {
    console.log('✅ ELF with string pattern matched!');
    console.log('   Combined ELF module + string matching works');
  } else {
    console.log('❌ ELF string pattern test failed');
  }

  console.log('\n' + '='.repeat(70));
  console.log('ELF MODULE INTEGRATION COMPLETE');
  console.log('='.repeat(70));
  console.log('\n✨ ELF module is now integrated with the scanner!');
  console.log('   - Automatic ELF detection (checks magic bytes)');
  console.log('   - ELF module properties available in conditions');
  console.log('   - Helper methods for common checks');
  console.log('   - Works alongside PE module');
})();
