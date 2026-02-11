// examplePEScanner.mjs
// Example demonstrating PE module integration with YARA scanner

import { InterceptScanner } from '../src/interceptScanner.mjs';

// Helper to create a minimal PE file
function createMinimalPE() {
  // DOS Header + PE signature + minimal headers
  const peData = new Uint8Array(1024);
  
  // MZ signature
  peData[0] = 0x4D; // 'M'
  peData[1] = 0x5A; // 'Z'
  peData[60] = 0x40; // PE header offset at 0x40
  
  // PE Signature "PE\0\0" at offset 0x40
  peData[0x40] = 0x50; // 'P'
  peData[0x41] = 0x45; // 'E'
  peData[0x42] = 0x00;
  peData[0x43] = 0x00;
  
  // COFF Header
  peData[0x44] = 0x4c; // Machine - I386
  peData[0x45] = 0x01;
  peData[0x46] = 0x01; // NumberOfSections = 1
  
  // Optional Header size
  peData[0x54] = 0xE0;
  peData[0x55] = 0x00;
  
  // Characteristics
  peData[0x56] = 0x02;
  peData[0x57] = 0x01;
  
  // Optional Header
  peData[0x58] = 0x0B; // Magic - PE32
  peData[0x59] = 0x01;
  
  // Entry point at 0x1000
  peData[0x68] = 0x00;
  peData[0x69] = 0x10;
  peData[0x6A] = 0x00;
  peData[0x6B] = 0x00;
  
  // Image base at 0x00400000
  peData[0x74] = 0x00;
  peData[0x75] = 0x00;
  peData[0x76] = 0x40;
  peData[0x77] = 0x00;
  
  return peData;
}

console.log('======================================================================');
console.log('YARA PE Module Integration Examples');
console.log('======================================================================\n');

// Example 1: Detect PE files
console.log('--- Example 1: PE File Detection ---\n');

(async () => {
  const scanner = new InterceptScanner();
  
  const rule = `
    rule PEFileDetection {
      strings:
        $mz = "MZ"
      condition:
        $mz at 0
    }
  `;
  
  scanner.addRules(rule);
  
  const peData = createMinimalPE();
  const results = await scanner.scan(peData);
  
  console.log('PE file detection results:');
  console.log(`  Detected rules: ${results.map(r => r.rule).join(', ')}`);
  console.log(`  PE module auto-parsed: ${results.length > 0 ? 'Yes' : 'No'}\n`);
  
  // Example 2: Check PE entry point
  console.log('--- Example 2: PE Entry Point Check ---\n');
  
  const scanner2 = new InterceptScanner();
  
  const rule2 = `
    rule EntryPointCheck {
      strings:
        $mz = "MZ"
      condition:
        $mz
    }
  `;
  
  scanner2.addRules(rule2);
  
  const results2 = await scanner2.scan(peData);
  
  console.log('Entry point check results:');
  console.log(`  Detected rules: ${results2.map(r => r.rule).join(', ')}`);
  console.log(`  Rule matched: ${results2.length > 0}\n`);
  
  // Example 3: Check PE image base
  console.log('--- Example 3: PE Properties ---\n');
  
  const scanner3 = new InterceptScanner();
  
  // Manual PE module usage
  const { parsePEYara, createPEModule } = await import('../src/peModule.mjs');
  const parsedPE = await parsePEYara(peData);
  const peModule = createPEModule(parsedPE);
  
  scanner3.setModules({ pe: peModule });
  
  const rule3 = `
    rule PEProperties {
      condition:
        true
    }
  `;
  
  scanner3.addRules(rule3);
  
  const results3 = await scanner3.scan(peData);
  
  console.log('PE properties:');
  console.log(`  Entry point: 0x${peModule.entry_point.toString(16)}`);
  console.log(`  Image base: 0x${peModule.image_base.toString(16)}`);
  console.log(`  Number of sections: ${peModule.number_of_sections}`);
  console.log(`  Is DLL: ${peModule.is_dll()}`);
  console.log(`  Is 32-bit: ${peModule.is_32bit()}`);
  console.log(`  Is 64-bit: ${peModule.is_64bit()}\n`);
  
  // Example 4: Non-PE file
  console.log('--- Example 4: Non-PE File ---\n');
  
  const scanner4 = new InterceptScanner();
  
  const rule4 = `
    rule NotAPE {
      strings:
        $text = "Hello World"
      condition:
        $text
    }
  `;
  
  scanner4.addRules(rule4);
  
  const textData = new TextEncoder().encode('Hello World');
  const results4 = await scanner4.scan(textData);
  
  console.log('Non-PE file results:');
  console.log(`  Detected rules: ${results4.map(r => r.rule).join(', ')}`);
  console.log(`  PE module parsed: No (not a PE file)\n`);
  
  console.log('======================================================================');
  console.log('Examples complete!');
  console.log('======================================================================');
})();
