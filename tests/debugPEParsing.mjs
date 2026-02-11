import { parsePEYara, createPEModule } from '../yaraPEModule.mjs';

/**
 * Create a minimal PE file (DOS header + PE header)
 */
function createPEFile(entryPoint = 0x1000) {
  const data = new Uint8Array(512);
  
  // DOS Header
  data[0] = 0x4D; // 'M'
  data[1] = 0x5A; // 'Z'
  
  // e_lfanew at offset 0x3C (points to PE header)
  const peHeaderOffset = 0x100;
  data[0x3C] = peHeaderOffset & 0xFF;
  data[0x3D] = (peHeaderOffset >> 8) & 0xFF;
  
  // PE Signature at offset 0x100
  data[peHeaderOffset] = 0x50; // 'P'
  data[peHeaderOffset + 1] = 0x45; // 'E'
  data[peHeaderOffset + 2] = 0x00;
  data[peHeaderOffset + 3] = 0x00;
  
  // COFF Header (20 bytes starting at peHeaderOffset + 4)
  const coffHeader = peHeaderOffset + 4;
  
  // Machine (2 bytes) - 0x014C = IMAGE_FILE_MACHINE_I386
  data[coffHeader] = 0x4C;
  data[coffHeader + 1] = 0x01;
  
  // NumberOfSections (2 bytes)
  data[coffHeader + 2] = 0x01;
  
  // SizeOfOptionalHeader (2 bytes at offset +16)
  data[coffHeader + 16] = 0xE0; // 224 bytes for PE32
  data[coffHeader + 17] = 0x00;
  
  // Optional Header starts at coffHeader + 20
  const optionalHeader = coffHeader + 20;
  
  // Magic number (2 bytes) - 0x010B = PE32
  data[optionalHeader] = 0x0B;
  data[optionalHeader + 1] = 0x01;
  
  // AddressOfEntryPoint (4 bytes at offset +16 in optional header)
  const entryPointOffset = optionalHeader + 16;
  data[entryPointOffset] = entryPoint & 0xFF;
  data[entryPointOffset + 1] = (entryPoint >> 8) & 0xFF;
  data[entryPointOffset + 2] = (entryPoint >> 16) & 0xFF;
  data[entryPointOffset + 3] = (entryPoint >> 24) & 0xFF;
  
  return data;
}

const data = createPEFile(0x1000);

console.log('Testing PE parsing...');
console.log('Data size:', data.length);
console.log('MZ signature:', data[0].toString(16), data[1].toString(16));

try {
  const parsedPE = await parsePEYara(data);
  console.log('\nParsed PE data:', parsedPE);
  
  if (parsedPE.error) {
    console.error('PE parsing error:', parsedPE.error);
  } else {
    const peModule = createPEModule(parsedPE);
    console.log('\nPE Module created successfully!');
    console.log('Entry point:', peModule.entry_point ? '0x' + peModule.entry_point.toString(16) : 'undefined');
    console.log('Image base:', peModule.image_base ? '0x' + peModule.image_base.toString(16) : 'undefined');
    console.log('Is 32-bit:', peModule.is_32bit());
    console.log('Is 64-bit:', peModule.is_64bit());
  }
} catch (err) {
  console.error('Error parsing PE:', err.message);
  console.error(err.stack);
}
