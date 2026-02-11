import { YaraScanner } from '../yaraScanner.mjs';

const scanner = new YaraScanner();
const rule = `
  rule Test {
    condition:
      uint8(0) == 0x4D and
      uint16(0) == 0x5A4D and
      uint32(0) == 0x00005A4D
  }
`;
scanner.addRules(rule);
const data = new Uint8Array([0x4D, 0x5A, 0x00, 0x00]);

// Manual calculation
const view = new DataView(data.buffer);
console.log('uint8(0):', '0x' + view.getUint8(0).toString(16), '(expected: 0x4D)');
console.log('uint16(0):', '0x' + view.getUint16(0, true).toString(16), '(expected: 0x5A4D)');
console.log('uint32(0):', '0x' + view.getUint32(0, true).toString(16), '(expected: 0x00005A4D)');

const result = await scanner.scan(data);
console.log('Match result:', result.length === 1 ? 'SUCCESS' : 'FAILED');
