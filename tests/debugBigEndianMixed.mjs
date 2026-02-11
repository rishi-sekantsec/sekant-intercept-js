import { YaraScanner } from '../yaraScanner.mjs';

const scanner = new YaraScanner();
const rule = `
  rule Test {
    condition:
      uint8(0) == 0x12 and
      int8(1) == 0x34 and
      uint16(2) == 0x7856 and
      uint16be(2) == 0x5678 and
      int16(4) == 0x10EF and
      int16be(4) == -0x0F12
  }
`;

try {
  scanner.addRules(rule);
  const data = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0xEF, 0x10]);
  
  const view = new DataView(data.buffer);
  console.log('Data:', Array.from(data).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
  console.log('\nChecking each condition:');
  console.log('uint8(0) =', '0x' + view.getUint8(0).toString(16), '(expected: 0x12)');
  console.log('int8(1) =', '0x' + view.getInt8(1).toString(16), '(expected: 0x34)');
  console.log('uint16(2) =', '0x' + view.getUint16(2, true).toString(16), '(expected: 0x7856)');
  console.log('uint16be(2) =', '0x' + view.getUint16(2, false).toString(16), '(expected: 0x5678)');
  console.log('int16(4) =', '0x' + view.getInt16(4, true).toString(16), '(expected: 0x10EF)');
  console.log('int16be(4) =', view.getInt16(4, false), '(expected: -0x0F12 =', -0x0F12, ')');
  
  const result = await scanner.scan(data);
  console.log('\nMatch result:', result.length === 1 ? 'SUCCESS' : 'FAILED');
} catch (err) {
  console.error('Error:', err.message);
  console.error(err);
}
