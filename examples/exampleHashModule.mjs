/**
 * YARA Hash Module - Usage Examples
 * 
 * This file demonstrates how to use the yaraHashModule with YARA rules.
 */

import { createHashModule, hash } from '../src/hashModule.mjs';

console.log('='.repeat(70));
console.log('YARA Hash Module - Usage Examples');
console.log('='.repeat(70));

// =============================================================================
// Example 1: Standalone hash functions (string input)
// =============================================================================
console.log('\n📌 Example 1: Standalone Hash Functions\n');

const testString = 'malware.exe';

console.log(`Testing string: "${testString}"\n`);

// MD5
const md5Hash = await hash.md5(testString);
console.log(`MD5:        ${md5Hash}`);

// SHA1
const sha1Hash = await hash.sha1(testString);
console.log(`SHA1:       ${sha1Hash}`);

// SHA256
const sha256Hash = await hash.sha256(testString);
console.log(`SHA256:     ${sha256Hash}`);

// checksum32
const checksum = hash.checksum32(testString);
console.log(`Checksum32: ${checksum}`);

// CRC32
const crc = hash.crc32(testString);
console.log(`CRC32:      ${crc}`);

// =============================================================================
// Example 2: Hash module with file data
// =============================================================================
console.log('\n📌 Example 2: Hash Module with File Data\n');

// Simulate file data
const fileData = new Uint8Array([
  0x4D, 0x5A, 0x90, 0x00, // DOS header "MZ"
  0x03, 0x00, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0x00, 0x00
]);

console.log('File size:', fileData.length, 'bytes');
console.log('File data:', Array.from(fileData.slice(0, 8)).map(b => '0x' + b.toString(16).toUpperCase().padStart(2, '0')).join(' '), '...\n');

const hashModule = createHashModule(fileData);

// Hash the entire file
const fileMD5 = await hashModule.md5(0, fileData.length);
console.log(`Full file MD5:     ${fileMD5}`);

// Hash first 4 bytes (DOS header)
const headerMD5 = await hashModule.md5(0, 4);
console.log(`First 4 bytes MD5: ${headerMD5}`);

// Hash bytes 4-8
const sectionMD5 = await hashModule.md5(4, 4);
console.log(`Bytes 4-8 MD5:     ${sectionMD5}`);

// =============================================================================
// Example 3: YARA Rule Example
// =============================================================================
console.log('\n📌 Example 3: YARA Rule Usage\n');

console.log('Example YARA rule using hash module:\n');
console.log(`rule DetectMalware {
    strings:
        $magic = { 4D 5A }
    
    condition:
        $magic at 0 and
        hash.md5(0, filesize) == "${fileMD5}" or
        hash.sha256(0, 100) == "abc123..." or
        hash.crc32("test") == "86d3f3a4"
}`);

// =============================================================================
// Example 4: Common Use Cases
// =============================================================================
console.log('\n📌 Example 4: Common Use Cases\n');

// Use case 1: Check if file starts with known hash
const knownMalwareHash = 'e10adc3949ba59abbe56e057f20f883e'; // MD5 of "123456"
const testData = new TextEncoder().encode('123456');
const testHashModule = createHashModule(testData);
const computedHash = await testHashModule.md5(0, testData.length);

console.log('Use Case 1: Known malware signature');
console.log(`  Known hash:    ${knownMalwareHash}`);
console.log(`  Computed hash: ${computedHash}`);
console.log(`  Match: ${computedHash === knownMalwareHash ? '✓ YES' : '✗ NO'}`);

// Use case 2: Hash specific sections
console.log('\nUse Case 2: Section hashing');
const exeData = new Uint8Array(1000);
for (let i = 0; i < exeData.length; i++) {
  exeData[i] = i % 256;
}
const exeHashModule = createHashModule(exeData);

console.log(`  .text section (0-100):    ${await exeHashModule.sha1(0, 100)}`);
console.log(`  .data section (100-200):  ${await exeHashModule.sha1(100, 100)}`);
console.log(`  .rsrc section (200-300):  ${await exeHashModule.sha1(200, 100)}`);

// Use case 3: Quick checksum comparison
console.log('\nUse Case 3: Quick checksum (faster than cryptographic hash)');
const file1 = new Uint8Array([1, 2, 3, 4, 5]);
const file2 = new Uint8Array([1, 2, 3, 4, 6]);
const hash1 = createHashModule(file1);
const hash2 = createHashModule(file2);

const crc1 = hash1.crc32(0, file1.length);
const crc2 = hash2.crc32(0, file2.length);

console.log(`  File1 CRC32: ${crc1}`);
console.log(`  File2 CRC32: ${crc2}`);
console.log(`  Files identical: ${crc1 === crc2 ? 'YES' : 'NO'}`);

// =============================================================================
// Example 5: Integration with YARA Conditions
// =============================================================================
console.log('\n📌 Example 5: Hash Conditions in YARA Rules\n');

console.log('Common hash condition patterns:\n');
console.log('1. Match known malware hash:');
console.log('   hash.md5(0, filesize) == "abc123..."');
console.log('');
console.log('2. Match PE header hash:');
console.log('   hash.sha256(0, 0x400) == "def456..."');
console.log('');
console.log('3. String hash matching:');
console.log('   hash.md5("malware") == "e10adc3949ba59abbe56e057f20f883e"');
console.log('');
console.log('4. Section hashing:');
console.log('   hash.sha1(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) == "..."');
console.log('');
console.log('5. Quick integrity check:');
console.log('   hash.crc32(0, 1024) == "12345678"');

console.log('\n' + '='.repeat(70));
console.log('✅ All examples completed successfully!');
console.log('='.repeat(70));
