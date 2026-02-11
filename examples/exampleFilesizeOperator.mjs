/**
 * Example: Using the Filesize Operator
 * 
 * Demonstrates filesize operator with various comparisons and size units.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';

console.log('=== Filesize Operator Examples ===\n');

// Example 1: Check if file is small (< 1KB)
console.log('Example 1: Small file detection');
const scanner1 = new InterceptScanner();
scanner1.addRules(`
  rule SmallFile {
    condition:
      filesize < 1KB
  }
`);

const smallData = new Uint8Array(512); // 512 bytes
const results1 = await scanner1.scan(smallData);
console.log(`File size: ${smallData.length} bytes`);
console.log(`Matched: ${results1.length > 0 ? 'YES' : 'NO'} (${results1.map(r => r.rule).join(', ') || 'none'})`);
console.log();

// Example 2: Check if file is medium-sized
console.log('Example 2: Medium file detection');
const scanner2 = new InterceptScanner();
scanner2.addRules(`
  rule MediumFile {
    condition:
      filesize > 10KB and filesize < 1MB
  }
`);

const mediumData = new Uint8Array(50 * 1024); // 50KB
const results2 = await scanner2.scan(mediumData);
console.log(`File size: ${mediumData.length} bytes (${Math.floor(mediumData.length / 1024)}KB)`);
console.log(`Matched: ${results2.length > 0 ? 'YES' : 'NO'} (${results2.map(r => r.rule).join(', ') || 'none'})`);
console.log();

// Example 3: Detect large files
console.log('Example 3: Large file detection');
const scanner3 = new InterceptScanner();
scanner3.addRules(`
  rule LargeFile {
    condition:
      filesize > 1MB
  }
`);

const largeData = new Uint8Array(2 * 1024 * 1024); // 2MB
const results3 = await scanner3.scan(largeData);
console.log(`File size: ${largeData.length} bytes (${Math.floor(largeData.length / (1024 * 1024))}MB)`);
console.log(`Matched: ${results3.length > 0 ? 'YES' : 'NO'} (${results3.map(r => r.rule).join(', ') || 'none'})`);
console.log();

// Example 4: Combine filesize with string matching
console.log('Example 4: Filesize + string matching');
const scanner4 = new InterceptScanner();
scanner4.addRules(`
  rule SmallMalware {
    strings:
      $payload = "malicious"
    condition:
      filesize < 10KB and $payload
  }
`);

const testData = new TextEncoder().encode('this file contains malicious code');
const results4 = await scanner4.scan(testData);
console.log(`File size: ${testData.length} bytes`);
console.log(`Contains "malicious": YES`);
console.log(`Matched: ${results4.length > 0 ? 'YES' : 'NO'} (${results4.map(r => r.rule).join(', ') || 'none'})`);
console.log();

// Example 5: Exact filesize match
console.log('Example 5: Exact filesize match');
const scanner5 = new InterceptScanner();
scanner5.addRules(`
  rule ExactSize {
    condition:
      filesize == 1024
  }
`);

const exactData = new Uint8Array(1024); // Exactly 1KB
const results5 = await scanner5.scan(exactData);
console.log(`File size: ${exactData.length} bytes (exactly 1KB)`);
console.log(`Matched: ${results5.length > 0 ? 'YES' : 'NO'} (${results5.map(r => r.rule).join(', ') || 'none'})`);
console.log();

// Example 6: Using filesize cap (default 1MB)
console.log('Example 6: Capped filesize (simulates streaming scenario)');
const scanner6 = new InterceptScanner();
scanner6.setMaxFileSize(1024); // Cap at 1KB for this example
scanner6.addRules(`
  rule PotentiallyLargeFile {
    condition:
      filesize > 1KB
  }
`);

const cappedData = new Uint8Array(1024); // At the cap
const results6 = await scanner6.scan(cappedData);
console.log(`File size: ${cappedData.length} bytes (at cap limit)`);
console.log(`Condition: filesize > 1KB`);
console.log(`Matched: ${results6.length > 0 ? 'YES' : 'NO'} - assumes file could be larger`);
console.log();

console.log('=== Examples Complete ===');
