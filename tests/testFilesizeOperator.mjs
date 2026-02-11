/**
 * Test Filesize Operator
 * 
 * Tests the filesize operator with various comparisons,
 * including special handling for capped files.
 */

import { YaraScanner } from '../yaraScanner.mjs';
import { test, assertTrue, printSummary, printSection } from './testingFramework.mjs';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

printSection('Filesize Operator Tests');

// Test 1: Basic filesize comparison
await test('filesize == exact size', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeExact {
      condition:
        filesize == 100
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
  assert(results[0].rule === 'FilesizeExact', `Expected FilesizeExact, got ${results[0].rule}`);
});

// Test 2: filesize greater than
await test('filesize > N', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeGreater {
      condition:
        filesize > 50
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 3: filesize less than
await test('filesize < N', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeLess {
      condition:
        filesize < 50
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 0, `Expected 0 matches, got ${results.length}`);
});

// Test 4: filesize range check
await test('filesize between range', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeRange {
      condition:
        filesize > 50 and filesize < 150
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 5: filesize with KB units
await test('filesize > 1KB', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeKB {
      condition:
        filesize > 1KB
    }
  `);
  
  const data = new Uint8Array(2048); // 2KB
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 6: Capped file - filesize == cap
await test('Capped file: filesize == maxFileSize', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(1024); // 1KB cap
  
  scanner.addRules(`
    rule FilesizeCapped {
      condition:
        filesize == 1024
    }
  `);
  
  const data = new Uint8Array(1024); // Exactly at cap
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 7: Capped file - filesize > cap (should match)
await test('Capped file: filesize > maxFileSize (assumes true)', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(1024); // 1KB cap
  
  scanner.addRules(`
    rule FilesizeLarger {
      condition:
        filesize > 1024
    }
  `);
  
  const data = new Uint8Array(1024); // At cap, could be larger
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match (assumes file could be larger), got ${results.length}`);
});

// Test 8: Capped file - filesize >= cap (should match)
await test('Capped file: filesize >= maxFileSize (assumes true)', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(1024); // 1KB cap
  
  scanner.addRules(`
    rule FilesizeAtLeastCap {
      condition:
        filesize >= 1024
    }
  `);
  
  const data = new Uint8Array(1024); // At cap
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 9: Capped file - filesize < cap (uses actual value)
await test('Capped file: filesize < maxFileSize (uses actual)', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(1024); // 1KB cap
  
  scanner.addRules(`
    rule FilesizeBelowCap {
      condition:
        filesize < 2048
    }
  `);
  
  const data = new Uint8Array(1024); // At cap
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match (1024 < 2048), got ${results.length}`);
});

// Test 10: Capped file - filesize == large value (should match)
await test('Capped file: filesize == large value (assumes true)', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(1024); // 1KB cap
  
  scanner.addRules(`
    rule FilesizeLargeValue {
      condition:
        filesize == 10MB
    }
  `);
  
  const data = new Uint8Array(1024); // At cap, could be 10MB
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match (assumes file could be 10MB), got ${results.length}`);
});

// Test 11: Non-capped file - normal comparisons
await test('Non-capped file: normal filesize comparisons', async () => {
  const scanner = new YaraScanner();
  scanner.setMaxFileSize(2048); // 2KB cap
  
  scanner.addRules(`
    rule FilesizeNormal {
      condition:
        filesize == 512
    }
  `);
  
  const data = new Uint8Array(512); // Below cap
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 12: Multiple filesize conditions
await test('Multiple filesize conditions with AND', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeMultiple {
      condition:
        filesize > 500 and filesize < 1500 and filesize != 999
    }
  `);
  
  const data = new Uint8Array(1000);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 13: filesize with string match
await test('filesize combined with string match', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeAndString {
      strings:
        $a = "test"
      condition:
        filesize < 1KB and $a
    }
  `);
  
  const data = new TextEncoder().encode('this is a test string');
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 14: filesize <= comparison
await test('filesize <= N', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeLessOrEqual {
      condition:
        filesize <= 100
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

// Test 15: filesize >= comparison
await test('filesize >= N', async () => {
  const scanner = new YaraScanner();
  scanner.addRules(`
    rule FilesizeGreaterOrEqual {
      condition:
        filesize >= 100
    }
  `);
  
  const data = new Uint8Array(100);
  const results = await scanner.scan(data);
  
  assert(results.length === 1, `Expected 1 match, got ${results.length}`);
});

printSummary();
