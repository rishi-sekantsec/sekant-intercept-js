/**
 * End-to-End YARA Scanner Example
 * 
 * Demonstrates the complete scanner workflow with real-world examples
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { createMathModule } from '../src/mathModule.mjs';
import { createHashModule } from '../src/hashModule.mjs';
import { string } from '../src/stringModule.mjs';
import { time } from '../src/timeModule.mjs';

console.log('='.repeat(70));
console.log('YARA Scanner End-to-End Examples');
console.log('='.repeat(70));

// ============================================================================
// Example 1: Simple malware detection
// ============================================================================

console.log('\n--- Example 1: Simple Malware Detection ---\n');

const malwareScanner = new InterceptScanner();

const malwareRules = `
  rule SuspiciousExecutable {
    meta:
      description = "Detects suspicious executable patterns"
      author = "Security Team"
    strings:
      $api1 = "CreateRemoteThread"
      $api2 = "VirtualAllocEx"
      $api3 = "WriteProcessMemory"
    condition:
      2 of them
  }

  rule PackedExecutable {
    strings:
      $upx = "UPX!"
      $packer = "This program cannot be run"
    condition:
      any of them
  }
`;

malwareScanner.addRules(malwareRules);

// Simulate suspicious file content
const suspiciousData = new TextEncoder().encode(
  'Some binary data CreateRemoteThread and VirtualAllocEx functions...'
);

const malwareResults = await malwareScanner.scan(suspiciousData);
console.log('Detected rules:', malwareResults.map(r => r.rule));
console.log('Tags:', malwareResults.flatMap(r => r.tags));
console.log('Matched strings:');
malwareResults.forEach(result => {
  Object.keys(result.strings).forEach(str => {
    if (result.strings[str].matched) {
      console.log(`  ${str}: ${result.strings[str].count} occurrence(s)`);
    }
  });
});

// ============================================================================
// Example 2: Document analysis with entropy check
// ============================================================================

console.log('\n--- Example 2: Document Analysis ---\n');

const docScanner = new InterceptScanner();

// Create sample document with embedded script
const documentData = new Uint8Array(1024);
const encoder = new TextEncoder();
const script = encoder.encode('<script>eval(atob("malicious_code"))</script>');
script.forEach((byte, i) => {
  documentData[100 + i] = byte;
});

// Add random data to increase entropy
for (let i = 500; i < 1024; i++) {
  documentData[i] = Math.floor(Math.random() * 256);
}

// Set up modules
const mathModule = createMathModule(documentData);
const hashModule = createHashModule(documentData);
docScanner.setModules({ math: mathModule, hash: hashModule });

const docRules = `
  rule SuspiciousDocument {
    strings:
      $script = "<script>"
      $eval = "eval("
      $atob = "atob("
    condition:
      all of them
  }
`;

docScanner.addRules(docRules);
const docResults = await await docScanner.scan(documentData);

console.log('Document analysis results:');
console.log('  Detected rules:', docResults.map(r => r.rule));
console.log('  File size:', documentData.length, 'bytes');
console.log('  Entropy (0-1000):', mathModule.entropy(0, documentData.length));

// ============================================================================
// Example 3: Network traffic analysis
// ============================================================================

console.log('\n--- Example 3: Network Traffic Analysis ---\n');

const networkScanner = new InterceptScanner();

const networkRules = `
  rule HTTPTraffic {
    strings:
      $http_get = "GET /"
      $http_post = "POST /"
      $http_ver = "HTTP/1"
    condition:
      any of ($http_*)
  }

  rule SuspiciousURL {
    strings:
      $url1 = "http://suspicious-domain.com"
      $url2 = "malware.exe"
      $url3 = "download.php"
    condition:
      $url1 or ($url2 and $url3)
  }
`;

networkScanner.addRules(networkRules);

const packetData = new TextEncoder().encode(
  'GET /download.php HTTP/1.1\\nHost: suspicious-domain.com\\nmalware.exe'
);

const networkResults = await await networkScanner.scan(packetData);
console.log('Network analysis results:');
networkResults.forEach(result => {
  console.log(`  Rule: ${result.rule}`);
  console.log(`  Matched strings: ${Object.keys(result.strings).filter(k => result.strings[k].matched).join(', ')}`);
});

// ============================================================================
// Example 4: Multiple file scanning
// ============================================================================

console.log('\n--- Example 4: Batch File Scanning ---\n');

const batchScanner = new InterceptScanner();

const batchRules = `
  rule ContainsPassword {
    strings:
      $pwd1 = "password" nocase
      $pwd2 = "passwd" nocase
      $pwd3 = "pwd" nocase
    condition:
      any of them
  }

  rule ContainsAPIKey {
    strings:
      $key = /[A-Za-z0-9]{32,}/
    condition:
      $key
  }
`;

batchScanner.addRules(batchRules);

const files = [
  { name: 'config.txt', data: 'username=admin\\npassword=secret123' },
  { name: 'api.txt', data: 'API_KEY=abc123def456ghi789jkl012mno345pqr678' },
  { name: 'readme.txt', data: 'This is a clean readme file with no secrets' }
];

console.log('Scanning multiple files:');
files.forEach(async file => {
  const fileData = new TextEncoder().encode(file.data);
  const fileResults = await await batchScanner.scan(fileData);
  
  if (fileResults.length > 0) {
    console.log(`  ${file.name}: ${fileResults.map(r => r.rule).join(', ')}`);
  } else {
    console.log(`  ${file.name}: Clean`);
  }
});

// ============================================================================
// Example 5: Scanner statistics
// ============================================================================

console.log('\n--- Example 5: Scanner Statistics ---\n');

const statsScanner = new InterceptScanner();

const statsRules = `
  rule TestRule1 {
    strings:
      $a = "test1"
    condition:
      $a
  }

  rule TestRule2 {
    strings:
      $b = "test2"
    condition:
      $b
  }

  rule TestRule3 {
    strings:
      $c = "test3"
    condition:
      $c
  }
`;

statsScanner.addRules(statsRules);
const stats = statsScanner.getStats();

console.log('Scanner statistics:');
console.log(`  Total rules loaded: ${stats.totalRules}`);
console.log(`  Total patterns indexed: ${stats.totalPatterns}`);
console.log(`  Rules: ${stats.ruleNames.join(', ')}`);

// Clear and reload
console.log('\nClearing scanner...');
statsScanner.clear();
const clearedStats = statsScanner.getStats();
console.log(`  Rules after clear: ${clearedStats.totalRules}`);

// ============================================================================
// Example 6: String module usage
// ============================================================================

console.log('\n--- Example 6: String Module ---\n');

const stringScanner = new InterceptScanner();
stringScanner.setModules({ string });

const stringRules = `
  rule HexStringDetection {
    strings:
      $version = "0x1234"
      $decimal = "42"
    condition:
      string.to_int($version) > 0x1000 or string.to_int($decimal) == 42
  }

  rule LongStringDetection {
    strings:
      $path = "C:\\\\Program Files\\\\Application\\\\config.ini"
    condition:
      string.length($path) > 30
  }
`;

stringScanner.addRules(stringRules);

const stringData = new TextEncoder().encode('Version: 0x1234, Value: 42, Path: C:\\Program Files\\Application\\config.ini');
const stringResults = await await stringScanner.scan(stringData);

console.log('String module results:');
stringResults.forEach(result => {
  console.log(`  Rule: ${result.rule}`);
  console.log(`  Metadata:`, result.metadata);
});

// Demonstrate string module functions directly
console.log('\nString module functions:');
console.log(`  string.to_int("0x1234"): ${string.to_int("0x1234")}`);
console.log(`  string.to_int("42"): ${string.to_int("42")}`);
console.log(`  string.to_int("o755", 8): ${string.to_int("o755", 8)}`);
console.log(`  string.length("Hello World"): ${string.length("Hello World")}`);

// ============================================================================
// Example 7: Time module usage
// ============================================================================

console.log('\n--- Example 7: Time Module ---\n');

const timeScanner = new InterceptScanner();
timeScanner.setModules({ time });

// Note: Time-based rules are evaluated at scan time
const timeRules = `
  rule RecentScan {
    condition:
      time.now() > 0
  }
`;

timeScanner.addRules(timeRules);

const timeData = new TextEncoder().encode('Sample data for time-based scanning');
const timeResults = await await timeScanner.scan(timeData);

console.log('Time module results:');
console.log(`  Current timestamp: ${time.now()}`);
console.log(`  Detected rules: ${timeResults.map(r => r.rule).join(', ')}`);

// ============================================================================
// Example 8: Combined module usage
// ============================================================================

console.log('\n--- Example 8: Combined Modules ---\n');

const combinedScanner = new InterceptScanner();

// Create sample data for combined analysis
const combinedData = new Uint8Array(512);
const header = new TextEncoder().encode('VERSION=0x0100 TIMESTAMP=');
header.forEach((byte, i) => { combinedData[i] = byte; });

// Add some random data for entropy
for (let i = 100; i < 512; i++) {
  combinedData[i] = Math.floor(Math.random() * 256);
}

const combinedMath = createMathModule(combinedData);
const combinedHash = createHashModule(combinedData);

combinedScanner.setModules({
  math: combinedMath,
  hash: combinedHash,
  string,
  time
});

const combinedRules = `
  rule ComplexAnalysis {
    strings:
      $header = "VERSION="
      $timestamp = "TIMESTAMP="
    condition:
      $header and $timestamp and 
      filesize > 100 and
      time.now() > 0
  }
`;

combinedScanner.addRules(combinedRules);
const combinedResults = await combinedScanner.scan(combinedData);

console.log('Combined module analysis:');
console.log(`  File size: ${combinedData.length} bytes`);
console.log(`  Entropy: ${combinedMath.entropy(0, combinedData.length).toFixed(2)}`);
console.log(`  MD5: ${await combinedHash.md5(0, combinedData.length)}`);
console.log(`  Scan time: ${new Date(time.now()).toISOString()}`);
console.log(`  Detected rules: ${combinedResults.map(r => r.rule).join(', ')}`);

console.log('\n' + '='.repeat(70));
console.log('Examples complete!');
console.log('='.repeat(70));
