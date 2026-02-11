/**
 * Complete Integration Example
 * 
 * Demonstrates how the YARA condition matching engine integrates with:
 * - String matching (from yaraStringMatch.mjs)
 * - Math module (from mathModule.mjs)
 * - Hash module (from yaraHashModule.mjs)
 * - Condition evaluation (from yaraConditionsMatch.mjs)
 * 
 * This example shows a complete YARA rule evaluation workflow.
 */

import { createScanFacts, evaluateRules } from '../src/yaraConditionsMatch.mjs';
import { createMathModule } from '../src/mathModule.mjs';

console.log('╔════════════════════════════════════════════════════════════════╗');
console.log('║   YARA Complete Integration Example                           ║');
console.log('╚════════════════════════════════════════════════════════════════╝\n');

// ============================================================================
// Create sample file data (simulated PE file with suspicious content)
// ============================================================================

const fileData = new Uint8Array(4096);

// Add MZ header (PE signature)
fileData[0] = 0x4D; // 'M'
fileData[1] = 0x5A; // 'Z'

// Add some "encrypted" data (high entropy section)
for (let i = 1000; i < 2000; i++) {
  fileData[i] = Math.floor(Math.random() * 256);
}

// Add some suspicious strings (simulated)
const encoder = new TextEncoder();
const apiString = encoder.encode('CreateProcessA');
apiString.forEach((byte, i) => {
  fileData[100 + i] = byte;
});

const urlString = encoder.encode('http://malicious.com');
urlString.forEach((byte, i) => {
  fileData[500 + i] = byte;
});

console.log('📄 Sample File Created:');
console.log(`   Size: ${fileData.length} bytes`);
console.log(`   MZ Header: ${String.fromCharCode(fileData[0], fileData[1])}`);
console.log(`   Suspicious strings embedded\n`);

// ============================================================================
// Step 1: String Matching Results (simulated)
// ============================================================================

// In a real scenario, these would come from yaraStringMatch.mjs scanner
const stringMatches = {
  '$mz': {
    identifier: '$mz',
    matched: true,
    count: 1,
    matches: [{ offset: 0, length: 2 }],
    offsets: [0],
    length: 2
  },
  '$api_createprocess': {
    identifier: '$api_createprocess',
    matched: true,
    count: 1,
    matches: [{ offset: 100, length: 14 }],
    offsets: [100],
    length: 14
  },
  '$suspicious_url': {
    identifier: '$suspicious_url',
    matched: true,
    count: 1,
    matches: [{ offset: 500, length: 21 }],
    offsets: [500],
    length: 21
  },
  '$api_regkey': {
    identifier: '$api_regkey',
    matched: false,
    count: 0,
    matches: [],
    offsets: [],
    length: null
  }
};

console.log('🔍 String Matching Results:');
Object.entries(stringMatches).forEach(([id, result]) => {
  const status = result.matched ? '✓' : '✗';
  const info = result.matched ? `(${result.count} matches at offsets: ${result.offsets.join(', ')})` : '';
  console.log(`   ${status} ${id} ${info}`);
});
console.log();

// ============================================================================
// Step 2: Module Integration
// ============================================================================

// Create Math module
const mathModule = createMathModule(fileData);

// Calculate some metrics
const overallEntropy = mathModule.entropy(0, fileData.length);
const encryptedSectionEntropy = mathModule.entropy(1000, 1000);
const normalSectionEntropy = mathModule.entropy(0, 100);

console.log('📊 Math Module Analysis:');
console.log(`   Overall entropy: ${overallEntropy.toFixed(4)} bits/byte`);
console.log(`   Encrypted section (1000-2000): ${encryptedSectionEntropy.toFixed(4)} bits/byte`);
console.log(`   Normal section (0-100): ${normalSectionEntropy.toFixed(4)} bits/byte`);
console.log(`   Mean byte value: ${mathModule.mean(0, fileData.length).toFixed(2)}`);
console.log();

// Note: In a real scenario, you would also integrate:
// - Hash module for file hashing
// - PE module for PE-specific analysis
// - Time module for timestamp checks

// ============================================================================
// Step 3: Create Scan Facts
// ============================================================================

const scanFacts = createScanFacts(
  fileData,
  stringMatches,
  {
    math: mathModule
    // In production, add: pe, elf, hash, time, string modules
  },
  {
    entrypoint: 0x1000,
    metadata: {
      filename: 'suspicious.exe',
      scanTime: Date.now(),
      scanner: 'yara-js'
    }
  }
);

console.log('✅ Scan Facts Created:');
console.log(`   File size: ${scanFacts.filesize} bytes`);
console.log(`   Entry point: 0x${scanFacts.entrypoint.toString(16)}`);
console.log(`   Strings tracked: ${Object.keys(scanFacts.strings).length}`);
console.log(`   Modules loaded: ${Object.keys(scanFacts.modules).length}`);
console.log();

// ============================================================================
// Step 4: Define YARA Rules (as condition ASTs)
// ============================================================================

const rules = [
  {
    name: 'IsPEFile',
    description: 'Detect PE file by MZ header',
    condition: {
      type: 'and',
      left: {
        type: 'at',
        identifier: '$mz',
        offset: { type: 'number', value: 0 }
      },
      right: {
        type: 'greaterThan',
        left: { type: 'identifier', name: 'filesize' },
        right: { type: 'number', value: 1000 }
      }
    }
  },
  
  {
    name: 'SuspiciousAPICalls',
    description: 'Detect suspicious API usage',
    condition: {
      type: 'or',
      left: { type: 'stringIdentifier', identifier: '$api_createprocess' },
      right: { type: 'stringIdentifier', identifier: '$api_regkey' }
    }
  },
  
  {
    name: 'NetworkIndicator',
    description: 'Detect network-related strings',
    condition: {
      type: 'stringIdentifier',
      identifier: '$suspicious_url'
    }
  },
  
  {
    name: 'HasEncryptedData',
    description: 'Detect high entropy sections (encryption/packing)',
    condition: {
      type: 'greaterThan',
      left: { type: 'number', value: encryptedSectionEntropy },
      right: { type: 'number', value: 7.0 }
    }
  },
  
  {
    name: 'MultipleIndicators',
    description: 'At least 2 suspicious indicators',
    condition: {
      type: 'quantified',
      quantifier: { type: 'number', value: 2 },
      items: ['$mz', '$api_createprocess', '$suspicious_url']
    }
  },
  
  {
    name: 'HighConfidenceMalware',
    description: 'Multiple conditions indicating malware',
    condition: {
      type: 'and',
      left: {
        type: 'and',
        left: { type: 'stringIdentifier', identifier: '$mz' },
        right: {
          type: 'quantified',
          quantifier: { type: 'number', value: 2 },
          items: 'them'
        }
      },
      right: {
        type: 'greaterThan',
        left: { type: 'number', value: encryptedSectionEntropy },
        right: { type: 'number', value: 7.0 }
      }
    }
  },
  
  {
    name: 'StringAtEntrypoint',
    description: 'Check if string is near entrypoint',
    condition: {
      type: 'inRange',
      identifier: '$mz',
      range: {
        type: 'range',
        start: { type: 'number', value: 0 },
        end: { type: 'number', value: 100 }
      }
    }
  },
  
  {
    name: 'DataIntegrityCheck',
    description: 'Validate PE header structure',
    condition: {
      type: 'equal',
      left: {
        type: 'dataAccess',
        dataType: 'uint16',
        offset: { type: 'number', value: 0 }
      },
      right: { type: 'number', value: 0x5A4D }
    }
  }
];

console.log('📋 YARA Rules Defined:');
rules.forEach((rule, i) => {
  console.log(`   ${i + 1}. ${rule.name}: ${rule.description}`);
});
console.log();

// ============================================================================
// Step 5: Evaluate All Rules
// ============================================================================

console.log('🔍 Evaluating Rules...\n');
console.log('═'.repeat(70));

const results = await evaluateRules(rules, scanFacts);

// Display results
results.forEach((result, i) => {
  const rule = rules[i];
  const status = result.matched ? '✅ MATCH' : '❌ NO MATCH';
  const error = result.error ? ` ⚠️ Error: ${result.error}` : '';
  
  console.log(`\n${status} - ${rule.name}`);
  console.log(`   ${rule.description}${error}`);
});

console.log('\n' + '═'.repeat(70));

// ============================================================================
// Step 6: Summary Statistics
// ============================================================================

const matchedRules = results.filter(r => r.matched);
const failedRules = results.filter(r => !r.matched);
const errorRules = results.filter(r => r.error);

console.log('\n📊 Evaluation Summary:');
console.log(`   Total rules: ${results.length}`);
console.log(`   Matched: ${matchedRules.length} (${Math.round(matchedRules.length / results.length * 100)}%)`);
console.log(`   Not matched: ${failedRules.length}`);
console.log(`   Errors: ${errorRules.length}`);

if (matchedRules.length > 0) {
  console.log('\n   Matched rules:');
  matchedRules.forEach(r => console.log(`     • ${r.rule}`));
}

// ============================================================================
// Step 7: Threat Assessment
// ============================================================================

console.log('\n🎯 Threat Assessment:');

const threatScore = matchedRules.length / results.length;
let threatLevel = 'LOW';
let threatColor = '🟢';

if (threatScore >= 0.75) {
  threatLevel = 'CRITICAL';
  threatColor = '🔴';
} else if (threatScore >= 0.5) {
  threatLevel = 'HIGH';
  threatColor = '🟠';
} else if (threatScore >= 0.25) {
  threatLevel = 'MEDIUM';
  threatColor = '🟡';
}

console.log(`   Threat Level: ${threatColor} ${threatLevel}`);
console.log(`   Threat Score: ${(threatScore * 100).toFixed(1)}%`);

if (matchedRules.some(r => r.rule === 'HighConfidenceMalware')) {
  console.log(`   ⚠️  High confidence malware indicators detected!`);
}

if (encryptedSectionEntropy > 7.5) {
  console.log(`   ⚠️  Encrypted/packed content detected (entropy: ${encryptedSectionEntropy.toFixed(2)})`);
}

if (matchedRules.some(r => r.rule === 'NetworkIndicator')) {
  console.log(`   ⚠️  Network communication capabilities detected`);
}

// ============================================================================
// Step 8: Detailed Analysis
// ============================================================================

console.log('\n📈 Detailed Analysis:');
console.log('   String Matches:');
Object.entries(stringMatches).forEach(([id, result]) => {
  if (result.matched) {
    console.log(`     ${id}: ${result.count} occurrence(s)`);
    result.offsets.forEach((offset, i) => {
      console.log(`       - Match ${i + 1} at offset 0x${offset.toString(16).padStart(4, '0')}`);
    });
  }
});

console.log('\n   Entropy Analysis:');
console.log(`     Overall file: ${overallEntropy.toFixed(4)} bits/byte`);
console.log(`     First 100 bytes: ${normalSectionEntropy.toFixed(4)} bits/byte`);
console.log(`     Bytes 1000-2000: ${encryptedSectionEntropy.toFixed(4)} bits/byte`);
console.log(`     Interpretation: ${encryptedSectionEntropy > 7.5 ? 'High entropy suggests encryption/packing' : 'Normal entropy'}`);

console.log('\n   File Structure:');
console.log(`     File type: PE Executable (MZ header)`);
console.log(`     File size: ${scanFacts.filesize} bytes (${(scanFacts.filesize / 1024).toFixed(2)} KB)`);
console.log(`     Entry point: 0x${scanFacts.entrypoint.toString(16)}`);

// ============================================================================
// Final Summary
// ============================================================================

console.log('\n╔════════════════════════════════════════════════════════════════╗');
console.log('║                                                                ║');
console.log('║   Integration Example Complete!                                ║');
console.log('║                                                                ║');
console.log('╚════════════════════════════════════════════════════════════════╝\n');

console.log('✨ Demonstrated Features:');
console.log('   ✓ String pattern matching integration');
console.log('   ✓ Math module entropy analysis');
console.log('   ✓ Condition evaluation engine');
console.log('   ✓ Multiple rule evaluation');
console.log('   ✓ ScanFacts structure');
console.log('   ✓ Complex condition ASTs');
console.log('   ✓ Quantifiers (N of them)');
console.log('   ✓ Data access (uint16)');
console.log('   ✓ Position checks (at, in range)');
console.log('   ✓ Threat assessment');
console.log('   ✓ Detailed reporting\n');
