/**
 * YARA Condition Matching Engine - Usage Examples
 * 
 * Demonstrates how to use the condition matching engine with real-world scenarios.
 */

import { createScanFacts, ConditionEvaluator, evaluateCondition, evaluateRules } from '../src/yaraConditionsMatch.mjs';

console.log('╔════════════════════════════════════════════════════════════════╗');
console.log('║   YARA Condition Matching Engine - Usage Examples             ║');
console.log('╚════════════════════════════════════════════════════════════════╝\n');

// ============================================================================
// Example 1: Simple String Matching
// ============================================================================

console.log('Example 1: Simple String Matching');
console.log('─'.repeat(70));

// Simulate scanning a PE file that found MZ header and some API calls
const peData = new Uint8Array(2048);
peData[0] = 0x4D; // 'M'
peData[1] = 0x5A; // 'Z'

const scanResult1 = createScanFacts(peData, {
  '$mz': {
    identifier: '$mz',
    matched: true,
    count: 1,
    matches: [{ offset: 0, length: 2 }],
    offsets: [0]
  },
  '$api_createfile': {
    identifier: '$api_createfile',
    matched: true,
    count: 3,
    matches: [
      { offset: 100, length: 10 },
      { offset: 500, length: 10 },
      { offset: 1000, length: 10 }
    ],
    offsets: [100, 500, 1000]
  }
});

// Rule: Detect PE file with suspicious API calls
const ruleCondition1 = {
  type: 'and',
  left: {
    type: 'at',
    identifier: '$mz',
    offset: { type: 'number', value: 0 }
  },
  right: {
    type: 'greaterThan',
    left: { type: 'stringCount', identifier: '$api_createfile' },
    right: { type: 'number', value: 2 }
  }
};

const result1 = evaluateCondition(ruleCondition1, scanResult1);
console.log(`Rule: $mz at 0 and #api_createfile > 2`);
console.log(`Result: ${result1 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Explanation: MZ header at offset 0: ${scanResult1.strings['$mz'].offsets[0] === 0}, ` +
            `API calls: ${scanResult1.strings['$api_createfile'].count} > 2\n`);

// ============================================================================
// Example 2: Quantifiers - Detecting Malware Indicators
// ============================================================================

console.log('Example 2: Quantifiers - Multiple Indicators');
console.log('─'.repeat(70));

const malwareData = new Uint8Array(4096);
const scanResult2 = createScanFacts(malwareData, {
  '$reg_key1': { matched: true, count: 2, matches: [], offsets: [100, 200] },
  '$reg_key2': { matched: true, count: 1, matches: [], offsets: [300] },
  '$reg_key3': { matched: false, count: 0, matches: [], offsets: [] },
  '$api_winexec': { matched: true, count: 1, matches: [], offsets: [500] },
  '$api_urldownload': { matched: true, count: 1, matches: [], offsets: [600] },
  '$suspicious_url': { matched: false, count: 0, matches: [], offsets: [] }
});

// Rule: At least 3 of the indicators must match
const ruleCondition2 = {
  type: 'quantified',
  quantifier: { type: 'number', value: 3 },
  items: 'them'
};

const result2 = evaluateCondition(ruleCondition2, scanResult2);
const matchedCount = Object.values(scanResult2.strings).filter(s => s.matched).length;
console.log(`Rule: 3 of them`);
console.log(`Result: ${result2 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Matched strings: ${matchedCount}/6`);
console.log(`Matched: $reg_key1, $reg_key2, $api_winexec, $api_urldownload\n`);

// ============================================================================
// Example 3: Data Access - PE Header Validation
// ============================================================================

console.log('Example 3: Data Access - PE Header Validation');
console.log('─'.repeat(70));

// Create a minimal PE header
const peHeader = new Uint8Array(512);
peHeader[0] = 0x4D; // 'M'
peHeader[1] = 0x5A; // 'Z'
// e_lfanew at offset 0x3C (little endian) - points to PE signature
peHeader[0x3C] = 0x80;
peHeader[0x3D] = 0x00;
peHeader[0x3E] = 0x00;
peHeader[0x3F] = 0x00;
// PE signature at offset 0x80
peHeader[0x80] = 0x50; // 'P'
peHeader[0x81] = 0x45; // 'E'
peHeader[0x82] = 0x00;
peHeader[0x83] = 0x00;

const scanResult3 = createScanFacts(peHeader);

// Rule: Validate PE file structure
// uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
const ruleCondition3 = {
  type: 'and',
  left: {
    type: 'equal',
    left: {
      type: 'dataAccess',
      dataType: 'uint16',
      offset: { type: 'number', value: 0 },
      endian: 'little'
    },
    right: { type: 'number', value: 0x5A4D }
  },
  right: {
    type: 'equal',
    left: {
      type: 'dataAccess',
      dataType: 'uint32',
      offset: { type: 'number', value: 0x80 },
      endian: 'little'
    },
    right: { type: 'number', value: 0x00004550 }
  }
};

const result3 = evaluateCondition(ruleCondition3, scanResult3);
console.log(`Rule: uint16(0) == 0x5A4D and uint32(0x80) == 0x00004550`);
console.log(`Result: ${result3 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`MZ signature: 0x${peHeader[0].toString(16).padStart(2, '0')}${peHeader[1].toString(16).padStart(2, '0')}`);
console.log(`PE signature at 0x80: 0x${peHeader[0x80].toString(16).padStart(2, '0')}${peHeader[0x81].toString(16).padStart(2, '0')}${peHeader[0x82].toString(16).padStart(2, '0')}${peHeader[0x83].toString(16).padStart(2, '0')}\n`);

// ============================================================================
// Example 4: Complex Conditions with Arithmetic
// ============================================================================

console.log('Example 4: Arithmetic and Bitwise Operations');
console.log('─'.repeat(70));

const data4 = new Uint8Array(1024);
const scanResult4 = createScanFacts(data4, {
  '$pattern': {
    matched: true,
    count: 10,
    matches: Array(10).fill(null).map((_, i) => ({ offset: i * 100, length: 4 })),
    offsets: Array(10).fill(null).map((_, i) => i * 100)
  }
});

// Rule: Check if pattern count is within acceptable range
// #pattern >= 5 and #pattern <= 20
const ruleCondition4 = {
  type: 'and',
  left: {
    type: 'greaterThanOrEqual',
    left: { type: 'stringCount', identifier: '$pattern' },
    right: { type: 'number', value: 5 }
  },
  right: {
    type: 'lessThanOrEqual',
    left: { type: 'stringCount', identifier: '$pattern' },
    right: { type: 'number', value: 20 }
  }
};

const result4 = evaluateCondition(ruleCondition4, scanResult4);
const patternCount = scanResult4.strings['$pattern'].count;
console.log(`Rule: #pattern >= 5 and #pattern <= 20`);
console.log(`Result: ${result4 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Pattern count: ${patternCount}\n`);

// ============================================================================
// Example 5: String Position Analysis
// ============================================================================

console.log('Example 5: String Position Analysis');
console.log('─'.repeat(70));

const data5 = new Uint8Array(2048);
const scanResult5 = createScanFacts(data5, {
  '$header_string': {
    matched: true,
    count: 1,
    matches: [{ offset: 50, length: 20 }],
    offsets: [50]
  },
  '$footer_string': {
    matched: true,
    count: 1,
    matches: [{ offset: 2000, length: 10 }],
    offsets: [2000]
  }
}, {}, { entrypoint: 0x1000 });

// Rule: Header string in first 100 bytes, footer string in last 100 bytes
const ruleCondition5 = {
  type: 'and',
  left: {
    type: 'inRange',
    identifier: '$header_string',
    range: {
      type: 'range',
      start: { type: 'number', value: 0 },
      end: { type: 'number', value: 100 }
    }
  },
  right: {
    type: 'greaterThan',
    left: {
      type: 'stringOffset',
      identifier: '$footer_string',
      index: 0
    },
    right: {
      type: 'subtract',
      left: { type: 'identifier', name: 'filesize' },
      right: { type: 'number', value: 100 }
    }
  }
};

const result5 = evaluateCondition(ruleCondition5, scanResult5);
console.log(`Rule: $header_string in (0..100) and @footer_string > (filesize - 100)`);
console.log(`Result: ${result5 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Header offset: ${scanResult5.strings['$header_string'].offsets[0]}`);
console.log(`Footer offset: ${scanResult5.strings['$footer_string'].offsets[0]}`);
console.log(`Filesize: ${scanResult5.filesize}\n`);

// ============================================================================
// Example 6: Batch Rule Evaluation
// ============================================================================

console.log('Example 6: Batch Rule Evaluation');
console.log('─'.repeat(70));

const data6 = new Uint8Array(1024);
data6[0] = 0x4D; // 'M'
data6[1] = 0x5A; // 'Z'

const scanResult6 = createScanFacts(data6, {
  '$mz': { matched: true, count: 1, matches: [], offsets: [0] },
  '$api_socket': { matched: true, count: 2, matches: [], offsets: [100, 200] },
  '$api_connect': { matched: true, count: 1, matches: [], offsets: [300] },
  '$suspicious_domain': { matched: true, count: 1, matches: [], offsets: [400] }
});

const rules = [
  {
    name: 'IsPE',
    condition: {
      type: 'at',
      identifier: '$mz',
      offset: { type: 'number', value: 0 }
    }
  },
  {
    name: 'NetworkActivity',
    condition: {
      type: 'and',
      left: { type: 'stringIdentifier', identifier: '$api_socket' },
      right: { type: 'stringIdentifier', identifier: '$api_connect' }
    }
  },
  {
    name: 'SuspiciousBehavior',
    condition: {
      type: 'and',
      left: {
        type: 'quantified',
        quantifier: { type: 'number', value: 2 },
        items: ['$api_socket', '$api_connect', '$suspicious_domain']
      },
      right: {
        type: 'greaterThan',
        left: { type: 'stringCount', identifier: '$api_socket' },
        right: { type: 'number', value: 1 }
      }
    }
  },
  {
    name: 'HighConfidenceMalware',
    condition: {
      type: 'quantified',
      quantifier: { type: 'percentage', value: 75 },
      items: 'them'
    }
  }
];

const results = await evaluateRules(rules, scanResult6);

console.log('Evaluated Rules:');
results.forEach(r => {
  const status = r.matched ? '✓ MATCH' : '✗ NO MATCH';
  const error = r.error ? ` (Error: ${r.error})` : '';
  console.log(`  ${status} - ${r.rule}${error}`);
});

console.log('\nSummary:');
console.log(`Total rules: ${results.length}`);
console.log(`Matched: ${results.filter(r => r.matched).length}`);
console.log(`Not matched: ${results.filter(r => !r.matched).length}`);
console.log(`Errors: ${results.filter(r => r.error).length}\n`);

// ============================================================================
// Example 7: Integration with Module Functions
// ============================================================================

console.log('Example 7: Module Integration (Conceptual)');
console.log('─'.repeat(70));

// This example shows how modules would be integrated
// In practice, you would import and create actual module instances

const data7 = new Uint8Array(1024);
const mockMathModule = {
  entropy: (offset, size) => 7.8, // High entropy = encrypted/compressed
  mean: (offset, size) => 127.5
};

const scanResult7 = createScanFacts(data7, {
  '$encrypted_marker': { matched: true, count: 1, matches: [], offsets: [500] }
}, {
  math: mockMathModule
});

// Rule: Detect encrypted section
// math.entropy(0, 1024) > 7.5 and $encrypted_marker
const evaluator7 = new ConditionEvaluator(scanResult7);

// Manually evaluate since we're using module functions
const entropy = scanResult7.modules.math?.entropy(0, 1024) || 0;
const hasMarker = evaluator7.evaluateStringIdentifier({ identifier: '$encrypted_marker' });
const result7 = entropy > 7.5 && hasMarker;

console.log(`Rule: math.entropy(0, 1024) > 7.5 and $encrypted_marker`);
console.log(`Result: ${result7 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Entropy: ${entropy} bits/byte (threshold: 7.5)`);
console.log(`Encrypted marker found: ${hasMarker}`);
console.log(`Interpretation: ${entropy > 7.5 ? 'High entropy suggests encryption/compression' : 'Normal entropy'}\n`);

// ============================================================================
// Example 8: Advanced String Set Operations
// ============================================================================

console.log('Example 8: Advanced String Set Operations');
console.log('─'.repeat(70));

const data8 = new Uint8Array(2048);
const scanResult8 = createScanFacts(data8, {
  '$api_registry_1': { matched: true, count: 2, matches: [], offsets: [100, 200] },
  '$api_registry_2': { matched: true, count: 1, matches: [], offsets: [300] },
  '$api_registry_3': { matched: false, count: 0, matches: [], offsets: [] },
  '$api_file_1': { matched: true, count: 1, matches: [], offsets: [400] },
  '$api_file_2': { matched: false, count: 0, matches: [], offsets: [] },
  '$api_network_1': { matched: true, count: 3, matches: [], offsets: [500, 600, 700] }
});

// Rule: Any registry API and any file API
const evaluator8 = new ConditionEvaluator(scanResult8);

// Resolve API sets
const registryApis = evaluator8.resolveStringSet('$api_registry_*');
const fileApis = evaluator8.resolveStringSet('$api_file_*');

const anyRegistry = registryApis.some(id => scanResult8.strings[id]?.matched);
const anyFile = fileApis.some(id => scanResult8.strings[id]?.matched);
const result8 = anyRegistry && anyFile;

console.log(`Rule: any of ($api_registry_*) and any of ($api_file_*)`);
console.log(`Result: ${result8 ? '✓ MATCH' : '✗ NO MATCH'}`);
console.log(`Registry APIs matched: ${registryApis.filter(id => scanResult8.strings[id]?.matched).length}/${registryApis.length}`);
console.log(`File APIs matched: ${fileApis.filter(id => scanResult8.strings[id]?.matched).length}/${fileApis.length}\n`);

// ============================================================================
// Summary
// ============================================================================

console.log('═'.repeat(70));
console.log('Examples Complete!');
console.log('═'.repeat(70));
console.log('\nKey Features Demonstrated:');
console.log('  ✓ String identifiers ($a, #a, @a)');
console.log('  ✓ Logical operators (and, or, not)');
console.log('  ✓ Comparison operators (==, !=, <, >, <=, >=)');
console.log('  ✓ Arithmetic operators (+, -, *, /, %)');
console.log('  ✓ Quantifiers (all, any, none, N of them, X%)');
console.log('  ✓ Data access (uint8, uint16, uint32)');
console.log('  ✓ Position checks (at, in range)');
console.log('  ✓ Batch rule evaluation');
console.log('  ✓ Module integration');
console.log('  ✓ Wildcard string sets\n');
