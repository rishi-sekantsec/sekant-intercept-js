/**
 * YARA Math Module - Usage Examples
 * 
 * This file demonstrates how to use the yaraMathModule in various scenarios.
 */

import { createMathModule, math } from '../src/mathModule.mjs';

console.log('='.repeat(70));
console.log('YARA Math Module - Usage Examples');
console.log('='.repeat(70));

// =============================================================================
// Example 1: Entropy Analysis (Detect Encrypted/Compressed Data)
// =============================================================================
console.log('\n📌 Example 1: Entropy Analysis\n');

// High entropy data (simulating encryption)
const encryptedData = new Uint8Array(1000);
for (let i = 0; i < 1000; i++) {
  encryptedData[i] = Math.floor(Math.random() * 256);
}

// Low entropy data (repetitive)
const plainData = new Uint8Array(1000);
for (let i = 0; i < 1000; i++) {
  plainData[i] = i % 10; // Only 10 different values
}

const encMath = createMathModule(encryptedData);
const plainMath = createMathModule(plainData);

const encEntropy = encMath.entropy(0, 1000);
const plainEntropy = plainMath.entropy(0, 1000);

console.log('Encrypted Data Analysis:');
console.log(`  Entropy: ${encEntropy.toFixed(4)} bits/byte`);
console.log(`  Status: ${encEntropy > 7.5 ? '🔒 Likely encrypted/compressed' : '📄 Plain text'}`);

console.log('\nPlain Data Analysis:');
console.log(`  Entropy: ${plainEntropy.toFixed(4)} bits/byte`);
console.log(`  Status: ${plainEntropy > 7.5 ? '🔒 Likely encrypted/compressed' : '📄 Plain text'}`);

// =============================================================================
// Example 2: Standalone String Entropy
// =============================================================================
console.log('\n📌 Example 2: String Entropy Analysis\n');

const passwords = [
  'aaaa',
  'password',
  'P@ssw0rd!',
  'xK9#mL2$pQ7&vN4'
];

console.log('Password Strength (based on entropy):');
passwords.forEach(pwd => {
  const entropy = math.entropy(pwd);
  let strength = '🔴 Weak';
  if (entropy > 3.5) strength = '🟡 Medium';
  if (entropy > 4.5) strength = '🟢 Strong';
  console.log(`  "${pwd}": ${entropy.toFixed(2)} bits/char ${strength}`);
});

// =============================================================================
// Example 3: Statistical Analysis of PE Header
// =============================================================================
console.log('\n📌 Example 3: PE File Header Analysis\n');

// Simulate PE header: "MZ" followed by DOS stub
const peHeader = new Uint8Array([
  0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
  0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]);

const peMath = createMathModule(peHeader);

console.log('PE Header Statistics:');
console.log(`  Mean byte value: ${peMath.mean(0, peHeader.length).toFixed(2)}`);
console.log(`  Min byte: 0x${peMath.min(0, peHeader.length).toString(16).toUpperCase()}`);
console.log(`  Max byte: 0x${peMath.max(0, peHeader.length).toString(16).toUpperCase()}`);
const mean = peMath.mean(0, peHeader.length);
console.log(`  Std deviation: ${peMath.deviation(0, peHeader.length, mean).toFixed(2)}`);
console.log(`  Entropy: ${peMath.entropy(0, peHeader.length).toFixed(4)} bits/byte`);

// =============================================================================
// Example 4: Byte Frequency Analysis
// =============================================================================
console.log('\n📌 Example 4: Byte Frequency Analysis\n');

const testData = new Uint8Array([
  0x00, 0x00, 0x00, 0x00,  // 4x null bytes
  0x41, 0x41, 0x41,         // 3x 'A'
  0xFF, 0xFF                // 2x 0xFF
]);

const freqMath = createMathModule(testData);

console.log('Byte Frequency Analysis:');
console.log(`  Count of 0x00: ${freqMath.count(0x00, 0, testData.length)}`);
console.log(`  Count of 0x41 ('A'): ${freqMath.count(0x41, 0, testData.length)}`);
console.log(`  Count of 0xFF: ${freqMath.count(0xFF, 0, testData.length)}`);

console.log('\nPercentage Distribution:');
console.log(`  0x00: ${(freqMath.percentage(0x00, 0, testData.length) * 100).toFixed(1)}%`);
console.log(`  0x41: ${(freqMath.percentage(0x41, 0, testData.length) * 100).toFixed(1)}%`);
console.log(`  0xFF: ${(freqMath.percentage(0xFF, 0, testData.length) * 100).toFixed(1)}%`);

console.log(`\nMost common byte (mode): 0x${freqMath.mode(0, testData.length).toString(16).toUpperCase()}`);

// =============================================================================
// Example 5: Serial Correlation (Detect Patterns)
// =============================================================================
console.log('\n📌 Example 5: Serial Correlation Analysis\n');

// Random data (no correlation)
const randomData = new Uint8Array(100);
for (let i = 0; i < 100; i++) {
  randomData[i] = Math.floor(Math.random() * 256);
}

// Sequential data (high positive correlation)
const sequentialData = new Uint8Array(100);
for (let i = 0; i < 100; i++) {
  sequentialData[i] = i;
}

// Alternating data (negative correlation)
const alternatingData = new Uint8Array(100);
for (let i = 0; i < 100; i++) {
  alternatingData[i] = i % 2 === 0 ? 0 : 255;
}

const randMath = createMathModule(randomData);
const seqMath = createMathModule(sequentialData);
const altMath = createMathModule(alternatingData);

console.log('Serial Correlation (Consecutive Byte Relationship):');
console.log(`  Random data: ${randMath.serial_correlation(0, 100).toFixed(4)}`);
console.log(`  Sequential data: ${seqMath.serial_correlation(0, 100).toFixed(4)} (positive)`);
console.log(`  Alternating data: ${altMath.serial_correlation(0, 100).toFixed(4)} (negative)`);

// =============================================================================
// Example 6: Monte Carlo Pi Estimation
// =============================================================================
console.log('\n📌 Example 6: Monte Carlo Pi Estimation\n');

const piData = new Uint8Array(10000);
for (let i = 0; i < 10000; i++) {
  piData[i] = Math.floor(Math.random() * 256);
}

const piMath = createMathModule(piData);
const estimatedPi = piMath.monte_carlo_pi(0, 10000);

console.log('Monte Carlo Pi Estimation:');
console.log(`  Estimated Pi: ${estimatedPi.toFixed(6)}`);
console.log(`  Actual Pi:    ${Math.PI.toFixed(6)}`);
console.log(`  Error:        ${Math.abs(estimatedPi - Math.PI).toFixed(6)}`);
console.log(`  Accuracy:     ${(100 - Math.abs(estimatedPi - Math.PI) / Math.PI * 100).toFixed(2)}%`);

// =============================================================================
// Example 7: Utility Functions
// =============================================================================
console.log('\n📌 Example 7: Utility Functions\n');

console.log('Math Utilities:');
console.log(`  abs(-42): ${math.abs(-42)}`);
console.log(`  to_number(true): ${math.to_number(true)}`);
console.log(`  to_number(false): ${math.to_number(false)}`);
console.log(`  in_range(5, 0, 10): ${math.in_range(5, 0, 10)}`);
console.log(`  in_range(15, 0, 10): ${math.in_range(15, 0, 10)}`);

// =============================================================================
// Example 8: YARA Rule Usage
// =============================================================================
console.log('\n📌 Example 8: YARA Rule Examples\n');

console.log('Example YARA rules using math module:\n');

console.log(`rule DetectEncryption {
    condition:
        math.entropy(0, filesize) > 7.5
}

rule DetectPackedCode {
    condition:
        math.entropy(0, 1024) > 7.8 and
        math.mean(0, 1024) > 100
}

rule DetectRepeatedBytes {
    condition:
        math.deviation(0, 100) < 10.0 or
        math.percentage(0x00, 0, filesize) > 0.5
}

rule DetectPatternedData {
    condition:
        math.serial_correlation(0, 1000) > 0.8 or
        math.serial_correlation(0, 1000) < -0.8
}

rule DetectByteDistribution {
    condition:
        math.mode(0, 1024) == 0x00 and
        math.max(0, 1024) < 128
}`);

// =============================================================================
// Example 9: Real-world Use Case - Malware Detection
// =============================================================================
console.log('\n📌 Example 9: Malware Detection Heuristics\n');

// Simulate different file types
const scenarios = [
  {
    name: 'Plain text file',
    data: new TextEncoder().encode('This is a plain text file with regular English text content.')
  },
  {
    name: 'Encrypted ransomware',
    data: (() => {
      const d = new Uint8Array(100);
      for (let i = 0; i < 100; i++) d[i] = Math.floor(Math.random() * 256);
      return d;
    })()
  },
  {
    name: 'Null-padded data',
    data: new Uint8Array(100).fill(0)
  }
];

console.log('Heuristic Analysis Results:\n');

scenarios.forEach(scenario => {
  const m = createMathModule(scenario.data);
  const entropy = m.entropy(0, scenario.data.length);
  const mean = m.mean(0, scenario.data.length);
  const nullPct = m.percentage(0x00, 0, scenario.data.length);
  
  console.log(`${scenario.name}:`);
  console.log(`  Entropy: ${entropy.toFixed(4)}`);
  console.log(`  Mean: ${mean.toFixed(2)}`);
  console.log(`  Null bytes: ${(nullPct * 100).toFixed(1)}%`);
  
  // Simple heuristic
  if (entropy > 7.5) {
    console.log(`  ⚠️  WARNING: High entropy detected - possible encryption`);
  } else if (nullPct > 0.8) {
    console.log(`  ℹ️  INFO: High null byte percentage - padding or unused space`);
  } else {
    console.log(`  ✅ OK: Normal entropy levels`);
  }
  console.log();
});

console.log('='.repeat(70));
console.log('✅ All examples completed successfully!');
console.log('='.repeat(70));
