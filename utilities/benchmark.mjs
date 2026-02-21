/**
 * InterceptScanner Performance Benchmark Suite
 * 
 * Comprehensive benchmarking framework to measure the impact of optimizations.
 * Tests multiple scenarios with detailed timing breakdowns.
 * 
 * Usage:
 *   node benchmark.mjs                    # Run all scenarios
 *   node benchmark.mjs --scenario=A       # Run specific scenario
 *   node benchmark.mjs --baseline         # Save baseline for comparison
 *   node benchmark.mjs --compare=baseline.json  # Compare to baseline
 *   node benchmark.mjs --timing           # Enable detailed timing output
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';
import { performance } from 'perf_hooks';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import process from 'process';

// ═════════════════════════════════════════════════════════════════════════
// Configuration
// ═════════════════════════════════════════════════════════════════════════

const RUNS_PER_SCENARIO = 5;
const OUTPUT_FILE = 'benchmark-results.json';
const BASELINE_FILE = 'benchmark-baseline.json';

// ═════════════════════════════════════════════════════════════════════════
// Test Data Generation
// ═════════════════════════════════════════════════════════════════════════

/**
 * Generate test data of specified size with patterns
 */
function generateTestData(sizeKB, patterns = []) {
  const size = sizeKB * 1024;
  const data = new Uint8Array(size);
  
  // Fill with semi-random data
  for (let i = 0; i < size; i++) {
    data[i] = (i * 13 + 42) % 256;
  }
  
  // Insert patterns at various offsets
  const encoder = new TextEncoder();
  patterns.forEach((pattern, idx) => {
    const bytes = encoder.encode(pattern);
    const offset = Math.floor((size / (patterns.length + 1)) * (idx + 1));
    if (offset + bytes.length < size) {
      data.set(bytes, offset);
    }
  });
  
  return data;
}

/**
 * Generate PE-like binary data
 */
function generatePEData(sizeKB) {
  const size = sizeKB * 1024;
  const data = new Uint8Array(size);
  
  // MZ header
  data[0] = 0x4D; // 'M'
  data[1] = 0x5A; // 'Z'
  
  // PE signature offset at 0x3C
  data[0x3C] = 0x80;
  data[0x3D] = 0x00;
  
  // PE signature at offset 0x80
  data[0x80] = 0x50; // 'P'
  data[0x81] = 0x45; // 'E'
  data[0x82] = 0x00;
  data[0x83] = 0x00;
  
  // Fill rest with semi-random data
  for (let i = 0x84; i < size; i++) {
    data[i] = (i * 17 + 123) % 256;
  }
  
  return data;
}

/**
 * Generate ELF-like binary data
 */
function generateELFData(sizeKB) {
  const size = sizeKB * 1024;
  const data = new Uint8Array(size);
  
  // ELF magic: 0x7F 'E' 'L' 'F'
  data[0] = 0x7F;
  data[1] = 0x45; // 'E'
  data[2] = 0x4C; // 'L'
  data[3] = 0x46; // 'F'
  
  // 64-bit ELF
  data[4] = 0x02;
  
  // Little endian
  data[5] = 0x01;
  
  // Fill rest
  for (let i = 6; i < size; i++) {
    data[i] = (i * 19 + 99) % 256;
  }
  
  return data;
}

function generateRepeatedPatternData(pattern, repeatCount) {
  const encoder = new TextEncoder();
  const patBytes = encoder.encode(pattern);
  const data = new Uint8Array(patBytes.length * repeatCount);

  for (let i = 0; i < repeatCount; i++) {
    data.set(patBytes, i * patBytes.length);
  }

  return data;
}

function generateUniformData(sizeKB, byteValue = 0x41) {
  const size = sizeKB * 1024;
  const data = new Uint8Array(size);
  data.fill(byteValue & 0xff);
  return data;
}

function generateRegexFloodRules(count) {
  const pattern = '/[\\s\\S]{1,1000}/';
  const blocks = [];
  for (let i = 1; i <= count; i++) {
    blocks.push(`
      rule RegexStress${i} {
        strings: $a = ${pattern}
        condition: $a
      }
    `);
  }
  return blocks.join('\n');
}

function generateHexFloodRules(count) {
  const pattern = '{ ?? [0-100] ?? }';
  const blocks = [];
  for (let i = 1; i <= count; i++) {
    blocks.push(`
      rule HexStress${i} {
        strings: $a = ${pattern}
        condition: $a
      }
    `);
  }
  return blocks.join('\n');
}

function generateWorstCaseStressRules() {
  return `${generateRegexFloodRules(150)}\n${generateHexFloodRules(150)}`;
}

// ═════════════════════════════════════════════════════════════════════════
// Test Scenarios
// ═════════════════════════════════════════════════════════════════════════

const SCENARIOS = {
  A: {
    name: 'Simple Rules (Baseline)',
    description: '10 simple rules with basic conditions on small file',
    rules: `
      rule SimpleString1 { strings: $a = "malware" condition: $a }
      rule SimpleString2 { strings: $a = "virus" condition: $a }
      rule SimpleString3 { strings: $a = "trojan" condition: $a }
      rule SimpleString4 { strings: $a = "backdoor" condition: $a }
      rule SimpleString5 { strings: $a = "payload" condition: $a }
      rule SimpleRegex1 { strings: $a = /test[0-9]+/ condition: $a }
      rule SimpleRegex2 { strings: $a = /file_[a-z]+/ condition: $a }
      rule SimpleAnd { strings: $a = "hello" $b = "world" condition: $a and $b }
      rule SimpleOr { strings: $a = "foo" $b = "bar" condition: $a or $b }
      rule SimpleQuantifier { strings: $a = "test" $b = "data" condition: any of them }
    `,
    data: generateTestData(100, ['malware', 'test123', 'hello', 'world', 'foo']),
    dataSize: '100KB'
  },
  
  B: {
    name: 'Complex Conditions (Condition-Heavy)',
    description: '20 rules with nested conditions and complex logic',
    rules: `
      rule ComplexNested1 {
        strings: $a = "str1" $b = "str2" $c = "str3"
        condition: ($a and $b) or ($b and $c) or ($a and $c)
      }
      rule ComplexNested2 {
        strings: $a = "pat1" $b = "pat2" $c = "pat3" $d = "pat4"
        condition: (($a and $b) or ($c and $d)) and ($a or $d)
      }
      rule ComplexNested3 {
        strings: $a = "test" $b = "data" $c = "info"
        condition: (($a or $b) and $c) or (not $c and $a)
      }
      rule ComplexQuantifier1 {
        strings: $a = "api1" $b = "api2" $c = "api3" $d = "api4" $e = "api5"
        condition: 3 of them
      }
      rule ComplexQuantifier2 {
        strings: $a = "func1" $b = "func2" $c = "func3" $d = "func4"
        condition: 50% of them
      }
      rule ComplexComparison1 {
        condition: filesize > 1000 and filesize < 1000000
      }
      rule ComplexComparison2 {
        strings: $a = "check"
        condition: $a and #a > 2 and @a[1] < 5000
      }
      rule ComplexArithmetic1 {
        strings: $a = "calc"
        condition: $a and (#a * 2) + 10 > 15
      }
      rule ComplexArithmetic2 {
        condition: (filesize \\ 1024) > 50 and (filesize % 100) == 0
      }
      rule ComplexBitwise1 {
        condition: (filesize & 0xFF) > 0 and (filesize | 0x100) != 0
      }
      rule ComplexForLoop1 {
        strings: $a = "loop"
        condition: for all i in (1..#a) : (@a[i] < filesize)
      }
      rule ComplexForLoop2 {
        strings: $a = "iter" $b = "next"
        condition: for any of them : ($ at 0)
      }
      rule ComplexModule1 {
        condition: math.entropy(0, 1024) > 7.0
      }
      rule ComplexModule2 {
        condition: math.mean(0, 512) > 100 and math.max(0, 512) < 250
      }
      rule ComplexCombined1 {
        strings: $a = "combo" $b = "mix"
        condition: ($a or $b) and filesize > 10000 and math.entropy(0, 100) > 3.0
      }
      rule ComplexCombined2 {
        strings: $a = "deep" $b = "nest" $c = "cond"
        condition: (($a and ($b or $c)) or (not $a and $c)) and #a + #b + #c > 0
      }
      rule ComplexCombined3 {
        strings: $x = "x" $y = "y" $z = "z"
        condition: 2 of ($x, $y, $z) and filesize > 0 and (@x[1] + @y[1]) < filesize
      }
      rule ComplexCombined4 {
        strings: $api = /api_[a-z]+/
        condition: $api and for all i in (1..#api) : (@api[i] > 100)
      }
      rule ComplexCombined5 {
        strings: $a = "alpha" $b = "beta" $c = "gamma"
        condition: (all of them) or (2 of them and filesize > 50000)
      }
      rule ComplexCombined6 {
        strings: $m = "marker"
        condition: $m and (#m > 1) and for any i in (1..#m-1) : (@m[i+1] - @m[i] > 100)
      }
    `,
    data: generateTestData(500, [
      'str1', 'str2', 'pat1', 'test', 'api1', 'api2', 'func1', 'check',
      'calc', 'loop', 'combo', 'deep', 'x', 'alpha', 'marker'
    ]),
    dataSize: '500KB'
  },
  
  C: {
    name: 'Quantifier-Heavy (Regex Cache Impact)',
    description: '15 rules with wildcards, quantifiers, and for loops',
    rules: `
      rule Wildcard1 {
        strings: $api1 = "CreateFile" $api2 = "CreateProcess" $api3 = "CreateRemoteThread"
        condition: any of ($api*)
      }
      rule Wildcard2 {
        strings: $func1 = "malloc" $func2 = "calloc" $func3 = "free"
        condition: all of ($func*)
      }
      rule Wildcard3 {
        strings: $str1 = "pattern1" $str2 = "pattern2" $str3 = "pattern3"
        condition: 2 of ($str*)
      }
      rule Quantifier1 {
        strings: $a = "a" $b = "b" $c = "c" $d = "d" $e = "e"
        condition: 60% of them
      }
      rule Quantifier2 {
        strings: $x = "x" $y = "y" $z = "z"
        condition: all of them
      }
      rule Quantifier3 {
        strings: $p = "p" $q = "q" $r = "r" $s = "s"
        condition: 3 of them
      }
      rule ForLoop1 {
        strings: $byte = { 00 01 02 03 }
        condition: for all of them : ($ at 0)
      }
      rule ForLoop2 {
        strings: $a = "check" $b = "verify"
        condition: for any of them : (# > 0)
      }
      rule ForLoop3 {
        strings: $marker = "MARK"
        condition: for all i in (1..#marker) : (@marker[i] < filesize)
      }
      rule ForLoop4 {
        strings: $tag1 = "tag1" $tag2 = "tag2" $tag3 = "tag3"
        condition: for 2 of ($tag*) : ($ in (0..1000))
      }
      rule WildcardFor1 {
        strings: $item1 = "item1" $item2 = "item2" $item3 = "item3"
        condition: for all of ($item*) : (# > 0)
      }
      rule WildcardFor2 {
        strings: $win1 = "win" $win2 = "windows" $win3 = "win32"
        condition: for any of ($win*) : ($ at entrypoint)
      }
      rule PercentageFor {
        strings: $a = "a" $b = "b" $c = "c" $d = "d"
        condition: for 75% of them : (# > 1)
      }
      rule RangeFor {
        strings: $num = /[0-9]+/
        condition: for all i in (1..5) : (@num[i] > 0)
      }
      rule ComplexForWildcard {
        strings: $s1 = "s1" $s2 = "s2" $s3 = "s3"
        condition: for all of ($s*) : (for all i in (1..#) : (@ < filesize))
      }
    `,
    data: generateTestData(1024, [
      'CreateFile', 'malloc', 'pattern1', 'a', 'x', 'p', 'check',
      'MARK', 'tag1', 'item1', 'win', 'a', 's1', '123'
    ]),
    dataSize: '1MB'
  },
  
  D: {
    name: 'Module-Heavy (Module Sharing Impact)',
    description: '25 rules using math, hash, and file format modules',
    rules: `
      rule Math1 { condition: math.entropy(0, 1024) > 6.0 }
      rule Math2 { condition: math.mean(0, 512) > 80 }
      rule Math3 { condition: math.deviation(0, 512, 100) > 10 }
      rule Math4 { condition: math.min(0, 100) >= 0 }
      rule Math5 { condition: math.max(0, 100) <= 255 }
      rule Math6 { condition: math.entropy(100, 200) > 5.0 }
      rule Math7 { condition: math.serial_correlation(0, 500) > -1.0 }
      rule Math8 { condition: math.count(0x41, 0, 1000) > 5 }
      rule Math9 { condition: math.percentage(0x00, 0, 500) < 50 }
      rule Math10 { condition: math.in_range(filesize, 1000, 100000) }
      rule MathCombined1 { 
        condition: math.entropy(0, 512) > 5.0 and math.mean(0, 512) > 100 
      }
      rule MathCombined2 { 
        condition: math.min(0, 100) < math.max(0, 100) 
      }
      rule HashChecksum { 
        condition: hash.checksum32(0, 100) > 0 
      }
      rule HashCRC { 
        condition: hash.crc32(0, 100) != 0 
      }
      rule FileSize1 { condition: filesize > 1024 }
      rule FileSize2 { condition: filesize < 5000000 }
      rule FileSize3 { condition: filesize == 2097152 }
      rule FileSizeArithmetic1 { condition: (filesize \\ 1024) > 1 }
      rule FileSizeArithmetic2 { condition: (filesize % 1024) >= 0 }
      rule EntrypointCheck { condition: entrypoint >= 0 }
      rule Combined1 {
        strings: $a = "test"
        condition: $a and math.entropy(0, 512) > 4.0 and filesize > 1000
      }
      rule Combined2 {
        condition: math.mean(0, 256) > 100 and hash.checksum32(0, 256) > 0
      }
      rule Combined3 {
        strings: $a = "data"
        condition: $a and math.count(0x61, 0, 1000) > 10 and filesize > 10000
      }
      rule Combined4 {
        condition: math.entropy(0, 1024) > 7.0 and (filesize \\ 1024) < 10000
      }
      rule Combined5 {
        strings: $a = "marker"
        condition: $a and math.deviation(0, 512, math.mean(0, 512)) > 20
      }
    `,
    data: generatePEData(2048),
    dataSize: '2MB (PE-like)'
  },
  
  E: {
    name: 'Real-World Mixed (Overall Impact)',
    description: '50 diverse rules representing real-world workload',
    rules: `
      // String matching (10 rules)
      rule Strings1 { strings: $a = "malware" condition: $a }
      rule Strings2 { strings: $a = "virus" condition: $a }
      rule Strings3 { strings: $a = /suspicious[0-9]+/ condition: $a }
      rule Strings4 { strings: $a = "backdoor" $b = "trojan" condition: $a and $b }
      rule Strings5 { strings: $a = "payload" condition: #a > 1 }
      rule Strings6 { strings: $a = { 4D 5A 90 00 } condition: $a at 0 }
      rule Strings7 { strings: $a = "test" ascii wide condition: $a }
      rule Strings8 { strings: $a = "password" nocase condition: $a }
      rule Strings9 { strings: $a = "admin" $b = "root" condition: any of them }
      rule Strings10 { strings: $a = "secret" condition: $a in (0..1000) }
      
      // Quantifiers (10 rules)
      rule Quant1 { strings: $a = "a" $b = "b" $c = "c" condition: 2 of them }
      rule Quant2 { strings: $x = "x" $y = "y" condition: all of them }
      rule Quant3 { strings: $p = "p" $q = "q" $r = "r" condition: any of them }
      rule Quant4 { strings: $api1 = "api1" $api2 = "api2" condition: all of ($api*) }
      rule Quant5 { strings: $f1 = "f1" $f2 = "f2" $f3 = "f3" condition: 60% of them }
      rule Quant6 { strings: $s = "s" condition: #s > 2 }
      rule Quant7 { strings: $m = "m" condition: @m[1] < 1000 }
      rule Quant8 { strings: $tag = "tag" condition: for all of them : (# > 0) }
      rule Quant9 { strings: $win = "win" condition: for any i in (1..5) : (@ > 0) }
      rule Quant10 { strings: $a = "a" $b = "b" condition: for all of them : (# > 0) }
      
      // Math module (10 rules)
      rule Math1 { condition: math.entropy(0, 1024) > 6.0 }
      rule Math2 { condition: math.mean(0, 512) > 100 }
      rule Math3 { condition: math.max(0, 100) < 256 }
      rule Math4 { condition: math.min(0, 100) >= 0 }
      rule Math5 { condition: math.count(0x00, 0, 500) < 100 }
      rule Math6 { condition: math.percentage(0x41, 0, 500) < 50 }
      rule Math7 { condition: math.entropy(100, 200) > 5.0 }
      rule Math8 { condition: math.serial_correlation(0, 500) > -1.0 }
      rule Math9 { condition: math.in_range(filesize, 100, 10000000) }
      rule Math10 { condition: math.deviation(0, 512, 100) > 10 }
      
      // File properties (10 rules)
      rule File1 { condition: filesize > 1000 }
      rule File2 { condition: filesize < 10000000 }
      rule File3 { condition: (filesize \\ 1024) > 1 }
      rule File4 { condition: (filesize % 100) == 0 }
      rule File5 { condition: filesize >= 1024 and filesize <= 2048000 }
      rule File6 { condition: entrypoint > 0 }
      rule File7 { condition: filesize > 0 and entrypoint >= 0 }
      rule File8 { condition: hash.checksum32(0, 100) > 0 }
      rule File9 { condition: hash.crc32(0, 100) != 0 }
      rule File10 { condition: filesize & 0xFF > 0 }
      
      // Complex combinations (10 rules)
      rule Complex1 {
        strings: $a = "combo"
        condition: $a and filesize > 10000 and math.entropy(0, 512) > 5.0
      }
      rule Complex2 {
        strings: $a = "test" $b = "data"
        condition: ($a or $b) and #a + #b > 0 and filesize > 5000
      }
      rule Complex3 {
        strings: $x = "x"
        condition: $x and for all i in (1..#x) : (@x[i] < filesize)
      }
      rule Complex4 {
        condition: math.entropy(0, 1024) > 7.0 and (filesize \\ 1024) < 10000
      }
      rule Complex5 {
        strings: $api = /api_[a-z]+/
        condition: $api and for all i in (1..#api) : (@api[i] > 100)
      }
      rule Complex6 {
        strings: $a = "alpha" $b = "beta"
        condition: (all of them) or (any of them and filesize > 50000)
      }
      rule Complex7 {
        strings: $m = "marker"
        condition: $m and #m > 1 and math.count(0x4D, 0, 1000) > 5
      }
      rule Complex8 {
        condition: (math.mean(0, 512) > 100) and (hash.checksum32(0, 512) > 0)
      }
      rule Complex9 {
        strings: $s = "secret"
        condition: $s and math.in_range(@s[1], 0, filesize)
      }
      rule Complex10 {
        strings: $a = "deep" $b = "nest"
        condition: ($a and $b) or (not $a and filesize > 100000) or math.entropy(0, 100) > 6.0
      }
    `,
    data: generateTestData(1024, [
      'malware', 'suspicious123', 'backdoor', 'trojan', 'payload', 'test',
      'password', 'admin', 'secret', 'a', 'x', 'tag', 'combo', 'data', 'marker'
    ]),
    dataSize: '1MB'
  },
  
  F: {
    name: 'Match Overflow (MAX_MATCHES Stress)',
    description: 'Single rule with >100 literal hits to prove aggregation can exceed MAX_MATCHES',
    rules: `
      rule OverflowMatches {
        strings: $a = "overflow"
        condition: $a
      }
    `,
    data: generateRepeatedPatternData('overflow', 150),
    dataSize: '~1.2KB (150 repetitions)'
  },
  
  G: {
    name: 'Worst Case Regex & Hex Flood',
    description: '300 rules (150 regex + 150 hex) that broadly match 1MB of uniform data to stress timing and aggregation',
    rules: generateWorstCaseStressRules(),
    data: generateUniformData(1024, 0x41),
    dataSize: '1MB uniform (0x41)'
  }
};

// ═════════════════════════════════════════════════════════════════════════
// Benchmarking Functions
// ═════════════════════════════════════════════════════════════════════════

/**
 * High-resolution timer wrapper
 */
class Timer {
  constructor(name) {
    this.name = name;
    this.startTime = 0;
    this.endTime = 0;
  }
  
  start() {
    this.startTime = performance.now();
  }
  
  stop() {
    this.endTime = performance.now();
    return this.elapsed();
  }
  
  elapsed() {
    return this.endTime - this.startTime;
  }
}

const STEP_LABELS = {
  buildAutomaton: "Build automaton",
  acSearch: "Aho-Corasick search",
  deduplicate: "Candidate deduplication",
  verifyCandidates: "Verify candidates",
  buildMatches: "Build string matches",
  evaluateConditions: "Evaluate conditions",
  filterStrings: "Filter strings",
};

const MODULE_LABELS = {
  total: "Total module creation",
  pe: "PE module",
  elf: "ELF module",
  math: "Math module",
  hash: "Hash module",
};

function aggregateRunTimings(runTimings) {
  if (!runTimings || runTimings.length === 0) {
    return null;
  }

  const sum = {
    total: 0,
    steps: {},
    modules: {},
    conditionParsingTotal: 0,
    conditionParsingByRule: {},
  };

  for (const run of runTimings) {
    if (run.total != null) {
      sum.total += run.total;
    }

    if (run.steps) {
      for (const [key, value] of Object.entries(run.steps)) {
        if (value == null) continue;
        sum.steps[key] = (sum.steps[key] || 0) + value;
      }
    }

    if (run.modules) {
      for (const [key, value] of Object.entries(run.modules)) {
        if (value == null) continue;
        sum.modules[key] = (sum.modules[key] || 0) + value;
      }
    }

    if (run.conditionParsing) {
      if (run.conditionParsing.total != null) {
        sum.conditionParsingTotal += run.conditionParsing.total;
      }
      if (run.conditionParsing.byRule) {
        for (const [ruleName, value] of Object.entries(run.conditionParsing.byRule)) {
          if (value == null) continue;
          sum.conditionParsingByRule[ruleName] = (sum.conditionParsingByRule[ruleName] || 0) + value;
        }
      }
    }
  }

  const count = runTimings.length;
  const averageSteps = {};
  for (const [key, value] of Object.entries(sum.steps)) {
    averageSteps[key] = value / count;
  }

  const averageModules = {};
  for (const [key, value] of Object.entries(sum.modules)) {
    averageModules[key] = value / count;
  }

  const averageConditionByRule = [];
  for (const [key, value] of Object.entries(sum.conditionParsingByRule)) {
    averageConditionByRule.push([key, value / count]);
  }
  averageConditionByRule.sort((a, b) => b[1] - a[1]);

  return {
    total: sum.total / count,
    steps: averageSteps,
    modules: averageModules,
    conditionParsing: {
      total: sum.conditionParsingTotal / count,
      topRules: averageConditionByRule.slice(0, 5),
    },
  };
}

/**
 * Run a single scan with detailed timing
 */
async function runScan(scanner, data) {
  // Overall scan time
  const totalTimer = new Timer('total');
  totalTimer.start();
  
  const results = await scanner.scan(data);

  const manualTotal = totalTimer.stop();
  const timingSnapshot = scanner.getTiming();
  const scanTiming = timingSnapshot && timingSnapshot.scan ? timingSnapshot.scan : null;

  const timings = scanTiming
    ? { ...scanTiming, matchCount: results.length }
    : { total: manualTotal, matchCount: results.length };

  if (timings.total == null) {
    timings.total = manualTotal;
  }
  if (timings.matchCount == null) {
    timings.matchCount = results.length;
  }
  
  return { results, timings };
}

/**
 * Run benchmark for a single scenario
 */
async function benchmarkScenario(scenarioId, scenario, runs = RUNS_PER_SCENARIO, options = {}) {
  console.log(`\n${'═'.repeat(80)}`);
  console.log(`📊 Scenario ${scenarioId}: ${scenario.name}`);
  console.log(`   ${scenario.description}`);
  console.log(`   Data size: ${scenario.dataSize}`);
  console.log(`${'═'.repeat(80)}\n`);

  const timingEnabled = Boolean(options.enableTiming);
  const timingLogger = options.timingLogger ?? null;
  const scanner = new InterceptScanner({
    timing: {
      enabled: timingEnabled,
      autoPrint: false,
      logger: timingLogger ?? console.log,
    },
  });
  
  // Compilation phase
  console.log('⏱️  Compiling rules...');
  const compileTimer = new Timer('compile');
  compileTimer.start();
  scanner.addRules(scenario.rules);
  const manualCompileTime = compileTimer.stop();
  const compileTimingSnapshot = timingEnabled ? scanner.getTiming().compile : null;
  const compileTime = compileTimingSnapshot?.total ?? manualCompileTime;
  console.log(`✓ Compilation: ${compileTime.toFixed(2)}ms`);
  
  const stats = scanner.getStats();
  console.log(`   Rules: ${stats.totalRules}, Strings: ${stats.totalStrings}, Patterns: ${stats.totalPatterns}`);
  
  // Warmup run
  console.log('\n🔥 Warmup run...');
  await scanner.scan(scenario.data);
  
  // Benchmark runs
  console.log(`\n🏃 Running ${runs} benchmark iterations...\n`);
  
  const runResults = [];
  
  for (let i = 0; i < runs; i++) {
    const { timings } = await runScan(scanner, scenario.data);
    runResults.push(timings);
    
    console.log(`   Run ${i + 1}: ${timings.total.toFixed(2)}ms (${timings.matchCount} matches)`);
  }
  
  // Calculate statistics
  const totalTimes = runResults.map(r => r.total);
  const avgTotal = totalTimes.reduce((a, b) => a + b, 0) / totalTimes.length;
  const minTotal = Math.min(...totalTimes);
  const maxTotal = Math.max(...totalTimes);
  const stdDev = Math.sqrt(
    totalTimes.reduce((sum, t) => sum + Math.pow(t - avgTotal, 2), 0) / totalTimes.length
  );
  
  console.log(`\n📈 Statistics:`);
  console.log(`   Average: ${avgTotal.toFixed(2)}ms`);
  console.log(`   Min:     ${minTotal.toFixed(2)}ms`);
  console.log(`   Max:     ${maxTotal.toFixed(2)}ms`);
  console.log(`   StdDev:  ${stdDev.toFixed(2)}ms`);
  console.log(`   CV:      ${((stdDev / avgTotal) * 100).toFixed(1)}%`);

  let timingSummary = null;
  if (timingEnabled) {
    timingSummary = aggregateRunTimings(runResults);
    if (compileTimingSnapshot) {
      console.log(`\n🛠️ Compilation timing:`);
      console.log(`   Total: ${compileTimingSnapshot.total.toFixed(2)}ms`);
    }
    if (timingSummary) {
      console.log(`\n🕒 Detailed timing (average per run):`);
      console.log(`   Total: ${timingSummary.total.toFixed(2)}ms`);

      const stepEntries = Object.entries(STEP_LABELS)
        .filter(([key]) => timingSummary.steps[key] != null)
        .map(([key, label]) => [label, timingSummary.steps[key]]);
      if (stepEntries.length > 0) {
        console.log('   Steps:');
        stepEntries.forEach(([label, value]) => {
          console.log(`     - ${label.padEnd(26)} ${value.toFixed(2)}ms`);
        });
      }

      const moduleEntries = Object.entries(MODULE_LABELS)
        .filter(([key]) => timingSummary.modules[key] != null && timingSummary.modules[key] > 0)
        .map(([key, label]) => [label, timingSummary.modules[key]]);
      if (moduleEntries.length > 0) {
        console.log('   Modules:');
        moduleEntries.forEach(([label, value]) => {
          console.log(`     - ${label.padEnd(26)} ${value.toFixed(2)}ms`);
        });
      }

      if (timingSummary.conditionParsing && timingSummary.conditionParsing.total != null) {
        console.log('   Condition parsing:');
        console.log(`     - total${' '.repeat(21)} ${timingSummary.conditionParsing.total.toFixed(2)}ms`);
        const topRules = timingSummary.conditionParsing.topRules || [];
        if (topRules.length > 0) {
          topRules.slice(0, 3).forEach(([ruleName, value]) => {
            console.log(`     - ${ruleName.padEnd(26)} ${value.toFixed(2)}ms`);
          });
        }
      }
    }
  }
  
  return {
    scenario: scenarioId,
    name: scenario.name,
    description: scenario.description,
    dataSize: scenario.dataSize,
    rules: stats,
    compile: {
      time: compileTime,
      details: compileTimingSnapshot,
    },
    runs: runResults,
    statistics: {
      average: avgTotal,
      min: minTotal,
      max: maxTotal,
      stdDev: stdDev,
      cv: (stdDev / avgTotal) * 100
    },
    timing: timingSummary,
  };
}

/**
 * Run all scenarios
 */
async function runAllBenchmarks(selectedScenario = null, options = {}) {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║                   YARA Scanner Performance Benchmark                         ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');
  
  const results = {
    timestamp: new Date().toISOString(),
    scenarios: {}
  };
  
  const scenariosToRun = selectedScenario 
    ? { [selectedScenario]: SCENARIOS[selectedScenario] }
    : SCENARIOS;
  
  for (const [id, scenario] of Object.entries(scenariosToRun)) {
    results.scenarios[id] = await benchmarkScenario(id, scenario, RUNS_PER_SCENARIO, options);
  }
  
  return results;
}

/**
 * Print summary table
 */
function printSummary(results) {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║                              Summary                                         ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Scenario │ Rules │ Data Size │ Compile  │ Avg Scan │ Min Scan │ Max Scan │ Comments');
  console.log('─────────┼───────┼───────────┼──────────┼──────────┼──────────┼──────────┼───────────────');
  
  for (const [id, result] of Object.entries(results.scenarios)) {
    let dataSizeStr = result.dataSize;
    let comment = '';
    
    const parenIndex = dataSizeStr.indexOf('(');
    if (parenIndex !== -1) {
      const closingParen = dataSizeStr.lastIndexOf(')');
      if (closingParen !== -1) {
        comment = dataSizeStr.substring(parenIndex + 1, closingParen);
        dataSizeStr = dataSizeStr.substring(0, parenIndex).trim();
      }
    }

    // Handle "uniform" case specifically to move it to comments
    if (dataSizeStr.includes('uniform')) {
      const parts = dataSizeStr.split(' uniform');
      dataSizeStr = parts[0].trim();
      comment = comment ? `uniform ${parts[1] || ''}, ${comment}` : `uniform ${parts[1] || ''}`;
    }

    const name = id.padEnd(8);
    const rules = String(result.rules.totalRules).padStart(5);
    const dataSize = dataSizeStr.padEnd(9);
    const compile = `${result.compile.time.toFixed(1)}ms`.padStart(8);
    const avg = `${result.statistics.average.toFixed(1)}ms`.padStart(8);
    const min = `${result.statistics.min.toFixed(1)}ms`.padStart(8);
    const max = `${result.statistics.max.toFixed(1)}ms`.padStart(8);
    
    console.log(`${name} │ ${rules} │ ${dataSize} │ ${compile} │ ${avg} │ ${min} │ ${max} │ ${comment}`);
  }
  
  console.log('');
}

/**
 * Compare to baseline
 */
function compareToBaseline(current, baseline) {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║                      Comparison to Baseline                                  ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Scenario │ Baseline Avg │ Current Avg │ Difference │ Improvement');
  console.log('─────────┼──────────────┼─────────────┼────────────┼────────────');
  
  for (const [id, currentResult] of Object.entries(current.scenarios)) {
    const baselineResult = baseline.scenarios[id];
    if (!baselineResult) continue;
    
    const baselineAvg = baselineResult.statistics.average;
    const currentAvg = currentResult.statistics.average;
    const diff = currentAvg - baselineAvg;
    const improvement = ((baselineAvg - currentAvg) / baselineAvg) * 100;
    
    const name = id.padEnd(8);
    const baseStr = `${baselineAvg.toFixed(1)}ms`.padStart(12);
    const currStr = `${currentAvg.toFixed(1)}ms`.padStart(11);
    const diffStr = `${diff > 0 ? '+' : ''}${diff.toFixed(1)}ms`.padStart(10);
    const impStr = `${improvement > 0 ? '+' : ''}${improvement.toFixed(1)}%`.padStart(10);
    
    const indicator = improvement > 5 ? '🚀' : improvement > 0 ? '✓' : improvement > -5 ? '=' : '⚠️';
    
    console.log(`${name} │ ${baseStr} │ ${currStr} │ ${diffStr} │ ${impStr} ${indicator}`);
  }
  
  console.log('');
}

// ═════════════════════════════════════════════════════════════════════════
// Main
// ═════════════════════════════════════════════════════════════════════════

async function main() {
  const args = process.argv.slice(2);
  const isBaseline = args.includes('--baseline');
  const showTiming = args.includes('--timing');
  const scenarioArg = args.find(a => a.startsWith('--scenario='));
  const compareArg = args.find(a => a.startsWith('--compare='));
  const selectedScenario = scenarioArg ? scenarioArg.split('=')[1] : null;
  
  if (selectedScenario && !SCENARIOS[selectedScenario]) {
    console.error(`❌ Unknown scenario: ${selectedScenario}`);
    console.log('Available scenarios:', Object.keys(SCENARIOS).join(', '));
    process.exit(1);
  }
  
  // Run benchmarks
  const results = await runAllBenchmarks(selectedScenario, { enableTiming: showTiming });
  
  // Print summary
  printSummary(results);
  
  // Save results
  const outputFile = isBaseline ? BASELINE_FILE : OUTPUT_FILE;
  writeFileSync(outputFile, JSON.stringify(results, null, 2));
  console.log(`\n💾 Results saved to: ${outputFile}\n`);
  
  // Compare to baseline if requested
  if (compareArg) {
    const baselineFile = compareArg.split('=')[1];
    if (existsSync(baselineFile)) {
      const baseline = JSON.parse(readFileSync(baselineFile, 'utf8'));
      compareToBaseline(results, baseline);
    } else {
      console.error(`❌ Baseline file not found: ${baselineFile}`);
    }
  } else if (!isBaseline && existsSync(BASELINE_FILE)) {
    // Auto-compare to baseline if it exists
    const baseline = JSON.parse(readFileSync(BASELINE_FILE, 'utf8'));
    compareToBaseline(results, baseline);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { runAllBenchmarks, benchmarkScenario };
