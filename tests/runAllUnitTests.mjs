#!/usr/bin/env node
/**
 * Comprehensive Unit Test Runner
 * 
 * Executes all unit test suites and provides detailed regression analysis.
 * This script runs feature-specific unit tests (Private rules, Global rules, Data access, etc.)
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

// Test suites to run
const testSuites = [
  {
    name: 'Anonymous Strings',
    file: 'testAnonymousStrings.mjs',
    description: 'Anonymous string identifiers ($ = "...")',
    expectedTests: null
  },
  {
    name: 'Big Endian Support',
    file: 'testBigEndian.mjs',
    description: 'Big-endian data access functions (uint16be, etc.)',
    expectedTests: null
  },
  {
    name: 'Boolean Literals',
    file: 'testBooleanLiterals.mjs',
    description: 'True/False literal support in conditions',
    expectedTests: null
  },
  {
    name: 'YARA Rule Compiler',
    file: 'testComprehensive.mjs',
    description: 'Complex rule compilation and parsing',
    expectedTests: null
  },
  {
    name: 'Data Access Functions',
    file: 'testDataAccess.mjs',
    description: 'Int/Uint 8-32 functionality',
    expectedTests: null
  },
  {
    name: 'Defined Keyword',
    file: 'testDefined.mjs',
    description: '"defined" keyword support',
    expectedTests: null
  },
  {
    name: 'Dependent Rules',
    file: 'testDependentRules.mjs',
    description: 'Rules referencing other rules in conditions',
    expectedTests: null
  },
  {
    name: 'Global Rules',
    file: 'testGlobalRules.mjs',
    description: '"global rule" modifier behavior',
    expectedTests: null
  },
  {
    name: 'Private Rules',
    file: 'testPrivateRules.mjs',
    description: '"private rule" modifier behavior',
    expectedTests: null
  }
];

// Test results
const results = [];
let totalTests = 0;
let totalPassed = 0;
let totalFailed = 0;
let totalDuration = 0;

/**
 * Run a single test suite
 */
function runTestSuite(suite) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const testPath = join(__dirname, suite.file);
    
    console.log(`${colors.cyan}${colors.bright}┌─────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.cyan}${colors.bright}│ Running: ${suite.name.padEnd(48)}│${colors.reset}`);
    console.log(`${colors.cyan}${colors.bright}└─────────────────────────────────────────────────────────────┘${colors.reset}`);
    console.log(`${colors.dim}${suite.description}${colors.reset}\n`);
    
    let stdout = '';
    let stderr = '';
    
    const child = spawn('node', [testPath], {
      cwd: __dirname,
      env: process.env
    });
    
    child.stdout.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      process.stdout.write(output);
    });
    
    child.stderr.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      process.stderr.write(output);
    });
    
    child.on('close', (code) => {
      const duration = Date.now() - startTime;
      
      // Parse output for test results
      const totalMatch = stdout.match(/Total [Tt]ests:\s*(\d+)/) || 
                        stdout.match(/Total:\s*(\d+)/) ||
                        stdout.match(/Tests run:\s*(\d+)/);
      const passedMatch = stdout.match(/Passed:\s*(\d+)/) || 
                         stdout.match(/✓ Passed:\s*(\d+)/) ||
                         stdout.match(/✓.*:\s*(\d+)/);
      const failedMatch = stdout.match(/Failed:\s*(\d+)/) || 
                         stdout.match(/✗ Failed:\s*(\d+)/) ||
                         stdout.match(/✗.*:\s*(\d+)/);
      const successRateMatch = stdout.match(/Success [Rr]ate:\s*([\d.]+)%/);
      
      const tests = totalMatch ? parseInt(totalMatch[1]) : 0;
      const passed = passedMatch ? parseInt(passedMatch[1]) : 0;
      const failed = failedMatch ? parseInt(failedMatch[1]) : 0;
      const successRate = successRateMatch ? parseFloat(successRateMatch[1]) : 
                         (tests > 0 ? (passed / tests * 100) : 0);
      
      results.push({
        suite: suite.name,
        file: suite.file,
        description: suite.description,
        expectedTests: suite.expectedTests,
        tests,
        passed,
        failed,
        successRate,
        duration,
        exitCode: code,
        stdout,
        stderr
      });
      
      totalTests += tests;
      totalPassed += passed;
      totalFailed += failed;
      totalDuration += duration;
      
      console.log('');
      resolve();
    });
  });
}

/**
 * Print summary report
 */
function printSummary() {
  console.log('\n');
  console.log(`${colors.bright}${colors.blue}═══════════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bright}${colors.blue}                    TEST RESULTS SUMMARY                           ${colors.reset}`);
  console.log(`${colors.bright}${colors.blue}═══════════════════════════════════════════════════════════════════${colors.reset}\n`);
  
  // Individual suite results
  console.log(`${colors.bright}Individual Unit Test Results:${colors.reset}\n`);
  
  results.forEach((result) => {
    const hasFailed = result.failed > 0;
    const statusIcon = hasFailed ? '✗' : '✓';
    const statusColor = hasFailed ? colors.red : colors.green;
    
    console.log(`${statusColor}${statusIcon} ${colors.bright}${result.suite}${colors.reset}`);
    console.log(`  File: ${colors.dim}${result.file}${colors.reset}`);
    console.log(`  Tests: ${result.tests} | ` +
                `Passed: ${colors.green}${result.passed}${colors.reset} | ` +
                `Failed: ${result.failed > 0 ? colors.red : colors.dim}${result.failed}${colors.reset}`);
    console.log(`  Success Rate: ${result.successRate.toFixed(1)}% | Duration: ${result.duration}ms`);
    console.log('');
  });
  
  console.log(`${colors.bright}Overall Statistics:${colors.reset}`);
  console.log(`Total Suites:  ${results.length}`);
  console.log(`Total Tests:   ${totalTests}`);
  console.log(`Total Passed:  ${colors.green}${totalPassed}${colors.reset}`);
  console.log(`Total Failed:  ${totalFailed > 0 ? colors.red : colors.dim}${totalFailed}${colors.reset}`);
  console.log(`Total Duration: ${totalDuration}ms`);
  
  if (totalFailed > 0) {
    console.log(`\n${colors.red}${colors.bright}SOME TESTS FAILED${colors.reset}`);
    process.exit(1);
  } else {
    console.log(`\n${colors.green}${colors.bright}ALL TESTS PASSED${colors.reset}`);
    process.exit(0);
  }
}

// Run all suites sequentially
(async () => {
  console.log(`\n${colors.bright}${colors.magenta}SEKANT INTERCEPT JS - UNIT TEST RUNNER${colors.reset}\n`);
  
  for (const suite of testSuites) {
    await runTestSuite(suite);
  }
  
  printSummary();
})();
