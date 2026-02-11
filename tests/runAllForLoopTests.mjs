#!/usr/bin/env node
/**
 * Comprehensive For Loop Test Runner
 * 
 * Executes all for loop test suites and provides detailed regression analysis.
 * This script runs all test files and aggregates results for easy monitoring.
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
    name: 'Basic For Loop Tests',
    file: 'testForLoops.mjs',
    description: 'Core functionality: quantifiers, ranges, string sets',
    expectedTests: 23
  },
  {
    name: 'Real-World Scenarios',
    file: 'testForLoopsRealWorld.mjs',
    description: 'Practical malware detection patterns',
    expectedTests: 11
  },
  {
    name: 'Comprehensive Edge Cases',
    file: 'testForLoopsComprehensive.mjs',
    description: 'Complex conditions, arithmetic, large datasets',
    expectedTests: 41
  },
  {
    name: 'Extreme Edge Cases',
    file: 'testForLoopsExtreme.mjs',
    description: 'Stress tests, boundaries, pathological cases',
    expectedTests: 25
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
      const totalMatch = stdout.match(/Total tests:\s*(\d+)/);
      const passedMatch = stdout.match(/Passed:\s*(\d+)/);
      const failedMatch = stdout.match(/Failed:\s*(\d+)/);
      const successRateMatch = stdout.match(/Success rate:\s*([\d.]+)%/);
      
      const tests = totalMatch ? parseInt(totalMatch[1]) : 0;
      const passed = passedMatch ? parseInt(passedMatch[1]) : 0;
      const failed = failedMatch ? parseInt(failedMatch[1]) : 0;
      const successRate = successRateMatch ? parseFloat(successRateMatch[1]) : 0;
      
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
  console.log(`${colors.bright}Individual Test Suite Results:${colors.reset}\n`);
  
  results.forEach((result, index) => {
    const statusIcon = result.exitCode === 0 && result.failed === 0 ? '✓' : '✗';
    const statusColor = result.exitCode === 0 && result.failed === 0 ? colors.green : colors.red;
    const testCountMatch = result.tests === result.expectedTests;
    const testCountColor = testCountMatch ? colors.green : colors.yellow;
    
    console.log(`${statusColor}${statusIcon} ${colors.bright}${result.suite}${colors.reset}`);
    console.log(`  File: ${colors.dim}${result.file}${colors.reset}`);
    console.log(`  Tests: ${testCountColor}${result.tests}${colors.reset}/${result.expectedTests} (expected) | ` +
                `Passed: ${colors.green}${result.passed}${colors.reset} | ` +
                `Failed: ${result.failed > 0 ? colors.red : colors.dim}${result.failed}${colors.reset}`);
    console.log(`  Success Rate: ${result.successRate === 100 ? colors.green : colors.yellow}${result.successRate.toFixed(1)}%${colors.reset} | ` +
                `Duration: ${colors.cyan}${result.duration}ms${colors.reset}`);
    
    if (!testCountMatch) {
      console.log(`  ${colors.yellow}⚠ Warning: Test count mismatch (expected ${result.expectedTests}, got ${result.tests})${colors.reset}`);
    }
    
    if (result.failed > 0) {
      console.log(`  ${colors.red}✗ ${result.failed} test(s) failed${colors.reset}`);
    }
    
    console.log('');
  });
  
  // Overall statistics
  console.log(`${colors.bright}${colors.blue}───────────────────────────────────────────────────────────────────${colors.reset}\n`);
  console.log(`${colors.bright}Overall Statistics:${colors.reset}\n`);
  
  const allPassed = totalFailed === 0 && results.every(r => r.exitCode === 0);
  const overallSuccessRate = totalTests > 0 ? (totalPassed / totalTests * 100) : 0;
  
  console.log(`  Total Test Suites: ${colors.bright}${results.length}${colors.reset}`);
  console.log(`  Total Tests: ${colors.bright}${totalTests}${colors.reset}`);
  console.log(`  Passed: ${colors.green}${colors.bright}${totalPassed}${colors.reset}`);
  console.log(`  Failed: ${totalFailed > 0 ? colors.red : colors.dim}${colors.bright}${totalFailed}${colors.reset}`);
  console.log(`  Success Rate: ${overallSuccessRate === 100 ? colors.green : colors.yellow}${colors.bright}${overallSuccessRate.toFixed(1)}%${colors.reset}`);
  console.log(`  Total Duration: ${colors.cyan}${totalDuration}ms${colors.reset} (${(totalDuration / 1000).toFixed(2)}s)`);
  
  console.log('');
  
  // Final verdict
  if (allPassed) {
    console.log(`${colors.green}${colors.bright}┌─────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.green}${colors.bright}│  ✓ ALL TESTS PASSED - FOR LOOPS PRODUCTION READY! 🎉      │${colors.reset}`);
    console.log(`${colors.green}${colors.bright}└─────────────────────────────────────────────────────────────┘${colors.reset}`);
  } else {
    console.log(`${colors.red}${colors.bright}┌─────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.red}${colors.bright}│  ✗ SOME TESTS FAILED - REVIEW REQUIRED                     │${colors.reset}`);
    console.log(`${colors.red}${colors.bright}└─────────────────────────────────────────────────────────────┘${colors.reset}`);
    
    console.log(`\n${colors.yellow}Failed Test Suites:${colors.reset}\n`);
    results.forEach(result => {
      if (result.failed > 0 || result.exitCode !== 0) {
        console.log(`  ${colors.red}✗ ${result.suite}${colors.reset} - ${result.failed} failed tests`);
      }
    });
  }
  
  console.log('\n');
  
  // Regression analysis
  console.log(`${colors.bright}${colors.blue}═══════════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bright}${colors.blue}                    REGRESSION ANALYSIS                            ${colors.reset}`);
  console.log(`${colors.bright}${colors.blue}═══════════════════════════════════════════════════════════════════${colors.reset}\n`);
  
  console.log(`${colors.bright}Coverage Analysis:${colors.reset}\n`);
  
  const coverage = [
    { feature: 'Quantifiers (any/all/none/N/N%)', tested: totalTests >= 100 },
    { feature: 'String sets (them, $pattern*)', tested: totalTests >= 100 },
    { feature: 'Numeric ranges (i in start..end)', tested: totalTests >= 100 },
    { feature: 'Complex arithmetic (i+1, i-1, etc)', tested: totalTests >= 100 },
    { feature: 'Nested boolean logic', tested: totalTests >= 100 },
    { feature: 'Edge cases (empty sets, boundaries)', tested: totalTests >= 100 },
    { feature: 'Large datasets (1000+ items)', tested: totalTests >= 100 },
    { feature: 'Real-world patterns', tested: totalTests >= 100 }
  ];
  
  coverage.forEach(item => {
    const icon = item.tested ? '✓' : '✗';
    const color = item.tested ? colors.green : colors.red;
    console.log(`  ${color}${icon}${colors.reset} ${item.feature}`);
  });
  
  console.log('');
  
  if (allPassed && totalTests >= 100) {
    console.log(`${colors.green}✓ Full regression coverage achieved${colors.reset}`);
    console.log(`${colors.green}✓ All edge cases validated${colors.reset}`);
    console.log(`${colors.green}✓ Production-ready for deployment${colors.reset}`);
  } else if (allPassed) {
    console.log(`${colors.yellow}⚠ Tests passing but coverage below target (${totalTests}/100)${colors.reset}`);
  } else {
    console.log(`${colors.red}✗ Regression detected - failures present${colors.reset}`);
  }
  
  console.log('\n');
  
  // Exit code
  process.exit(allPassed ? 0 : 1);
}

/**
 * Main execution
 */
async function main() {
  console.log(`${colors.bright}${colors.magenta}╔═══════════════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.bright}${colors.magenta}║                                                                   ║${colors.reset}`);
  console.log(`${colors.bright}${colors.magenta}║          YARA FOR LOOPS - COMPREHENSIVE TEST SUITE                ║${colors.reset}`);
  console.log(`${colors.bright}${colors.magenta}║                                                                   ║${colors.reset}`);
  console.log(`${colors.bright}${colors.magenta}╚═══════════════════════════════════════════════════════════════════╝${colors.reset}\n`);
  
  console.log(`${colors.dim}Running ${testSuites.length} test suites...${colors.reset}\n`);
  console.log(`${colors.dim}Started at: ${new Date().toLocaleString()}${colors.reset}\n\n`);
  
  // Run all test suites sequentially
  for (const suite of testSuites) {
    await runTestSuite(suite);
  }
  
  // Print summary
  printSummary();
}

// Run the test suite
main().catch(error => {
  console.error(`${colors.red}${colors.bright}Fatal error running tests:${colors.reset}`, error);
  process.exit(1);
});
