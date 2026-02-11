# Testing & QA Guide

## Overview

This project uses a custom standalone testing framework designed to run YARA implementation tests without external dependencies. The framework supports sync/async tests, assertions, and grouped reporting.

## Test Structure

-   `tests/`: Main test entry points (e.g., `tests/testInterceptScanner.mjs`).
-   `test_files/`: Binary or text files used as scan targets.
-   `selective_tests/`: Specialized regression tests for specific features.
-   `utilities/testingFramework.mjs`: The core testing harness.

## Running Tests

To run the full suite, execute the main test runner (check `package.json` if available, or run node scripts directly):

```bash
# Example: Running the scanner comprehensive tests
node tests/testInterceptScanner.mjs
```

## Writing Tests

Create a new test file importing the framework:

```javascript
import { test, assertEquals, assertTrue, printSummary } from '../utilities/testingFramework.mjs';
import { InterceptScanner } from '../interceptScanner.mjs';

console.log('Testing My New Feature');

await test('Feature X should detect pattern', async () => {
    const scanner = new InterceptScanner();
    await scanner.addRules('rule A { strings: $a="pattern" condition: $a }');
    
    const results = await scanner.scan(new TextEncoder().encode("pattern in buffer"));
    
    assertEquals(results.length, 1, "Should find 1 match");
    assertEquals(results[0].rule, "A", "Rule name should match");
});

printSummary();
```

## Assertion API

| Function | Description |
|----------|-------------|
| `assertEquals(actual, expected)` | Strict equality check (`===`) |
| `assertTrue(value)` | Checks truthiness |
| `assertFalse(value)` | Checks falsiness |
| `assertArrayLength(arr, len)` | Validates array size |
| `assertContains(arr, item)` | Checks if item exists in array |
| `assertThrows(fn)` | Expects function to throw error |

## Performance Benchmarking

To measure performance regression:

1.  Run the benchmark script (e.g., `node benchmark.mjs --timing`).
2.  Compare results against the baselines stored in `docs/developer/PERFORMANCE_HISTORY.md`.

Key metrics to watch:
-   **AC Search**: Should remain O(n).
-   **Build String Matches**: High cost in quantifier-heavy rules (potential bottleneck).
-   **Verification**: Watch for regex fan-out regressions.

---
**Last Updated:** 2026-02-11
