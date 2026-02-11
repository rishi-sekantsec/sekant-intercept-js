# General Overview

## Introduction
The JS-based YARA scanner is a complete, end-to-end scanning pipeline designed to execute YARA rules against binary data in a JavaScript environment. It integrates custom Aho-Corasick pattern matching with a full-featured condition evaluation engine to provide high-performance rule matching.

## Architecture

The scanner operates in two main stages: **Initialization** and **Execution**.

### Phase 0: Initialization & Compilation
Before any scanning occurs, rules must be added to the scanner.
1.  **Rule Parsing**: `yaraRuleCompiler.mjs` parses raw YARA text into an internal object representation, extracting metadata, tags, and strings.
2.  **String Compilation**: `yaraStringMatch.mjs` compiles text, hex, and regex patterns into executable matchers.
3.  **Optimization**: The `ahocorasickEngine.mjs` builds a unified automaton from all eligible string literals (and extracted regex prefixes) across all rules. This prepares the scanner for O(n) multi-pattern searching.

### Phase 1-5: The Scanning Pipeline
Once verified and compiled, the `scan()` method executes on a buffer:

1.  **Candidate Detection (Aho-Corasick)**: 
    - Rapidly scans the binary stream for potential string matches using the automaton built in Phase 0.
    - Result: A list of "candidate" matches (rule ID, string ID, offset).
2.  **Deduplication**: 
    - Filters redundant candidate matches to ensure clean downstream processing.
3.  **Verification**: 
    - Validates candidates against full constraints (e.g., verifying regex patterns at specific offsets or checking hex wildcards).
    - Runs non-optimized matchers (those with no literals) linearly.
4.  **String Match Building**: 
    - Aggregates verified matches into a structured dictionary keying matches to their rule identifiers.
    - Produces the `ScanFacts` intermediate representation.
5.  **Condition Evaluation**: 
    - Compiles rule conditions into an Abstract Syntax Tree (AST) (cached if possible).
    - Evaluates the AST against the `ScanFacts` to determine final rule validity.

## Key Files & Purpose

| File | Purpose |
|------|---------|
| `interceptScanner.mjs` | The main orchestrator class. Manages the pipeline, holds rule state, and executes scans. |
| `yaraConditionParser.mjs` | A Recursive Descent parser that converts YARA condition strings into a JSON-based AST. |
| `yaraConditionsMatch.mjs` | The evaluation engine. Traverses the AST and `ScanFacts` to compute boolean results for rules. |
| `yaraRuleCompiler.mjs` | Parses raw YARA rule text to extract metadata, strings, and condition logic. |
| `yaraStringMatch.mjs` | Handles the compilation of string patterns (Hex, Text, Regex) into matchable objects. |
| `ahocorasickEngine.mjs` | Implements the Aho-Corasick multi-pattern search algorithm for O(n) scanning performance. |

## Documentation Roadmap

To fully understand the codebase, we recommend reading the developer documentation in the following order:

### 1. Data Structures
Understanding the data flow is prerequisite to understanding the logic.
-   [SCAN_FACTS_STRUCTURE.md](SCAN_FACTS_STRUCTURE.md): The intermediate JSON object connecting the scanner and evaluator.
-   [SCAN_OUTPUT_REFERENCE.md](SCAN_OUTPUT_REFERENCE.md): The final JSON output format of the scanner.
-   [AST_REFERENCE.md](AST_REFERENCE.md): The JSON structure of parsed YARA conditions.

### 2. Core Engines
The detailed logic of the two main phases.
-   [STRING_MATCHING_ENGINE.md](STRING_MATCHING_ENGINE.md): How patterns (Regex, Hex, Text) are optimized and scanned.
-   [CONDITIONS_MATCHING_ENGINE.md](CONDITIONS_MATCHING_ENGINE.md): How the AST is evaluated against the Scan Facts.

### 3. Extensibility
-   [CUSTOM_MODULE_OVERVIEW.md](CUSTOM_MODULE_OVERVIEW.md): How to add new features or modules to the scanner.

### 4. Quality & Process
-   [TESTING_AND_QA.md](TESTING_AND_QA.md): How to run the custom testing framework.
-   [PERFORMANCE_PROFILING.md](PERFORMANCE_PROFILING.md): Performance budgets and profiling tools.
-   [CONTRIBUTION_GUIDELINES.md](CONTRIBUTION_GUIDELINES.md): Code style and contribution workflow.

## Key Assumptions

1.  **Memory Model**: The scanner assumes the entire file content fits in a standard JavaScript `Uint8Array`. Large file scanning requiring streaming is not currently implemented in the core flow.
2.  **Environment**: The engine is designed to run in generic JavaScript environments (Node.js, Browser) without native C bindings.
3.  **Module Availability**: Standard modules (PE, ELF, Math) are assumed to be instantiated and passed into the scanner context if rules require them.

## Example Usage

### Basic Initialization and Scanning

```javascript
import { InterceptScanner } from './interceptScanner.mjs';

// 1. Initialize
const scanner = new InterceptScanner();

// 2. Add Rules
const rules = `
  rule DetectExample {
    strings:
      $a = "suspicious_string"
    condition:
      $a
  }
`;
await scanner.addRules(rules);

// 3. Scan Data
const data = new Uint8Array(fs.readFileSync('target.exe'));
const results = await scanner.scan(data);

console.log(results); 
// Output: [{ rule: 'DetectExample', namespace: 'default', ... }]
```

### With Modules

```javascript
import { createMathModule } from './mathModule.mjs';

const scanner = new InterceptScanner();
const data = new Uint8Array(...);

// Modules must be instantiated per-scan or managed by the caller
const modules = {
  math: createMathModule(data)
};
scanner.setModules(modules);

scanner.addRules(`rule Entropy { condition: math.entropy(0, filesize) > 7.0 }`);
scanner.scan(data);
```

---
**Last Updated:** 2026-02-11
