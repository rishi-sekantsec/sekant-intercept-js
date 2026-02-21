# Performance Profiling

## Overview

The scanner is performance-sensitive, as it may run against megabytes of binary data in constrained environments (browsers, lambdas). We maintain strict performance budgets for the 5-phase pipeline.

## Baseline Metrics (as of Nov 2025)

*These were collected on a Mac M3. Timing may differ on other systems*

| Phase | Scenario | Typical Runtime (ms) | Bottleneck Source |
|-------|----------|----------------------|-------------------|
| **AC Search** | Module Heavy (D) | ~54ms (99%) | Byte-by-byte traversal of large binaries when module guards fail. |
| **String Build** | Quantifier Heavy (C) | ~92ms (72%) | Array allocation/sorting when rules have thousands of matches (capped at 100). |
| **Verification** | Real World (E) | ~39ms (24%) | Regex engine execution on candidate offsets. |

## Optimization Strategies

### 1. Aho-Corasick (AC) Search
-   **Trie Compression**: We use a flat-array transition table to minimize object overhead.
-   **Failure Links**: Critical for O(n) performance. Ensure failure links are correctly computed for new patterns.

### 2. Match Building (The "Cloning" Problem)
-   **Issue**: Rules like `strings: $a = "a" condition: #a > 1000` generate massive arrays of matches.
-   **Mitigation**: We implement a **100-match cap** per string identifier.
-   **Future Work**: Stream matches directly to the condition evaluator instead of building arrays.

### 3. Regex Verification
-   **Issue**: Regexes without good literal prefixes force linear scanning or frequent verification calls.
-   **Mitigation**: The `yaraStringMatch.mjs` compiler attempts to extract the longest possible literal prefix to feed the AC engine.

## Profiling Tools

Use `benchmark.mjs` to generate a breakdown:

```bash
node benchmark.mjs --timing
```

Output focuses on the 5 phases:
1.  **AC Search**: Raw pattern finding.
2.  **Deduplication**: Filtering unique offsets.
3.  **Verification**: Full regex/hex checks.
4.  **Build String Matches**: Converting offsets to `ScanFacts`.
5.  **Condition Eval**: Running the AST.

---
**Last Updated:** 2026-02-21
