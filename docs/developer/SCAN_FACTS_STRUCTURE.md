# Scan Facts Structure

## Overview

The `ScanFacts` object is the unified, intermediate representation of all data extracted from a file during a scan. It serves as the "truth" that the Condition Matching Engine evaluates against. It isolates the *scanning* phase from the *evaluation* phase.

## JSON Structure

```javascript
{
  // 1. Core File Data
  data: Uint8Array,           // The raw binary content of the file
  filesize: number,           // Total size of the file in bytes (maps to `filesize` keyword)
  entrypoint: number,         // Entry point offset if applicable (maps to `entrypoint` keyword)

  // 2. String Validation Results
  // Maps string identifiers ($a) to their match details.
  strings: {
    "$a": {
      identifier: "$a",       // The identifier name
      matched: boolean,       // True if at least one instance was found
      count: number,          // Total count of matches found
      matches: [              // List of all match instances
        {
          offset: number,     // Offset of this specific match
          length: number,     // Length of this specific match
          data: string        // Optional: The actual data matched (for debug/reporting)
        },
        // ... more matches
      ],
      offsets: number[],      // Cached array of offsets for fast iteration
      length: number          // Fixed length of the string (if applicable/known at compile time)
    },
    // ... more strings
  },

  // 3. Module Contexts
  // Instantiated module objects providing helper functions and parsed checking instructions to `pe.*`, `elf.*`, etc.
  modules: {
    pe: PEModule,             // Instance of PE module (parsed headers, sections, etc.)
    elf: ELFModule,           // Instance of ELF module
    math: MathModule,         // Instance of Math module
    hash: HashModule,         // Instance of Hash module
    time: TimeModule,         // Instance of Time module
    string: StringModule      // Instance of String module
  },

  // 4. Metadata
  metadata: {
    filename: string,         // Name of the file scanned
    scanTime: number,         // Timestamp of the scan
    scanner: string,          // Scanner version/identifier
    // ... custom metadata fields
  }
}
```

## Usage

The `ScanFacts` object is created by the `InterceptScanner` after string matching and module parsing is complete.

```javascript
import { createScanFacts } from './yaraConditionsMatch.mjs';

const facts = createScanFacts(
    rawData, 
    stringResults, 
    moduleInstances, 
    { entrypoint: 0x4000 }
);
```

This object is then passed to `evaluateCondition(ast, facts)`.

---
**Last Updated:** 2026-02-11
