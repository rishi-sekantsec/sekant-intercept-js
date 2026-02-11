# Scan Output Reference

## Overview

The `InterceptScanner.scan()` method returns a JSON array containing all rules that matched the input data. Each object in the array represents a single matched rule.

## JSON Structure

```javascript
[
  // Array of matched rule objects
  {
    // 1. Identification
    rule: "RuleName",           // The name of the rule
    namespace: "default",       // Namespace (default is "default")
    
    // 2. Metadata
    tags: ["tag1", "tag2"],     // Array of tags attached to the rule
    metadata: {                 // Key-value pairs from the meta section
      description: "Detects malware X",
      author: "Security Analyst",
      severity: 10,
      version: "1.0"
    },

    // 3. String Matches
    // Dictionary of strings that triggered the match
    // Note: Anonymous strings ($ = ...) and private strings are excluded
    strings: {
      "$a": {
        identifier: "$a",       // Variable name
        matched: true,          // Always true in output
        count: 2,               // Total number of matches found (capped at 100)
        
        // List of specific match instances (capped at 100)
        matches: [
          {
            offset: 1024,       // Byte offset in the file
            length: 16          // Length of the match
          },
          {
            offset: 2048,
            length: 16
          }
        ],
        
        // Flattened list of offsets for convenience
        offsets: [1024, 2048]
      },
      // ... other matched strings
    }
  },
  // ... next matched rule
]
```

## Field Details

### Rule Identification
-   `rule`: The identifier defined in the YARA source (`rule RuleName { ... }`).
-   `namespace`: Currently defaults to "default". Future support for multiple namespaces may utilize this field.

### Metadata
-   `tags`: Useful for filtering results (e.g., `["malware", "critical"]`).
-   `metadata`: Arbitrary key-value pairs. Values can be strings, integers, or booleans depending on the rule definition.

### String Matches
This section provides evidence for *why* the rule matched.
-   **Filtering**:
    -   Strings declared `private` in the rule are structural only and are **removed** from this output.
    -   Anonymous strings (`$ = "pattern"`) are internal and **removed** from this output.
-   **Limits**:
    -   `count` and `matches` array are capped at `MAX_MATCHES` (default: 100).
    -   `length` is capped at `MAX_STRING_MATCH_LENGTH` (default: 2048).

## Usage Example

```javascript
const results = await scanner.scan(data);

// 1. Iterate matches
for (const match of results) {
    console.log(`Detected: ${match.rule}`);
    
    // 2. Check tags
    if (match.tags.includes("critical")) {
        alert("Critical Threat!");
    }

    // 3. Inspect specific string evidence
    if (match.strings["$signature"]) {
        const offset = match.strings["$signature"].matches[0].offset;
        console.log(`Signature found at 0x${offset.toString(16)}`);
    }
}
```
