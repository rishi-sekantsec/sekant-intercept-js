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
    -   `count` and `matches` array are capped at the scanner's `maxMatches` (default: 100).
    -   `length` is the full matched length and is never truncated; only the verifier's scan window is bounded (4096 bytes, `MAX_RE_SCAN_LIMIT`).

### Capture Groups (Intercept extension)

YARA's match record (`YR_MATCH`) carries no capture information, so capture output is opt-in.
Construct the scanner with `includeCaptures: true`:

```javascript
const scanner = new InterceptScanner({ includeCaptures: true });
```

Regex matches then carry an enumerable `captures` array with **capture group 1** — the same group
`rejectRECapture(...)` passes to filter rules — including its value and its byte position:

```javascript
matches: [
  { offset: 0, length: 9,
    captures: [ { index: 1, name: 'user', value: 'abc', offset: 3, length: 3 } ] }
]
```

-   `index` is always `1`; later groups are not reported, so their substrings are collectable
    immediately after the match iteration.
-   `name` is present only when group 1 is named (`(?<user>...)`).
-   `offset` and `length` are **absolute byte offsets** into the scanned buffer, so
    `data.slice(offset, offset + length)` yields the captured text.
-   A non-participating group 1 reports `value: null, offset: null, length: null`; an empty
    participating group reports `""` at a numeric offset with `length: 0`. A pattern with no
    capture group yields `captures: []`.
-   A capture may lie outside the match span: `/(?=(abc))/` matches zero bytes but captures three,
    and `/(?<=(ab))c/` captures bytes before the match.
-   Text and hex strings have no `captures` property.
-   **`d` flag**: positions require the ES2022 `d` (hasIndices) flag, which is applied internally
    from the option and never appears in rule text — a user-written `d` in `/…/d` is ignored, since
    rule flags are limited to `s` and `i`. If a runtime lacks it, `value` is still reported and
    `offset`/`length` are `null`.
-   **Cost**: roughly 1.25x on a scan dominated by many regex matches; verification of individual
    candidates is unaffected.

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
