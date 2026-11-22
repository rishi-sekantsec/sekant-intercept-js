# String Matching Engine

## Architecture

The string matching engine is responsible for compiling YARA string definitions (Text, Hex, Regex) into executable matchers and executing them against binary data. It works closely with the `AhoCorasickEngine` to optimize the search process.

### Components

1.  **Pattern Compilation (`yaraStringMatch.mjs`)**: Converts string definitions into matcher functions.
2.  **Fast Search (`ahocorasickEngine.mjs`)**: Builds an Aho-Corasick automaton for multi-pattern search.
3.  **Verification**: Confirms potential matches found by Aho-Corasick or performs linear scans for unoptimized patterns.

## Matcher Object Structure

When the rule compiler processes strings, it generates a "Matcher Object" for each variable. This object encapsulates the logic finding that specific pattern in the data.

### Limits & Defaults
-   **Verification Scan Window**: 4096 bytes (`MAX_RE_SCAN_LIMIT`, mirroring libyara's `YR_RE_SCAN_LIMIT`). Bounds how far Aho-Corasick candidate verification can see for text strings and literal-prefixed regexes; a match extending past the window is not detected. Hex strings and regexes without a literal prefix are scanned over the full buffer. Reported match `length` values are never truncated.
-   **Max Matches Per String**: 100 (`MAX_MATCHES`), configurable via the scanner's `maxMatches` option/property. Enforced for hex strings and regexes without a literal prefix; literal text matches are uncapped.

### Common Structure
All matcher objects share this interface:

```javascript
{
  // The executable search function
  // @param data {Uint8Array} - The binary data to scan
  // @param offset {number} - (Optional) If provided, verify match ONLY at this offset
  // @returns {Array} - List of match objects { offset, length, ... }
  matcher: function(data, offset),

  type: "text" | "hex" | "regex",
  private: boolean // If true, matches are not included in final output
}
```

### Type-Specific Properties

**Text Matcher**:
```javascript
{
  type: "text",
  patterns: [
    // Pre-computed byte sequences for all variants (wide, ascii, base64 permutations)
    { bytes: Uint8Array, isWide: boolean }
  ],
  nocase: boolean, // If true, matching ignores case
  xor: [min, max] | null // Key range if XOR modifier is used
}
```

**Regex Matcher**:
```javascript
{
  type: "regex",
  literalPrefix: string, // Extracted prefix for Aho-Corasick optimization
  nocase: boolean
}
```

**Hex Matcher**:
```javascript
{
  type: "hex"
  // Note: Hex matchers handle wildcards and jumps internally via Regex
}
```

## Handling of String Types

### Text Strings
-   **Compilation**: Strings are converted to byte sequences.
-   **Modifiers**:
    -   `ascii`, `wide`: Generates corresponding byte patterns (single-byte vs double-byte with nulls).
    -   `nocase`: Generates case-insensitive variants or configure the matcher to ignore case.
    -   `xor`: Generates multiple variants of the string XORed with keys 0-255.
    -   `base64`: Calculations valid range of base64 permutations.
-   **Optimization**: Text literals are the primary candidates for the Aho-Corasick automaton.

### Regular Expressions
-   **Engine**: Uses JavaScript's native `RegExp` engine.
-   **Optimization**: extract *literal prefixes* from the regex (e.g., `/http:\/\/server\.com\/[a-z]+/` -> `http://server.com/`) to use as Aho-Corasick candidates.
-   **Execution**:
    1.  Search for the literal prefix using AC.
    2.  If found, run the full JS `RegExp` on the surrounding data to verify the match.
    3.  If no prefix can be extracted, falls back to a linear scan (slower).

### Hex Strings
-   **Compilation**: Parsed into a sequence of bytes and wildcards.
-   **Wildcards**: Supported (e.g., `{ 11 ?? 33 }`).
-   **Jumps**: Variable jumps (`[2-4]`) are converted into internal regex representations for matching.
-   **Optimization**: Like regex, hex strings with fixed leading sequences use those sequences as AC candidates. Patterns starting with wildcards generally require slower scanning methods.

## Aho-Corasick Engine

The `ahocorasickEngine.mjs` implements the Aho-Corasick algorithm:
-   **Input**: A set of "keywords" (literals from text strings, prefixes from regex/hex).
-   **Output**: A state machine that scans data in O(n) time, reporting when any keyword is found.
-   **Purpose**: To drastically reduce the number of times expensive full-matchers (Regex/Hex) need to run.

## Intercept Filter Rules

Intercept adds `reject(...)` and `rejectRECapture(...)` string modifiers backed by `filter rule`
declarations. Neither is valid YARA; both are rejected by libyara.

```yara
filter rule starts_with_mal {
  strings:
    $m = "mal"
  condition:
    $m
}

rule Demo {
  strings:
    $a = "malware" reject(starts_with_mal)
    $b = /dl\/([a-z0-9]+)/ rejectRECapture(starts_with_mal)
  condition:
    any of them
}
```

- **Candidate-only input**: a filter rule is evaluated against the verified match bytes alone
  (`data[offset .. offset + length]`). It cannot see the rest of the file, which bounds its cost
  and makes it independent of file size.
- **Capture input**: `rejectRECapture(...)` hands the filter capture group 1 instead of the full
  match. If the pattern has no group, or group 1 is empty or did not participate, the full match is
  used. Text and hex strings therefore always pass the full match. Only group 1 is considered.
- **Buffer access**: an undeclared `$_` in a condition is the whole buffer as decoded text — the
  candidate for `reject(...)`, the capture for `rejectRECapture(...)`, and the file in normal rules.
  It can be passed straight to module functions (`string.length($_)`, `hash.md5($_)`). Declaring a
  string named `$_` restores ordinary string semantics. While undeclared, `#_` is `0` and `@_` /
  `!_` are undefined, so comparisons against them are undefined and the filter fails open.
- **Verdict**: `reject(a, b)` and `rejectRECapture(a, b)` are each an OR. If any filter returns
  `true`, the candidate is discarded before string facts are built, so `#a`, `@a`, and `$a at N`
  reflect surviving matches only.
- **Size cap**: matches longer than `MAX_FILTER_RULE_BUFFER_SIZE` (4096) keep the match and skip
  filtering; a diagnostic is reported. The cap applies to the match length, so a capture is always
  within it.
- **Fail-open**: a filter that throws is treated as not rejecting.
- **Facts**: `filesize` is the candidate length, offsets are buffer-relative, `entrypoint` is `0`.
- **Modules**: `string`, `time`, `math`, `hash`, and custom modules are available. `pe`/`elf` are
  compile errors for filter rules. Custom modules receive the candidate buffer and the scan
  metadata; they are initialized lazily, only for filters that reference them.
- **Registry**: filter rules live in `InterceptScanner.compiledFilterRules` and never participate
  in normal matching, results, or Aho-Corasick.
- **Diagnostics**: `scan()` and `scanFilterRules()` return arrays of matches with a non-enumerable
  `diagnostics` property (duplicate definitions, unknown filter names/modules, oversized
  candidates, filter errors, rejection counts).
- **API**: `scanFilterRules(data, metadata, ruleNames)` evaluates filter rules directly and
  returns the same result shape as `scan()`.

## Key Assumptions

1.  **Prefix Extraction**: The performance of the scanner relies heavily on the ability to extract long, unique prefixes from Regex or Hex strings. Patterns like `/.*bad/` will suffer performance penalties.
2.  **JS RegExp**: The engine assumes the environment supports standard JS RegExp. Features specific to PCRE/RE2 that are not in JS (e.g., atomic groups) are not supported.

## Error Handling

-   **Invalid Patterns**: Compilation throws errors for malformed hex or regex strings.
-   **Runtime Errors**: Matchers are wrapped to catch runtime issues (e.g., massive backtracking) though JS RegExp constraints typically prevent infinite loops, catastrophic backtracking is a risk with poorly written user rules.

---
**Last Updated:** 2026-02-11
