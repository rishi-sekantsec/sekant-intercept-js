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
-   **Max String Match Length**: 2048 bytes (`MAX_STRING_MATCH_LENGTH`). Matches exceeding this length are truncated.
-   **Max Matches Per String**: 100 (`MAX_MATCHES`).

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

## Key Assumptions

1.  **Prefix Extraction**: The performance of the scanner relies heavily on the ability to extract long, unique prefixes from Regex or Hex strings. Patterns like `/.*bad/` will suffer performance penalties.
2.  **JS RegExp**: The engine assumes the environment supports standard JS RegExp. Features specific to PCRE/RE2 that are not in JS (e.g., atomic groups) are not supported.

## Error Handling

-   **Invalid Patterns**: Compilation throws errors for malformed hex or regex strings.
-   **Runtime Errors**: Matchers are wrapped to catch runtime issues (e.g., massive backtracking) though JS RegExp constraints typically prevent infinite loops, catastrophic backtracking is a risk with poorly written user rules.

---
**Last Updated:** 2026-02-11
