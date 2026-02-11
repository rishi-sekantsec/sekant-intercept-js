# Engine Differences & Architecture

This engine is a pure JavaScript implementation of YARA, designed for portability and safety in JS environments (Node.js and Browser). While it aims for high compatibility, there are key architectural differences compared to the reference C-based `libyara`.

## 1. Import Statements are Optional
In standard YARA, `import "pe"` is strictly required to use the PE module. In this engine, standard modules (`pe`, `elf`, `math`, `hash`, `time`) are **automatically loaded** and available.
- **Compatibility**: You can still use `import` statements; the compiler validates them but they are not strictly necessary for the module to function.

## 2. Match Limits & Optimization
To prevent excessive memory usage during scanning (especially in browser environments), this engine enforces limits on capture results.
- **Max Matches**: The engine limits the number of individual string matches recorded per rule to **100** (`MAX_MATCHES`), whereas `libyara` typically records all matches until a much higher system limit.
- **Match Length Limit**: Individual string matches are capped at **2048 bytes** (`MAX_STRING_MATCH_LENGTH`). Matches longer than this are truncated in the `ScanFacts` result, though the condition logic remains valid.
- **Large Arrays**: Output objects containing massive byte arrays may be truncated or summarized to prevent JSON serialization failures or memory exhaustion.
- **Unbounded Jumps**: Unbounded jumps in hex strings (e.g., `[-]`) are limited to **10,000** bytes (`MAX_HEX_JUMP`) to prevent excessive searching, unlike standard YARA which may search much further.
- **File Size**: The engine scans the **full content** of the buffer provided to `scan()`.
- **Filesize Keyword Cap**: The `filesize` keyword has an "optimistic" behavior when the `maxFileSize` limit is reached. If a file is larger than `maxFileSize` (default 1MB), comparisons like `filesize > 2MB` will evaluate to `true` (assuming the file *could* be that large). This supports streaming scenarios where the full size is unknown.
- **Batched Matching**: String matching uses Aho-Corasick for literals, followed by RegExp verification.

## 3. Regular Expression Engine & Compatibility
This engine uses JavaScript's native `RegExp` for regular expression matching.
- **Standard**: `libyara` uses its own engine (mostly PCRE compatible but with specific limitations).
- **Difference**: Some complex regex features specific to PCRE or Perl might not behave identically in JS RegExp. However, standard YARA regex usage (hex, ranges, groups) works as expected.
- **Possessive Quantifiers**: Features like `*+`, `++`, and atomic groups `(?>...)` are not supported.
- **Unicode**: JS RegExp handles Unicode differently (UTF-16) compared to YARA's UTF-8, which may affect usage of the `/u` flag.

## 4. String Modifiers
- **Base64 Limitations**: The implementation relies on standard JS functions which may have trouble with non-ASCII binary data in base64 strings (`btoa` limitations). It is recommended to stick to ASCII-safe data for base64 matching.
- **Private Strings**: The `private` modifier is fully supported and will hide the string from the output.

## 5. Performance Strategy
- **Memory Usage (Hex)**: For hex string matching, the engine converts the input buffer to a hex string. While cached, this doubles the memory requirement for the file data during scanning of hex rules (e.g., 1MB file -> 2MB hex string).
- **Aho-Corasick**: Like `libyara`, this engine uses Aho-Corasick for fast multi-pattern scanning of text literals.
- **Async Architecture**: The scanner and module system are fundamentally `async`.
  - While standard YARA functions are synchronous, this engine uses `await` internally for module calls (e.g., `hash.md5`, `pe` parsing).
  - This enables support for non-blocking Web Crypto APIs and prevents freezing the main thread during heavy scans.
- **Speed**: Pure JS memory scanning is generally slower (~2-10x) than native C implementations, so performance-sensitive workflows should account for this.

---
**Last Updated:** 2026-02-11
