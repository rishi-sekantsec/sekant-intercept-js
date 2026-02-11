# YARA Grammar Support

This document outlines the YARA rule grammar supported by the JS-based engine.

## Rule Structure

The engine supports the standard YARA rule structure:

```yara
rule RuleName : tag1 tag2 {
    meta:
        author = "Name"
        description = "Description"
        // ... other metadata
    strings:
        $a = "string"
        $b = { 00 11 22 33 }
    condition:
        $a or $b
}
```

- **Global Rules**: `global rule ...` is supported.
- **Private Rules**: `private rule ...` is supported.
- **Tags**: Supported.
- **Metadata**: Supported.

## Strings

The engine supports the following string types and modifiers:

### Text Strings (`"..."`)
- **ASCII**: Default.
- **Wide**: `wide` modifier supported (UTF-16LE).
- **No Case**: `nocase` modifier supported.
- **XOR**: `xor` modifier supported (0-255).
- **Base64**: `base64` and `base64wide` modifiers supported.
- **Fullword**: `fullword` modifier supported.
- **Private**: `private` modifier supported (suppresses output).

### Hex Strings (`{ ... }`)
- Supports standard hex sequences and wildcards (`?`, `??`).
- **Jumps**: Variable length jumps `[min-max]` are supported (mapped to regex internally).
- **Unbounded Jumps**: `[-]` or `[N-]` are supported but capped at **10,000 bytes** (`MAX_HEX_JUMP`) to prevent performance issues.
- **NOT Operator**: Supported for single bytes (`~00`) and nibbles (`~?0`), including multiple NOTs (`~00 ~FF`).
    - **Note**: `NOT` combined with complex alternatives (e.g., `~(AA|BB)`) is **partially supported** and may require rewriting rules (e.g., to `~AA ~BB`).

### Regular Expressions (`/.../`)
The engine uses JavaScript's native `RegExp` engine.
- **Modifiers**: `nocase` (`i` flag), `dotall` (`s` flag).
- **Note**: This is a key difference from `libyara`, which uses its own regex engine (RE2/PCRE-like). JS RegExp supports most standard features but may behave differently with complex lookaheads/lookbehinds or specific escape sequences.
- **Unsupported**: Possessive quantifiers (`*+`, `++`) and atomic groups `(?>...)` are not supported in JS regex.

## Conditions

The condition evaluator supports a wide range of YARA operators:

### Logic & Comparison
- Boolean: `and`, `or`, `not`
- Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Identifiers: `$a`, `#a` (count), `@a` (first offset) are supported.
- String Sets: `them` keyword supported.

### Quantifiers
- `any of them`
- `all of them`
- `none of them`
- `N of them` (exact count)
- `N% of them` (percentage)
- `any/all/none of ($a, $b*)` (sets of strings)

### Iteration (Loops)
- `for any/all of them : ( ... )`
- `for any/all i in (min..max) : ( ... )`

### Arithmetic & Bitwise
- Math: `+`, `-`, `*`, `\`, `%`
- Bitwise: `&`, `|`, `^`, `~`, `<<`, `>>`
- Precedence follows standard YARA rules.

### Position & Count
- `entrypoint`: Entry point offset (PE/ELF).
- `#a`: Count of matches for string `$a`.
- `@a`: Offset of the *first* match of `$a`.
- `@a[i]`: Offset of the *i-th* match.
- `!a`: Length of the *first* match.
- `!a[i]`: Length of the *i-th* match.

### Position Constraints
- `$a at <offset>`: Match at exact offset.
- `$a in (<start>..<end>)`: Match within range.

### Filesize Operations
- `filesize`: The size of the scanned file in bytes.
- **Unit Support**: `KB` (1024), `MB` (1024^2), `GB` (1024^3).
  ```yara
  filesize > 200KB
  filesize < 10MB
  ```

### Memory Access
- `int8(<offset>)`, `int16(...)`, `int32(...)`
- `uint8(...)`, `uint16(...)`, `uint32(...)`
- `int8be(...)` (Big Endian variants), etc.


## Unsupported / Limitations

While the engine supports the majority of YARA's feature set, there are specific limitations inherent to this implementation compared to `libyara`.

### 1. Grammar & Syntax
- **Include Directive**: The `include` directive is **not supported**. Use `import` for modules only.
- **External Variables**: Passing external variables (e.g., `-d var=value` CLI arguments) is **not supported**. All identifiers must resolve to internal modules, loop variables, or predefined fields (`filesize`, `entrypoint`).
- **Rule Identifiers**: Rule names referenced in conditions (e.g., `RuleA` inside `RuleB`) are supported but must typically be defined in the same file or batch. There is no global symbol table across separate compiler instances.
- **Anonymous Strings**: Declaring anonymous strings (variable `$ = ...`) is **not supported**.

### 2. Iterators
- **Strict Integer Sets**: Iterating over explicit integer sets is **not supported**.
  - **Unsupported**: `for any i in (1, 2, 5, 8) : ...`
  - **Supported**: `for any i in (1..10) : ...` (Ranges are supported).
- **Array Iteration**: Iterating over module arrays (like `pe.sections`) is **not supported**.
  - **Unsupported**: `for any section in pe.sections : ...`
  - **Workaround**: Use ranges with indexed access: `for any i in (0..pe.number_of_sections) : ( pe.sections[i].name == ... )`

### 3. Operator Precedence (CRITICAL)
There is a known divergence in operator precedence between this engine and standard YARA (C-like precedence) involving Bitwise operators and Comparisons.

- **Standard YARA**: Comparisons (`==`, `!=`) bind **tighter** than Bitwise OR/AND (`|`, `&`).
  - `$a | $b == 0` is interpreted as `$a | ($b == 0)`.
- **SEKANT Engine**: Comparisons bind **looser** than Bitwise operators.
  - `$a | $b == 0` is interpreted as `($a | $b) == 0`.

**Recommendation**: Always use parentheses when mixing Bitwise and Comparison operators to ensure consistent behavior across engines.

### 4. File Size & Units
- **Multipliers**: `KB`, `MB`, `GB` suffixes are **supported** (e.g., `filesize > 200KB`).
- **Mixed Case**: Units are case-insensitive (`kb`, `KB`, `kB`).

### 5. String Modifiers
- The following modifiers are parsed but may have limited implementation specifics:
  - `xor`: Supported (range defaults to 0-255).
  - `base64`: Supported.
  - `base64wide`: Supported.

### 6. Modules
Only the standard modules listed in [MODULES_SUPPORT.md](MODULES_SUPPORT.md) are available. Custom modules or C-based plugins are not supported.

---
**Last Updated:** 2026-02-11