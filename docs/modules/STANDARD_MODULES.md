# Standard Modules

## 1. Math Module
Provides mathematical and statistical functions for analyzing binary data and strings.

### Statistical Functions

#### `math.entropy(offset, size)` / `math.entropy(string)`
Calculates the Shannon entropy of a data region or string.
- **Parameters**: 
  - `offset`: Starting byte offset (0-based integer)
  - `size`: Number of bytes to analyze
  - `string`: String content to analyze
- **Returns**: Float between 0.0 and 8.0 (bits per byte)
- **Interpretation**:
  - `0.0 - 2.0`: Highly structured/repetitive data
  - `6.0 - 7.5`: Randomized data
  - `7.5 - 8.0`: High entropy (likely encrypted or compressed)
- **Example**: `math.entropy("password")` might return `~3.0`

#### `math.monte_carlo_pi(offset, size)`
Estimates Pi using Monte Carlo simulation on the data region.
- **Returns**: Float (target ~3.14159)
- **Interpretation**: Values close to Pi indicate "good" randomness.
- **Example**: `math.monte_carlo_pi(0, 10000)` → `3.141...`

#### `math.serial_correlation(offset, size)`
Calculates serial correlation between consecutive bytes.
- **Returns**: Float between -1.0 and 1.0
- **Interpretation**: 
  - `~0.0`: No correlation (random)
  - `0.5 - 1.0`: Consecutive bytes are similar
  - `-1.0 - -0.5`: Consecutive bytes alternate
  
#### `math.mean(offset, size)`
Calculates the arithmetic mean of byte values.
- **Returns**: Float (0.0 - 255.0)

#### `math.deviation(offset, size)`
Calculates the standard deviation of byte values.
- **Returns**: Float representing the spread/variability.

### Byte Analysis (0-255)

#### `math.min(offset, size)` / `math.max(offset, size)`
Finds the minimum or maximum byte value in the region.
- **Returns**: Integer (0-255)

#### `math.mode(offset, size)`
Finds the most frequently occurring byte value.
- **Returns**: Integer (0-255)

#### `math.count(byte, offset, size)`
Counts occurrences of a specific byte.
- **Parameters**: `byte` (0-255)
- **Returns**: Integer count

#### `math.percentage(byte, offset, size)`
Calculates the frequency of a byte as a fraction.
- **Returns**: Float (0.0 to 1.0)
- **Example**: `math.percentage(0x00, 0, 1024)` → `0.5` (if 50% are null bytes)

### Helper Functions

#### `math.in_range(value, lower, upper)`
Checks if a value falls within a closed interval `[lower, upper]`.
- **Returns**: Boolean`
- **Example**: `math.in_range(5, 0, 10)` → `true`

#### `math.to_number(boolean)`
Converts a boolean to an integer.
- **Returns**: `1` for true, `0` for false

---

## 2. Hash Module
Provides cryptographic hash functions. Supports both string hashing and data region hashing.

### Algorithms
- **MD5**: 32-character hex string
- **SHA1**: 40-character hex string
- **SHA256**: 64-character hex string
- **CRC32**: 8-character hex string
- **Checksum32**: 8-character hex string (Simple sum)

### API Reference

#### Data Region Hashing
`hash.algorithm(offset, size)`
- **Parameters**:
  - `offset`: Starting byte offset (0-based)
  - `size`: Number of bytes to hash
- **Validation**: Throws error if `offset + size > filesize`.
- **Example**: 
  - `hash.md5(0, 512)` → Hash of the first 512 bytes.

#### String Hashing
`hash.algorithm(string)`
- **Parameters**:
  - `string`: Input text
- **Example**:
  - `hash.md5('hello')` → `"5d41402abc4b2a76b9719d911017c592"`
  - `hash.checksum32('hello')` → `"00000214"`

---

## 3. String Module
Provides string parsing and manipulation utilities.

#### `string.to_int(string, [base])`
Converts a string representation of a number to an integer.
- **Parameters**:
  - `string`: Text to parse (e.g., "123", "0x1A").
  - `base` (Optional): Radix (2-36). Default is 10.
- **Implicit Behavior**:
  - **Auto-detection**: If no base provided, detects `0x`/`0X` (hex) and `0o`/`0O` (octal).
  - **Error Handling**: Returns `0` for invalid inputs, non-strings, or failed definitions (NaN).
- **Examples**:
  - `string.to_int("42")` → `42`
  - `string.to_int("0x1234")` → `4660`
  - `string.to_int("1010", 2)` → `10`
  - `string.to_int("invalid")` → `0`

#### `string.length(string)`
Returns the length of a string.
- **Returns**: Integer length (or `0` if input is not a string).
- **Examples**:
  - `string.length("Hello")` → `5`
  - `string.length("")` → `0`

---

## 4. Time Module
Provides access to current execution time.

#### `time.now()`
Returns the current Unix timestamp in milliseconds.
- **Returns**: Integer (Milliseconds since Epoch)
- **Example**: `1762487540157`
- **Usage**: Useful for creating time-bound rules (e.g., only match if scanning occurred after a certain date).

---

## Known Limitations & Differences

### Hash Module
- **Async Execution**: In this JS engine, cryptographic functions (MD5, SHA1, SHA256) are transparently asynchronous to support WebCrypto APIs. While hidden from the YARA rule syntax, this may impact integration if the engine is embedded in synchronous contexts.
- **Empty Inputs**: Hashing an empty string or zero-size region returns the standard hash for empty input.

### Math Module
- **Precision**: Calculations use JavaScript `Number` (IEEE 754 double-precision), which generally matches C-based YARA but may show minute differences in floating-point edge cases.

### String Module
- **Encoding**: Strings are treated as UTF-16 (standard JS strings). Use the `ascii` or `wide` modifiers in YARA rules to explicitly handle encoding expectations.

---
**Last Updated:** 2026-02-11

