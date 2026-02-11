# PE Module

The `pe` module allows you to parse and analyze Portable Executable (PE) files. It exposes most of the fields available in the standard YARA PE module.

## Core Properties

| Field | Type | Description |
|-------|------|-------------|
| `machine` | integer | Machine type (e.g., `pe.MACHINE_I386`, `pe.MACHINE_AMD64`) |
| `subsystem` | integer | Subsystem (e.g., `pe.SUBSYSTEM_WINDOWS_GUI`) |
| `entry_point` | integer | File offset of the entry point |
| `image_base` | integer | Image base address |
| `number_of_sections` | integer | Number of sections |
| `imphash` | string | Import hash (MD5) |
| `file_size` | integer | Size of the file in bytes |
| `is_32bit` | boolean | True for PE32 (0x010b) |
| `is_64bit` | boolean | True for PE32+ (0x020b) |
| `is_dll` | boolean | True if IMAGE_FILE_DLL flag is set |

### Optional Header Fields
- `size_of_code`
- `size_of_initialized_data`
- `size_of_uninitialized_data`
- `base_of_code`
- `base_of_data`
- `section_alignment`
- `file_alignment`
- `dll_characteristics`

## Helper Methods

### `pe.importsFunction(dll_name, [function_name])`
Checks for imported DLLs or functions.
- **Parameters**:
  - `dll_name` (String): Name of the DLL (case-insensitive)
  - `function_name` (String, optional): Name of the function (case-insensitive)
- **Returns**: Boolean
- **Examples**:
  ```yara
  pe.importsFunction("kernel32.dll", "CreateProcess")
  pe.importsFunction("kernel32.dll") // Checks if DLL is imported
  ```

### `pe.exports_function(function_name)`
Checks if a function is exported.
- **Parameters**: `function_name` (String)
- **Returns**: Boolean
- **Example**: `pe.exports_function("DllRegisterServer")`

## Data Structures

### Sections
Access sections via the `sections` array (0-indexed).

| Property | Description |
|----------|-------------|
| `name` | Section name (e.g., `.text`) |
| `virtual_address` | RVA of the section |
| `virtual_size` | Virtual size |
| `raw_data_offset` | File offset of raw data |
| `raw_data_size` | Size of raw data |
| `characteristics` | Section flags (see Constants) |
| `entropy` | Calculated entropy (0.0 - 8.0) |
| `md5` | MD5 hash of section content |
| `sha1` | SHA-1 hash of section content |
| `sha256` | SHA-256 hash of section content |

> **Note**: Unlike standard YARA, this engine **pre-calculates** section hashes during parsing. You can access `section.md5` directly without calling hash functions.

### Imports
`pe.imports` is an array of objects:
```json
[
  {
    "dll": "kernel32.dll",
    "functions": [
      { "name": "CreateProcess", "ordinal": null },
      { "name": null, "ordinal": 123 }
    ]
  }
]
```

### Digital Signature
- `pe.digital_signature.has_signature`: Boolean
- `pe.digital_signature.certificate_table`: `{ offset: number, size: number }`

### Rich Header
- `pe.rich_signature.offset`: Offset of the Rich Header (if present) or `null`.

## Constants

### Machine Types
- `pe.MACHINE_I386`: 0x014c (Intel 386)
- `pe.MACHINE_AMD64`: 0x8664 (x64)
- `pe.MACHINE_ARM`: 0x01c0 (ARM)
- `pe.MACHINE_ARM64`: 0xaa64 (ARM64)

### Subsystem Types
- `pe.SUBSYSTEM_NATIVE`: 1
- `pe.SUBSYSTEM_WINDOWS_GUI`: 2
- `pe.SUBSYSTEM_WINDOWS_CUI`: 3

### Section Characteristics
- `pe.SECTION_CNT_CODE`: 0x00000020
- `pe.SECTION_CNT_INITIALIZED_DATA`: 0x00000040
- `pe.SECTION_CNT_UNINITIALIZED_DATA`: 0x00000080
- `pe.SECTION_MEM_EXECUTE`: 0x20000000
- `pe.SECTION_MEM_READ`: 0x40000000
- `pe.SECTION_MEM_WRITE`: 0x80000000

## Known Limitations & Differences

### 1. Functionality Gaps
- **Section Iteration**: The `for any section in pe.sections` syntax is not yet supported. Use direct array indexing (e.g. `pe.sections[0]`) or standard JS logic if wrapping the engine.
- **Rich Header**: Parsing of tool IDs and versions (`pe.rich_signature.toolid(...)`) is **not supported**. Only presence and offset are available.
- **Authenticode**: Full certificate parsing (issuer, serials, timestamps) is **not supported**. Only `has_signature` and the certificate table location.

### 2. Missing Operators
- **`at` Operator**: Checking specific field locations (e.g., `$s at pe.entry_point`) is not yet implemented.
- **`filesize`**: The `filesize` keyword is not yet available in conditions.

### 3. Implementation Differences
- **Pre-calculation**: Section hashes (`md5`, `sha1`) are calculated eagerly during parsing, not on-demand. This simplifies rules but may impact performance on very large files.

---
**Last Updated:** 2026-02-11

