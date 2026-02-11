# ELF Module

The `elf` module parses Executable and Linkable Format (ELF) files. It provides access to headers, sections, segments, and dynamic linking information.

## Core Properties

| Field | Type | Description |
|-------|------|-------------|
| `type` | integer | File type (e.g., `elf.ET_EXEC`, `elf.ET_DYN`) |
| `machine` | integer | Machine type (e.g., `elf.EM_X86_64`) |
| `entry_point` | integer | Virtual address of the entry point |
| `is_64bit` | boolean | True for 64-bit binaries |
| `endianness` | string | Byte order: `"little"` or `"big"` |
| `number_of_sections` | integer | Count of sections |
| `number_of_segments` | integer | Count of program headers |
| `file_size` | integer | Size of the ELF file in bytes |
| `soname` | string | Shared object name (for libraries) |

## Helper Methods

### `elf.imports_library(library_name)`
Checks if the binary depends on a specific library (DT_NEEDED).
- **Parameters**: `library_name` (String)
- **Returns**: Boolean
- **Example**: `elf.imports_library("libc")`

### `elf.exports_function(function_name)`
Checks if a function is exported.
- **Parameters**: `function_name` (String)
- **Returns**: Boolean
- **Example**: `elf.exports_function("main")`

### `elf.get_section_by_name(name)`
Retrieves a section object by its name.
- **Parameters**: `name` (String)
- **Returns**: Section object (or null)
- **Example**: `elf.get_section_by_name(".text")`

## Data Structures

### Sections
Access via `elf.sections` array (0-indexed).
| Property | Description |
|----------|-------------|
| `name` | Section name (e.g., `.text`) |
| `address` | Virtual address |
| `size` | Size in bytes |
| `offset` | File offset |
| `type` | Section type (SHT_*) |
| `flags` | Section flags (SHF_*) |
| `entropy` | Calculated entropy (0.0 - 8.0) |
| `md5`/`sha1`/`sha256`| Pre-calculated hashes of content |

### Segments (Program Headers)
Access via `elf.program_headers` or `elf.segments`.
| Property | Description |
|----------|-------------|
| `type` | Segment type (e.g., PT_LOAD) |
| `offset` | File offset |
| `vaddr` | Virtual address |
| `paddr` | Physical address |
| `filesz` | File size |
| `memsz` | Memory size |
| `flags` | Segment flags (R/W/X) |
| `align` | Alignment |

### Dynamic Linking
- `elf.needed_libraries`: Array of strings (e.g., `["libc.so.6", "libdl.so.2"]`)
- `elf.imports`: Array of strings (Imported function names)
- `elf.exports`: Array of strings (Exported function names)

## Constants

### Architecture (`elf.ARCH_*` / `elf.EM_*`)
- `elf.EM_386` / `elf.ARCH_X86`: 3
- `elf.EM_X86_64` / `elf.ARCH_X86_64`: 62
- `elf.EM_ARM` / `elf.ARCH_ARM`: 40
- `elf.EM_AARCH64` / `elf.ARCH_AARCH64`: 183

### File Types (`elf.TYPE_*` / `elf.ET_*`)
- `elf.ET_EXEC` / `elf.TYPE_EXEC`: 2 (Executable)
- `elf.ET_DYN` / `elf.TYPE_DYN`: 3 (Shared Object)
- `elf.ET_CORE` / `elf.TYPE_CORE`: 4 (Core Dump)

## Known Limitations & Differences

### 1. Functionality Gaps
- **Dynamic Symbols**: Full parsing of the dynamic symbol table is not yet implemented. Only exported functions found in `.dynsym` are exposed via `elf.exports`.
- **Relocations**: Relocation tables and entries are not currently extracted or exposed.
- **Notes**: Parsing of special note sections (e.g., `.note.ABI-tag`) is not supported.

### 2. Implementation Differences
- **Pre-calculated Hashes**: Like the PE module, ELF section hashes are computed eagerly during file parsing, not lazily.
- **Missing Operators**: Core engine limitations (missing `at`, `filesize`, string count) apply here as well.

---
**Last Updated:** 2026-02-11

