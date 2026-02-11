# Supported Modules

The engine includes several built-in modules to extend detection capabilities. While compatible with standard YARA module syntax, some implementations may differ slightly due to the JavaScript environment.

## PE Module (`pe`)

Validates and parses Windows Portable Executable files.

**Supported Features:**
- **Headers**: Parsing of characteristics, entry point, machine type, timestamp.
- **Sections**: Name, raw size/data, virtual size/address, characteristics, entropy, MD5/SHA1/SHA256 hashes.
- **Imports/Exports**: Listing imported DLLs and functions, and exported functions.
- **Signatures**: Basic detection of digital signatures (`pe.digital_signature.has_signature`).
- **Rich Header**: Parsing of Rich Header entries (`pe.rich_signature` - presence detection).
- **Imphash**: Calculation of import hash (`pe.imphash()`).

**Unsupported / Key Differences:**
- **Resources**: `pe.resources` (icons, version strings, manifests) is not currently implemented in the engine, though the underlying library supports it.
- **Version Info**: `pe.version_info` keys (CompanyName, FileDescription, etc.) are not currently implemented, though the underlying library supports parsing these resources.
- **Detailed Signatures**: Certificate chains, issuers, and serial numbers (`pe.signatures[...]`) are not parsed. The engine detects signature presence, but full PKCS#7 parsing requires external crypto libraries not currently integrated.
- **PDB/Debug**: Debug directory information (`pe.pdb_path`) is not currently implemented.
- **Rich Header Details**: Individual tool IDs and versions within the Rich Header are not parsed; only presence/offset is detected.
- **Overlay**: `pe.overlay` access is not supported.

## ELF Module (`elf`)

Validates and parses ELF binaries (Linux/Unix).

**Supported Features:**
- **Headers**: Entry point, machine, type.
- **Sections**: Standard section parsing.
- **Segments**: Program header analysis.
- **Symbols**: Symbol table parsing.

## Math Module (`math`)

Provides mathematical and statistical functions.

**Functions:**
- `math.entropy(offset, size)`
- `math.entropy(string)`
- `math.monte_carlo_pi(offset, size)`
- `math.serial_correlation(offset, size)`
- `math.mean(offset, size)`
- `math.deviation(offset, size)`
- `math.min(offset, size)`
- `math.max(offset, size)`
- `math.mode(offset, size)`
- `math.abs(value)`
- `math.count(byte, offset, size)`
- `math.percentage(byte, offset, size)`
- `math.to_number(bool)`
- `math.in_range(value, lower, upper)`

## Hash Module (`hash`)

Provides cryptographic hashing.

**Functions:**
- `hash.md5(offset, size)` / `hash.md5(string)`
- `hash.sha1(offset, size)` / `hash.sha1(string)`
- `hash.sha256(offset, size)` / `hash.sha256(string)`
- `hash.crc32(offset, size)` / `hash.crc32(string)`

## Other Modules

- **String**: `string.to_int`, `string.length`.
- **Time**: `time.now()`.

## Unsupported Modules
The following standard YARA modules are **NOT** currently supported:
- `cuckoo` (Sandbox integration)
- `magic` (File type detection via libmagic)
- `console` (Logging during scanning)
- `dotnet` (.NET specific parsing)

---
**Last Updated:** 2026-02-11
