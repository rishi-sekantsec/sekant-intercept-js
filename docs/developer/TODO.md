# Improvement TODO List

This document tracks planned improvements and feature gaps to address in the Intercept.js engine.

## PE Module Enhancements (pe-library integration)

The underlying `pe-library` supports these features, but they need to be mapped in `peModule.mjs`.

- [ ] **Resources Parsing** (Added: 2026-02-11)
    - Implement `pe.resources` array.
    - Expose resource types, IDs, languages, and lengths.
- [ ] **Version Information** (Added: 2026-02-11)
    - Parse VS_VERSION_INFO from resources.
    - Implement `pe.version_info` dictionary (CompanyName, FileDescription, ProductVersion, etc.).
    - Implement helper functions like `pe.file_version` and `pe.product_version`.
- [ ] **Debug Directory** (Added: 2026-02-11)
    - Implement `pe.pdb_path` (requires `pe-library` support for Debug Directory, need to verify if exposed).
    - Expose debug timestamp and type.

## Engine Features

- [ ] **Rich Header Parsing** (Added: 2026-02-11)
    - Expand `pe.rich_signature` to include the tool list (`toolid`, `version`, `times`) rather than just offset/presence.
    - Note: This requires manual parsing of the Rich Header block as `pe-library` might not parse the internal structure fully yet.
- [ ] **Detailed Signatures** (Added: 2026-02-11)
    - Investigate integrating `pkijs` or a similar lightweight crypto library to parse `pe.signatures` (certificates, issuers) beyond just specific presence.
- [ ] **Stream Scanning Support** (Added: 2026-02-11)
    - Implement support for streaming input (e.g., node streams or web streams) to scan very large files without loading the entire file into memory.
    - Requires logic to maintain sliding windows or buffers for cross-chunk pattern matching.
    - **Goal:** Enable scanning of multi-gigabyte files within a fixed memory footprint while building the full `ScanFacts` object.
- [ ] **Bitwise Precedence Fix** (Added: 2026-02-12)
    - Align operator precedence with standard YARA (comparison looser than bitwise).
    - Current workaround is requiring parentheses.

## Documentation

- [ ] **Developer Guide** (Added: 2026-02-11)
    - Create documentation for contributors on how to add new modules or update existing ones.

---
**Last Updated:** 2026-02-12
