# File Variations for YARA Testing

## Generated Files (21 variations)

### Archives - Basic (7 files)
- **basic_archive.zip** - Standard ZIP archive (PK\x03\x04 signature)
- **empty_archive.zip** - Empty ZIP archive (PK\x05\x06 signature)
- **rar5_archive.rar** - RAR v5.0 archive (Rar!\x1a\x07\x01\x00 signature)
- **7zip_archive.7z** - 7-Zip archive (7z\xbc\xaf\x27\x1c signature)
- **tar_archive.tar** - TAR archive (ustar signature at offset 257)
- **tar_gz_archive.tar.gz** - TAR + GZIP compressed
- **tar_bz2_archive.tar.bz2** - TAR + BZIP2 compressed
- **tar_xz_archive.tar.xz** - TAR + XZ compressed

### Compression - Single Files (4 files)
- **gzip_file.pdf.gz** - GZIP compressed PDF (\x1f\x8b\x08 signature)
- **bzip2_file.txt.bz2** - BZIP2 compressed text (BZh signature)
- **xz_file.html.xz** - XZ compressed HTML (\xfd7zXZ\x00 signature)

### Encrypted Archives (4 files)
- **encrypted_zip.zip** - ZIP with password encryption (encryption bit flag 0x09 at offset 6)
  - Password: `testpass123`
  - Signature: PK\x03\x04 with encryption flag set
- **encrypted_rar5.rar** - RAR v5 with password encryption
  - Password: `testpass123`
  - Signature: Rar!\x1a\x07\x01\x00 with encryption flag
- **encrypted_7z.7z** - 7-Zip with password encryption
  - Password: `testpass123`
- **encrypted_pdf.pdf** - PDF with 256-bit AES encryption
  - User password: `userpass`
  - Owner password: `ownerpass`
  - Contains /Encrypt keyword at offset ~256

### Databases (2 files)
- **test_database.sqlite** - SQLite 3.x database ("SQLite format 3\x00" signature)
- **test_database.db** - SQLite 3.x database with .db extension

### Disk Images (2 files)
- **test_disk.dmg** - Apple DMG disk image (zlib compressed, \x78\x01... signature)
- **test_disk.iso** - ISO 9660 filesystem (CD001 at offset 0x8001)

### Packages/Archives (1 file)
- **test_archive.xar** - XAR archive (xar! signature, used in macOS PKG files)

### Executables (1 file)
- **macho_executable** - Mach-O 64-bit ARM64 executable (\xfe\xed\xfa\xcf signature)
  - Native macOS executable compiled with GCC/Clang
  - Simple "Hello World" program

## Verification Commands

### Check file types:
```bash
file *
```

### View magic bytes:
```bash
xxd -l 16 filename
```

### Test ZIP encryption flag:
```bash
xxd -l 10 encrypted_zip.zip
# Look for byte 0x09 at offset 6 (encryption flag)
```

### Test RAR5 encryption:
```bash
xxd -l 16 encrypted_rar5.rar
# RAR v5 signature with encryption flag set
```

### Test PDF encryption:
```bash
strings encrypted_pdf.pdf | grep -i encrypt
# Should show /Encrypt dictionary
```

## Coverage Summary

### ✅ Fully Covered
- ZIP archives (basic, empty, encrypted)
- RAR v5 (basic, encrypted)
- 7-Zip (basic, encrypted)
- TAR archives
- GZIP compression
- BZIP2 compression
- XZ compression
- PDF (encrypted variant)
- SQLite databases
- DMG disk images
- ISO disk images
- XAR archives
- Mach-O executables (64-bit ARM)

## Notes

- All encrypted files use password: `testpass123` (except PDF which uses `userpass`/`ownerpass`)
- Generated files are minimal size for testing purposes
- File signatures are verified to match YARA detection patterns
- macOS-specific executables (Mach-O) are ARM64 architecture on Apple Silicon
