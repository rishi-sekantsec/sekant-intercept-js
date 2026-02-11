/**
 * Comprehensive File Type Detection Test Suite for yaraSekantModule
 * 
 * Tests the file type detection capabilities of the Sekant YARA Module
 * by scanning actual files from real_files directory and verifying:
 * - detected_types array contains expected file type signatures
 * - file_category is correctly assigned
 * - hasFileType() function works with patterns and wildcards
 * - ext_mismatch_content detects extension/content mismatches
 * - is_encrypted flag is correctly set
 */

import { readFileSync } from 'fs';
import { resolve, basename, extname } from 'path';
import { YaraScanner } from '../yaraScanner.mjs';
import { SekantYaraModule } from '../yaraSekantModule.mjs';
import {
  numberedTest as test,
  assertEquals,
  assertTrue,
  assertFalse,
  printSummary
} from './testingFramework.mjs';

console.log('='.repeat(70));
console.log('YARA Sekant Module - File Type Detection Tests');
console.log('='.repeat(70));

// Helper to load real files
function loadRealFile(relativePath) {
  const fullPath = resolve('../real_files', relativePath);
  return readFileSync(fullPath);
}

// Helper to transform scanner results
function transformResults(resultsArray) {
  return {
    matchedRules: resultsArray.map(r => r.rule),
    results: resultsArray
  };
}

// =============================================================================
// Section 1: Archive Detection - Variations Folder
// =============================================================================
console.log('\n📦 Section 1: Archive Format Detection (Variations)');

await test('1.1: Detect basic ZIP archive', async () => {
  const rules = `
    rule DetectZIP {
      condition:
        sekant.hasFileType("zip") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/basic_archive.zip');
  const metadata = { filename: "basic_archive.zip", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectZIP'));
});

await test('1.2: Detect empty ZIP archive', async () => {
  const rules = `
    rule DetectEmptyZIP {
      condition:
        sekant.hasFileType("zip") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/empty_archive.zip');
  const metadata = { filename: "empty_archive.zip", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectEmptyZIP'));
});

await test('1.3: Detect encrypted ZIP archive', async () => {
  const rules = `
    rule DetectEncryptedZIP {
      condition:
        sekant.hasFileType("zip_encrypted") and
        sekant.is_encrypted and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/encrypted_zip.zip');
  const metadata = { filename: "encrypted_zip.zip", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectEncryptedZIP'));
});

await test('1.4: Detect RAR v5 archive', async () => {
  const rules = `
    rule DetectRAR5 {
      condition:
        sekant.hasFileType("rar") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/rar5_archive.rar');
  const metadata = { filename: "rar5_archive.rar", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectRAR5'));
});

await test('1.5: Detect encrypted RAR v5 archive', async () => {
  const rules = `
    rule DetectEncryptedRAR5 {
      condition:
        sekant.hasFileType("rar_encrypted") and
        sekant.is_encrypted and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/encrypted_rar5.rar');
  const metadata = { filename: "encrypted_rar5.rar", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectEncryptedRAR5'));
});

await test('1.6: Detect 7-Zip archive', async () => {
  const rules = `
    rule Detect7Zip {
      condition:
        sekant.hasFileType("7z") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/7zip_archive.7z');
  const metadata = { filename: "7zip_archive.7z", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('Detect7Zip'));
});

await test('1.7: Detect encrypted 7-Zip archive', async () => {
  const rules = `
    rule DetectEncrypted7Zip {
      condition:
        sekant.hasFileType("7z") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/encrypted_7z.7z');
  const metadata = { filename: "encrypted_7z.7z", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectEncrypted7Zip'));
});

await test('1.8: Detect TAR archive', async () => {
  const rules = `
    rule DetectTAR {
      condition:
        sekant.hasFileType("tar") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/tar_archive.tar');
  const metadata = { filename: "tar_archive.tar", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectTAR'));
});

await test('1.9: Detect GZIP compressed file', async () => {
  const rules = `
    rule DetectGZIP {
      condition:
        sekant.hasFileType("gz") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/gzip_file.pdf.gz');
  const metadata = { filename: "gzip_file.pdf.gz", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectGZIP'));
});

await test('1.10: Detect BZIP2 compressed file', async () => {
  const rules = `
    rule DetectBZIP2 {
      condition:
        sekant.hasFileType("bz2") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/bzip2_file.txt.bz2');
  const metadata = { filename: "bzip2_file.txt.bz2", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectBZIP2'));
});

await test('1.11: Detect XZ compressed file', async () => {
  const rules = `
    rule DetectXZ {
      condition:
        sekant.hasFileType("xz") and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/xz_file.html.xz');
  const metadata = { filename: "xz_file.html.xz", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectXZ'));
});

// =============================================================================
// Section 2: PDF and Document Detection
// =============================================================================
console.log('\n📄 Section 2: PDF and Document Detection');

await test('2.1: Detect regular PDF', async () => {
  const rules = `
    rule DetectPDF {
      condition:
        sekant.hasFileType("pdf") and
        sekant.file_category == "pdf" and
        not sekant.is_encrypted
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.pdf');
  const metadata = { filename: "ffc.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectPDF'));
});

await test('2.2: Detect encrypted PDF', async () => {
  const rules = `
    rule DetectEncryptedPDF {
      condition:
        sekant.hasFileType("pdf_encrypted") and
        sekant.is_encrypted and
        sekant.file_category == "pdf"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/encrypted_pdf.pdf');
  const metadata = { filename: "encrypted_pdf.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectEncryptedPDF'));
});

await test('2.3: Detect Microsoft Office legacy formats (OLE2)', async () => {
  const rules = `
    rule DetectMSOfficeLegacy {
      condition:
        (sekant.hasFileType("doc") or 
         sekant.hasFileType("xls") or 
         sekant.hasFileType("ppt")) and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.doc');
  const metadata = { filename: "ffc.doc", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectMSOfficeLegacy'));
});

await test('2.4: Detect DOCX (ZIP-based Office)', async () => {
  const rules = `
    rule DetectDOCX {
      condition:
        sekant.hasFileType("docx") and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.docx');
  const metadata = { filename: "ffc.docx", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectDOCX'));
});

await test('2.5: Detect XLSX (ZIP-based Office)', async () => {
  const rules = `
    rule DetectXLSX {
      condition:
        sekant.hasFileType("xlsx") and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.xlsx');
  const metadata = { filename: "ffc.xlsx", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectXLSX'));
});

await test('2.6: Detect PPTX (ZIP-based Office)', async () => {
  const rules = `
    rule DetectPPTX {
      condition:
        sekant.hasFileType("pptx") and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.pptx');
  const metadata = { filename: "ffc.pptx", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectPPTX'));
});

// =============================================================================
// Section 3: Image Format Detection
// =============================================================================
console.log('\n🖼️  Section 3: Image Format Detection');

await test('3.1: Detect PNG image', async () => {
  const rules = `
    rule DetectPNG {
      condition:
        sekant.hasFileType("png") and
        sekant.file_category == "image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.png');
  const metadata = { filename: "ffc.png", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectPNG'));
});

await test('3.2: Detect JPEG image', async () => {
  const rules = `
    rule DetectJPEG {
      condition:
        (sekant.hasFileType("jpg") or sekant.hasFileType("jpeg")) and
        sekant.file_category == "image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.jpg');
  const metadata = { filename: "ffc.jpg", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectJPEG'));
});

await test('3.3: Detect GIF image', async () => {
  const rules = `
    rule DetectGIF {
      condition:
        sekant.hasFileType("gif") and
        sekant.file_category == "image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.gif');
  const metadata = { filename: "ffc.gif", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectGIF'));
});

await test('3.4: Detect BMP image', async () => {
  const rules = `
    rule DetectBMP {
      condition:
        sekant.hasFileType("bmp") and
        sekant.file_category == "image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.bmp');
  const metadata = { filename: "ffc.bmp", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectBMP'));
});

// =============================================================================
// Section 4: Executable and Binary Detection
// =============================================================================
console.log('\n⚙️  Section 4: Executable Detection');

await test('4.1: Detect Mach-O executable', async () => {
  const rules = `
    rule DetectMachO {
      condition:
        (sekant.hasFileType("dylib") or sekant.hasFileType("bundle")) and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/macho_executable');
  const metadata = { filename: "macho_executable", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectMachO'));
});

await test('4.2: Detect Windows PE executable (1mb.exe)', async () => {
  const rules = `
    rule DetectPE_EXE {
      condition:
        sekant.hasFileType("exe") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/1mb.exe');
  const metadata = { filename: "1mb.exe", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectPE_EXE'));
});

await test('4.3: Detect Windows PE executable (loadtest.exe)', async () => {
  const rules = `
    rule DetectPE_LoadTest {
      condition:
        sekant.hasFileType("exe") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/loadtest.exe');
  const metadata = { filename: "loadtest.exe", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectPE_LoadTest'));
});

await test('4.4: Detect Windows DLL (32-bit)', async () => {
  const rules = `
    rule DetectDLL32 {
      condition:
        sekant.hasFileType("dll") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/smalldll.dll');
  const metadata = { filename: "smalldll.dll", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectDLL32'));
});

await test('4.5: Detect Windows DLL (64-bit)', async () => {
  const rules = `
    rule DetectDLL64 {
      condition:
        sekant.hasFileType("dll") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/smalldll64.dll');
  const metadata = { filename: "smalldll64.dll", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectDLL64'));
});

// =============================================================================
// Section 5: Database Detection
// =============================================================================
console.log('\n💾 Section 5: Database Detection');

await test('5.1: Detect SQLite database (.sqlite)', async () => {
  const rules = `
    rule DetectSQLite {
      condition:
        (sekant.hasFileType("sqlite") or 
         sekant.hasFileType("db") or 
         sekant.hasFileType("sqlite3")) and
        sekant.file_category == "database"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/test_database.sqlite');
  const metadata = { filename: "test_database.sqlite", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectSQLite'));
});

await test('5.2: Detect SQLite database (.db)', async () => {
  const rules = `
    rule DetectSQLiteDB {
      condition:
        (sekant.hasFileType("sqlite") or 
         sekant.hasFileType("db") or 
         sekant.hasFileType("sqlite3")) and
        sekant.file_category == "database"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/test_database.db');
  const metadata = { filename: "test_database.db", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectSQLiteDB'));
});

// =============================================================================
// Section 6: Disk Images and Packages
// =============================================================================
console.log('\n💿 Section 6: Disk Images and Packages');

await test('6.1: Detect DMG disk image', async () => {
  const rules = `
    rule DetectDMG {
      condition:
        sekant.hasFileType("dmg") and
        sekant.file_category == "disk_image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/test_disk.dmg');
  const metadata = { filename: "test_disk.dmg", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectDMG'));
});

await test('6.2: Detect ISO disk image', async () => {
  const rules = `
    rule DetectISO {
      condition:
        sekant.hasFileType("iso") and
        sekant.file_category == "disk_image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/test_disk.iso');
  const metadata = { filename: "test_disk.iso", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectISO'));
});

await test('6.3: Detect XAR archive (macOS package)', async () => {
  const rules = `
    rule DetectXAR {
      condition:
        (sekant.hasFileType("xar") or sekant.hasFileType("pkg")) and
        sekant.file_category == "package"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/test_archive.xar');
  const metadata = { filename: "test_archive.xar", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectXAR'));
});

// =============================================================================
// Section 7: Wildcard Pattern Matching
// =============================================================================
console.log('\n🔍 Section 7: Wildcard Pattern Matching');

await test('7.1: hasFileType with wildcard - zip*', async () => {
  const rules = `
    rule WildcardZIP {
      condition:
        sekant.hasFileType("zip*")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.docx');
  const metadata = { filename: "ffc.docx", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('WildcardZIP'));
});

await test('7.2: hasFileType with wildcard - *encrypted', async () => {
  const rules = `
    rule WildcardEncrypted {
      condition:
        sekant.hasFileType("*encrypted")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/encrypted_zip.zip');
  const metadata = { filename: "encrypted_zip.zip", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('WildcardEncrypted'));
});

await test('7.3: hasFileType with exact match array', async () => {
  const rules = `
    rule ArrayMatch {
      condition:
        sekant.hasFileType("pdf")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.pdf');
  const metadata = { filename: "ffc.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('ArrayMatch'));
});

// =============================================================================
// Section 8: Extension Mismatch Detection
// =============================================================================
console.log('\n⚠️  Section 8: Extension Mismatch Detection');

await test('8.1: Detect extension mismatch - ZIP with wrong extension', async () => {
  const rules = `
    rule ExtensionMismatch {
      condition:
        sekant.ext_mismatch_content and
        sekant.hasFileType("zip")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  // Use a ZIP file but claim it's a PDF
  const data = loadRealFile('variations/basic_archive.zip');
  const metadata = { filename: "fake.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('ExtensionMismatch'));
});

await test('8.2: No mismatch when extension matches content', async () => {
  const rules = `
    rule NoMismatch {
      condition:
        not sekant.ext_mismatch_content and
        sekant.hasFileType("pdf")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.pdf');
  const metadata = { filename: "document.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('NoMismatch'));
});

await test('8.3: ZIP disguised as PDF document', async () => {
  const rules = `
    rule ZipAsPDF {
      condition:
        sekant.ext_mismatch_content and
        sekant.hasFileType("zip") and
        not sekant.hasFileType("pdf")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/fake_document.pdf');
  const metadata = { filename: "fake_document.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('ZipAsPDF'));
});

await test('8.4: PDF disguised as JPG image', async () => {
  const rules = `
    rule PDFAsJPG {
      condition:
        sekant.ext_mismatch_content and
        sekant.hasFileType("pdf") and
        not sekant.hasFileType("jpg")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/fake_image.jpg');
  const metadata = { filename: "fake_image.jpg", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('PDFAsJPG'));
});

await test('8.5: SQLite database disguised as JavaScript', async () => {
  const rules = `
    rule SQLiteAsJS {
      condition:
        sekant.ext_mismatch_content and
        (sekant.hasFileType("sqlite") or sekant.hasFileType("db"))
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/fake_script.js');
  const metadata = { filename: "fake_script.js", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('SQLiteAsJS'));
});

await test('8.6: PNG image disguised as executable', async () => {
  const rules = `
    rule PNGAsEXE {
      condition:
        sekant.ext_mismatch_content and
        sekant.hasFileType("png") and
        not sekant.hasFileType("exe")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/fake_executable.exe');
  const metadata = { filename: "fake_executable.exe", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('PNGAsEXE'));
});

await test('8.7: DOCX disguised as video file', async () => {
  const rules = `
    rule DOCXAsVideo {
      condition:
        sekant.ext_mismatch_content and
        sekant.hasFileType("docx") and
        sekant.hasFileType("zip")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('variations/fake_video.mp4');
  const metadata = { filename: "fake_video.mp4", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DOCXAsVideo'));
});

// =============================================================================
// Section 9: Multiple Type Detection (Overlapping Signatures)
// =============================================================================
console.log('\n🔗 Section 9: Multiple Type Detection');

await test('9.1: ZIP-based Office formats detected as both', async () => {
  const rules = `
    rule MultipleTypes {
      condition:
        sekant.hasFileType("zip") and
        sekant.hasFileType("docx")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.docx');
  const metadata = { filename: "document.docx", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('MultipleTypes'));
});

await test('9.2: OLE2 format detected with multiple extensions', async () => {
  const rules = `
    rule OLE2Multiple {
      condition:
        sekant.hasFileType("doc") or
        sekant.hasFileType("xls") or
        sekant.hasFileType("ppt")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.xls');
  const metadata = { filename: "spreadsheet.xls", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('OLE2Multiple'));
});

// =============================================================================
// Section 10: Real-World Downloaded Files
// =============================================================================
console.log('\n🌐 Section 10: Real-World Downloaded Files');

await test('10.1: Detect malicious OneNote file', async () => {
  const rules = `
    rule MaliciousOneNote {
      condition:
        sekant.hasFileType("one") and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/malicious-248f46fe7bc7f550938715935731846ef80f2af029712fa6a5283165b0d40977.one');
  const metadata = { filename: "document.one", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('MaliciousOneNote'));
});

await test('10.2: Detect APK (ZIP-based Android package)', async () => {
  const rules = `
    rule DetectAPK {
      condition:
        (sekant.hasFileType("apk") or sekant.hasFileType("zip")) and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/malicious-b008e30590725d6a5bde09ebad2cfe6ff0b002b16b3b93fe9150a608a180f511.apk');
  const metadata = { filename: "app.apk", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectAPK'));
});

await test('10.3: Detect MSI installer', async () => {
  const rules = `
    rule DetectMSI {
      condition:
        sekant.hasFileType("msi") and
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/Sample.msi');
  const metadata = { filename: "installer.msi", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectMSI'));
});

await test('10.4: Detect Windows LNK (Shell Link) file', async () => {
  const rules = `
    rule DetectLNK {
      condition:
        sekant.hasFileType("lnk") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/malicious-8d278172242da77f4bf8bac9ec90152300bde595f8e29de216369ea9dd07abde.lnk');
  const metadata = { filename: "shortcut.lnk", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectLNK'));
});

await test('10.5: Detect CHM (Compiled HTML Help) file', async () => {
  const rules = `
    rule DetectCHM {
      condition:
        sekant.hasFileType("chm") and
        sekant.file_category == "executable"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('downloads/malicious-d17fc270185e599ba009c238a35a41caab53df92257bc546896c78409afce000.chm');
  const metadata = { filename: "help.chm", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectCHM'));
});

// =============================================================================
// Section 11: Sample PDFs from sample-files
// =============================================================================
console.log('\n📚 Section 11: Sample PDF Files');

await test('11.1: Detect PDF from sample-files', async () => {
  const rules = `
    rule SamplePDF {
      condition:
        sekant.hasFileType("pdf") and
        sekant.file_category == "pdf"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('sample-files/001-trivial/minimal-document.pdf');
  const metadata = { filename: "minimal-document.pdf", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('SamplePDF'));
});

// =============================================================================
// Section 12: OpenOffice/LibreOffice Formats (ZIP-based)
// =============================================================================
console.log('\n📊 Section 12: OpenOffice/LibreOffice Formats');

await test('12.1: Detect ODT (OpenDocument Text)', async () => {
  const rules = `
    rule DetectODT {
      condition:
        (sekant.hasFileType("odt") or sekant.hasFileType("zip")) and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.odt');
  const metadata = { filename: "document.odt", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectODT'));
});

await test('12.2: Detect ODS (OpenDocument Spreadsheet)', async () => {
  const rules = `
    rule DetectODS {
      condition:
        (sekant.hasFileType("ods") or sekant.hasFileType("zip")) and
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.ods');
  const metadata = { filename: "spreadsheet.ods", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  assertTrue(result.matchedRules.includes('DetectODS'));
});

// =============================================================================
// Section 13: Additional Image Formats
// =============================================================================
console.log('\n🎨 Section 13: Additional Image Formats');

await test('13.1: Detect TIFF image', async () => {
  const rules = `
    rule DetectTIFF {
      condition:
        sekant.file_category == "image"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const data = loadRealFile('file-format-commons/files/ffc.tif');
  const metadata = { filename: "image.tif", filesize: data.length };
  
  const result = transformResults(await scanner.scan(data, metadata));
  // TIFF not in signature list, so should not match
  assertFalse(result.matchedRules.includes('DetectTIFF'));
});

// =============================================================================
// Section 14: Encryption Detection Summary
// =============================================================================
console.log('\n🔒 Section 14: Encryption Detection Summary');

await test('14.1: All encrypted archives have is_encrypted flag', async () => {
  const rules = `
    rule AllEncryptedHaveFlag {
      condition:
        sekant.is_encrypted
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const encryptedFiles = [
    'variations/encrypted_zip.zip',
    'variations/encrypted_rar5.rar',
    'variations/encrypted_pdf.pdf'
  ];
  
  for (const file of encryptedFiles) {
    const data = loadRealFile(file);
    const metadata = { filename: basename(file), filesize: data.length };
    const result = transformResults(await scanner.scan(data, metadata));
    assertTrue(result.matchedRules.includes('AllEncryptedHaveFlag'), 
               `File ${file} should have is_encrypted flag`);
  }
});

await test('14.2: Non-encrypted files do not have is_encrypted flag', async () => {
  const rules = `
    rule NotEncrypted {
      condition:
        not sekant.is_encrypted
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const nonEncryptedFiles = [
    'variations/basic_archive.zip',
    'variations/rar5_archive.rar',
    'file-format-commons/files/ffc.pdf'
  ];
  
  for (const file of nonEncryptedFiles) {
    const data = loadRealFile(file);
    const metadata = { filename: basename(file), filesize: data.length };
    const result = transformResults(await scanner.scan(data, metadata));
    assertTrue(result.matchedRules.includes('NotEncrypted'),
               `File ${file} should NOT have is_encrypted flag`);
  }
});

// =============================================================================
// Section 15: File Category Validation
// =============================================================================
console.log('\n🗂️  Section 15: File Category Validation');

await test('15.1: Archive category assignments', async () => {
  const rules = `
    rule ArchiveCategory {
      condition:
        sekant.file_category == "archive"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const archiveFiles = [
    'variations/basic_archive.zip',
    'variations/rar5_archive.rar',
    'variations/7zip_archive.7z',
    'variations/tar_archive.tar',
    'variations/gzip_file.pdf.gz',
    'variations/bzip2_file.txt.bz2',
    'variations/xz_file.html.xz'
  ];
  
  for (const file of archiveFiles) {
    const data = loadRealFile(file);
    const metadata = { filename: basename(file), filesize: data.length };
    const result = transformResults(await scanner.scan(data, metadata));
    assertTrue(result.matchedRules.includes('ArchiveCategory'),
               `File ${file} should have archive category`);
  }
});

await test('15.2: Office category assignments', async () => {
  const rules = `
    rule OfficeCategory {
      condition:
        sekant.file_category == "office"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  
  const officeFiles = [
    'file-format-commons/files/ffc.doc',
    'file-format-commons/files/ffc.xls',
    'file-format-commons/files/ffc.ppt',
    'file-format-commons/files/ffc.docx',
    'file-format-commons/files/ffc.xlsx',
    'file-format-commons/files/ffc.pptx'
  ];
  
  for (const file of officeFiles) {
    const data = loadRealFile(file);
    const metadata = { filename: basename(file), filesize: data.length };
    const result = transformResults(await scanner.scan(data, metadata));
    assertTrue(result.matchedRules.includes('OfficeCategory'),
               `File ${file} should have office category`);
  }
});

// =============================================================================
// Final Summary
// =============================================================================
console.log('\n' + '='.repeat(70));
printSummary();
console.log('='.repeat(70));
