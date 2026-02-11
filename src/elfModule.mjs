/*
 * Copyright 2026 Rishi Kant (Sekant Security Inc.)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { computeEntropy, digestHex, calculateMD5, readUint16, readUint32, readUint64, readString, toHex } from "./sharedUtils.mjs";

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const DT_NEEDED = 1;
const DT_SONAME = 14;
const DT_RPATH = 15;
const DT_RUNPATH = 29;

/* -------------------------
   ELF Header
------------------------- */
function parseElfHeader(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < 4; i++) if (buf[i] !== ELF_MAGIC[i]) throw new Error("Not ELF");

  const elfClass = buf[4];
  const littleEndian = buf[5] === 1;
  const header = { is64bit: elfClass === 2, littleEndian };
  
  // Parse type and machine (standard ELF header fields)
  header.type = readUint16(view, 0x10, littleEndian);
  header.machine = readUint16(view, 0x12, littleEndian);
  
  header.entry_point = header.is64bit ? readUint64(view, 0x18, littleEndian) : readUint32(view, 0x18, littleEndian);
  header.phoff = header.is64bit ? readUint64(view, 0x20, littleEndian) : readUint32(view, 0x1C, littleEndian);
  header.shoff = header.is64bit ? readUint64(view, 0x28, littleEndian) : readUint32(view, 0x20, littleEndian);
  header.phentsize = header.is64bit ? readUint16(view, 0x36, littleEndian) : readUint16(view, 0x2A, littleEndian);
  header.phnum = header.is64bit ? readUint16(view, 0x38, littleEndian) : readUint16(view, 0x2C, littleEndian);
  header.shentsize = header.is64bit ? readUint16(view, 0x3A, littleEndian) : readUint16(view, 0x2E, littleEndian);
  header.shnum = header.is64bit ? readUint16(view, 0x3C, littleEndian) : readUint16(view, 0x30, littleEndian);
  header.shstrndx = header.is64bit ? readUint16(view, 0x3E, littleEndian) : readUint16(view, 0x32, littleEndian);
  return header;
}

/* -------------------------
   Program headers
------------------------- */
function parseProgramHeaders(buf, header) {
  const phs = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = header.phoff;

  for (let i = 0; i < header.phnum; i++) {
    let p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align;
    if (header.is64bit) {
      p_type = readUint32(view, offset, header.littleEndian);
      p_flags = readUint32(view, offset + 4, header.littleEndian);
      p_offset = readUint64(view, offset + 8, header.littleEndian);
      p_vaddr = readUint64(view, offset + 16, header.littleEndian);
      p_filesz = readUint64(view, offset + 32, header.littleEndian);
      p_memsz = readUint64(view, offset + 40, header.littleEndian);
      p_align = readUint64(view, offset + 48, header.littleEndian);
      offset += 56;
    } else {
      p_type = readUint32(view, offset, header.littleEndian);
      p_offset = readUint32(view, offset + 4, header.littleEndian);
      p_vaddr = readUint32(view, offset + 8, header.littleEndian);
      p_filesz = readUint32(view, offset + 16, header.littleEndian);
      p_memsz = readUint32(view, offset + 20, header.littleEndian);
      p_flags = readUint32(view, offset + 24, header.littleEndian);
      p_align = readUint32(view, offset + 28, header.littleEndian);
      offset += 32;
    }
    phs.push({ type: p_type, offset: p_offset, vaddr: p_vaddr, filesz: p_filesz, memsz: p_memsz, flags: p_flags, align: p_align });
  }
  return phs;
}

/* -------------------------
   Sections + hashes
------------------------- */
async function parseSections(buf, header) {
  const shs = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = header.shoff;

  for (let i = 0; i < header.shnum; i++) {
    const sh_offset = header.is64bit ? readUint64(view, offset + 24, header.littleEndian) : readUint32(view, offset + 16, header.littleEndian);
    const sh_size = header.is64bit ? readUint64(view, offset + 32, header.littleEndian) : readUint32(view, offset + 20, header.littleEndian);
    const sectionData = sh_offset + sh_size <= buf.length ? buf.slice(sh_offset, sh_offset + sh_size) : new Uint8Array();

    // Compute hashes using shared utilities (browser-compatible)
    const md5Hash = calculateMD5(sectionData);
    const sha1Hash = await digestHex("SHA-1", sectionData);
    const sha256Hash = await digestHex("SHA-256", sectionData);

    shs.push({
      offset: sh_offset,
      size: sh_size,
      entropy: computeEntropy(sectionData),
      raw_data: sectionData,
      md5: md5Hash,
      sha1: sha1Hash,
      sha256: sha256Hash,
    });

    offset += header.is64bit ? 64 : 40;
  }

  return shs;
}

/* -------------------------
   Dynamic dependencies parsing
------------------------- */
function parseDynamicDependencies(buf, sections, header) {
  const dynSection = sections.find(s => s.raw_data && s.raw_data.length > 0 && s.name === ".dynamic");
  const dynstrSection = sections.find(s => s.raw_data && s.raw_data.length > 0 && s.name === ".dynstr");
  if (!dynSection || !dynstrSection) return { needed_libraries: [], soname: null, rpath: null, runpath: null };

  const dynBuf = dynSection.raw_data;
  const strBuf = dynstrSection.raw_data;
  const view = new DataView(dynBuf.buffer, dynBuf.byteOffset, dynBuf.byteLength);
  const entrySize = header.is64bit ? 16 : 8;

  const needed_libraries = [];
  let soname = null;
  let rpath = null;
  let runpath = null;

  for (let offset = 0; offset + entrySize <= dynBuf.length; offset += entrySize) {
    const tag = header.is64bit ? readUint64(view, offset, header.littleEndian) : readUint32(view, offset, header.littleEndian);
    const val = header.is64bit ? readUint64(view, offset + 8, header.littleEndian) : readUint32(view, offset + 4, header.littleEndian);

    if (tag === DT_NEEDED) needed_libraries.push(readString(strBuf, val));
    else if (tag === DT_SONAME) soname = readString(strBuf, val);
    else if (tag === DT_RPATH) rpath = readString(strBuf, val);
    else if (tag === DT_RUNPATH) runpath = readString(strBuf, val);
  }

  return { needed_libraries, soname, rpath, runpath };
}

/* -------------------------
   Exported symbols
------------------------- */
function parseExports(buf, sections, header) {
  const exportsArr = [];
  const dynsym = sections.find(s => s.name === ".dynsym");
  const dynstr = sections.find(s => s.name === ".dynstr");
  if (!dynsym || !dynstr) return exportsArr;

  const symBuf = dynsym.raw_data;
  const strBuf = dynstr.raw_data;
  const view = new DataView(symBuf.buffer, symBuf.byteOffset, symBuf.byteLength);
  const entrySize = header.is64bit ? 24 : 16;

  for (let offset = 0; offset + entrySize <= symBuf.length; offset += entrySize) {
    const nameOffset = readUint32(view, offset, header.littleEndian);
    if (nameOffset >= strBuf.length) continue;
    const name = readString(strBuf, nameOffset);
    if (name) exportsArr.push(name);
  }

  return exportsArr;
}

/* -------------------------
   Main YARA-Compatible ELF Parser
------------------------- */
export async function parseELFYaraFull(inputBytes) {
  if (inputBytes instanceof ArrayBuffer) inputBytes = new Uint8Array(inputBytes);
  const file_size = inputBytes.length;

  let header;
  try { header = parseElfHeader(inputBytes); } 
  catch (e) { return { error: "Invalid ELF file", message: e.message }; }

  const program_headers = parseProgramHeaders(inputBytes, header);
  const sections = await parseSections(inputBytes, header);
  const { needed_libraries, soname, rpath, runpath } = parseDynamicDependencies(inputBytes, sections, header);
  const exportsArr = parseExports(inputBytes, sections, header);

  const vaddr = (program_headers?.map(ph => ph.vaddr) || [0])[0];
  const offset = (program_headers?.map(ph => ph.offset) || [0])[0];

  return {
    type: header.type,
    machine: header.machine,
    entry_point: header.entry_point - vaddr + offset,
    is_64bit: header.is64bit,
    endianness: header.littleEndian ? "little" : "big",
    file_size,
    program_headers,
    sections,
    imports: needed_libraries.map(lib => ({ dll: lib, functions: [] })),
    exports: exportsArr,
    needed_libraries,
    soname,
    rpath,
    runpath,
    hashes: {}, // optional whole-file hashes
  };
}

/* -------------------------
   Create YARA-Compatible ELF Module
------------------------- */
export function createELFModule(parsedELF) {
  if (!parsedELF || parsedELF.error) {
    return null;
  }

  // Create module with all ELF properties
  const elfModule = {
    // Basic properties
    type: parsedELF.type || 0,
    machine: parsedELF.machine || 0,
    entry_point: parsedELF.entry_point || 0,
    file_size: parsedELF.file_size || 0,
    is_64bit: parsedELF.is_64bit || false,
    endianness: parsedELF.endianness || "little",
    
    // Sections
    sections: parsedELF.sections || [],
    number_of_sections: (parsedELF.sections || []).length,
    
    // Program headers (also exposed as "segments" for Python YARA compatibility)
    program_headers: parsedELF.program_headers || [],
    segments: parsedELF.program_headers || [],  // Alias for Python YARA compatibility
    number_of_segments: (parsedELF.program_headers || []).length,
    
    // Imports/Exports
    imports: parsedELF.needed_libraries || [],
    exports: parsedELF.exports || [],
    needed_libraries: parsedELF.needed_libraries || [],
    
    // Dynamic linking info
    soname: parsedELF.soname || null,
    rpath: parsedELF.rpath || null,
    runpath: parsedELF.runpath || null,
    
    // Helper methods
    is_32bit() {
      return !this.is_64bit;
    },
    
    is_little_endian() {
      return this.endianness === "little";
    },
    
    is_big_endian() {
      return this.endianness === "big";
    },
    
    // Check if imports a specific library
    imports_library(libName) {
      return this.needed_libraries.some(lib => 
        lib.toLowerCase().includes(libName.toLowerCase())
      );
    },
    
    // Check if exports a specific function
    exports_function(funcName) {
      return this.exports.some(exp => exp === funcName);
    },
    
    // Get section by name
    get_section_by_name(name) {
      return this.sections.find(s => s.name === name);
    },
    
    // ELF constants (matching YARA standard)
    // ELF types (e_type)
    ET_NONE: 0,
    ET_REL: 1,
    ET_EXEC: 2,
    ET_DYN: 3,
    ET_CORE: 4,
    
    // ELF machine types (e_machine)
    EM_NONE: 0,
    EM_386: 3,         // Intel 80386
    EM_X86_64: 62,     // AMD x86-64
    EM_ARM: 40,        // ARM
    EM_AARCH64: 183,   // ARM 64-bit
    
    // Legacy names for compatibility
    ARCH_X86: 3,
    ARCH_X86_64: 62,
    ARCH_ARM: 40,
    ARCH_AARCH64: 183,
    
    TYPE_EXEC: 2,
    TYPE_DYN: 3,
    TYPE_CORE: 4,
  };

  return elfModule;
}
