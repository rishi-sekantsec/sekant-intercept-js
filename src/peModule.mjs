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

// Browser-compatible PE parser that mirrors YARA's PE module fields.
// Includes lightweight detection of digital signature (no PKIjs).

import * as PE from "pe-library";
import { computeEntropy, digestHex, calculateMD5, readUtf16leString, findPattern } from "./sharedUtils.mjs";

/* -------------------------
   Section processing
------------------------- */
async function parsePESections(exe, inputBytes) {
  const sections = [];
  const exeSections = exe.getAllSections?.() || exe.sections || [];
  for (const s of exeSections) {
    // Handle different PE library structures
    const sectionInfo = s.info || s;
    const data = s.data ? new Uint8Array(s.data) : (s.data ?? new Uint8Array());
    
    // Compute section hashes using shared utilities (browser-compatible)
    const md5Hash = calculateMD5(data);
    const sha1Hash = await digestHex("SHA-1", data);
    const sha256Hash = await digestHex("SHA-256", data);
    
    const sectionHashes = {
      md5: md5Hash,
      sha1: sha1Hash,
      sha256: sha256Hash,
    };
    
    sections.push({
      name: (sectionInfo.name || s.name || "")?.replace(/\0.*$/, ""),
      raw_data: data,
      entropy: computeEntropy(data),
      virtual_address: sectionInfo.virtualAddress ?? sectionInfo.VirtualAddress ?? s.VirtualAddress ?? 0,
      virtual_size: sectionInfo.virtualSize ?? sectionInfo.VirtualSize ?? s.VirtualSize ?? 0,
      raw_data_offset: sectionInfo.pointerToRawData ?? sectionInfo.PointerToRawData ?? s.PointerToRawData ?? 0,
      raw_data_size: sectionInfo.sizeOfRawData ?? sectionInfo.SizeOfRawData ?? s.SizeOfRawData ?? 0,
      characteristics: (sectionInfo.characteristics ?? sectionInfo.Characteristics ?? s.Characteristics ?? 0) >>> 0, // Convert to unsigned 32-bit
      ...sectionHashes,
    });
  }
  return sections;
}

/* -------------------------
   Imports / Exports
------------------------- */
function parseImports(exe) {
  return (exe.imports || []).map(imp => ({
    dll: imp.name || "",
    functions: (imp.functions || []).map(f => ({ name: f.name || null, ordinal: f.ordinal || null })),
  }));
}

function parseExports(exe) {
  return (exe.exports || []).map(e => e.name || e).filter(Boolean);
}

/* -------------------------
   ImpHash
------------------------- */
function computeImpHash(importsArray) {
  const parts = [];
  for (const imp of importsArray) {
    const dll = (imp.dll || "").toLowerCase();
    if (Array.isArray(imp.functions)) {
      for (const fn of imp.functions) {
        const name = (fn.name || `ordinal${fn.ordinal || ""}`).toLowerCase();
        parts.push(`${dll}.${name}`);
      }
    }
  }
  // Use calculateMD5 with TextEncoder for string hashing
  const encoder = new TextEncoder();
  return calculateMD5(encoder.encode(parts.join(",")));
}

/* -------------------------
   Digital Signature
------------------------- */
function detectAuthenticode(exe) {
  const dirEntry = exe.optionalHeader?.dataDirectory?.[PE.Format.ImageDirectoryEntry.Security];
  if (!dirEntry || !dirEntry.virtualAddress || !dirEntry.size) return { has_signature: false };
  return { has_signature: true, certificate_table: { offset: dirEntry.virtualAddress, size: dirEntry.size } };
}

/* -------------------------
   Rich Header detection
------------------------- */
function detectRichHeader(buf) {
  const pattern = new Uint8Array([0x52, 0x69, 0x63, 0x68]); // "Rich"
  const offset = findPattern(buf, pattern);
  return offset !== -1 ? { offset } : null;
}

/* -------------------------
   Optional Header Fields (flattened for YARA)
------------------------- */
function parseOptionalHeaderFlat(exe) {
  const opt = exe.newHeader?.optionalHeader || exe.optionalHeader;
  if (!opt) return {};
  
  return {
    size_of_code: opt.sizeOfCode ?? 0,
    size_of_initialized_data: opt.sizeOfInitializedData ?? 0,
    size_of_uninitialized_data: opt.sizeOfUninitializedData ?? 0,
    address_of_entry_point: opt.addressOfEntryPoint ?? 0,
    base_of_code: opt.baseOfCode ?? 0,
    base_of_data: opt.baseOfData ?? 0,
    image_base: opt.imageBase ?? 0,
    section_alignment: opt.sectionAlignment ?? 0,
    file_alignment: opt.fileAlignment ?? 0,
    subsystem: opt.subsystem ?? 0,
    dll_characteristics: opt.dllCharacteristics ?? 0,
    size_of_stack_reserve: opt.sizeOfStackReserve ?? 0,
    size_of_stack_commit: opt.sizeOfStackCommit ?? 0,
    size_of_heap_reserve: opt.sizeOfHeapReserve ?? 0,
    size_of_heap_commit: opt.sizeOfHeapCommit ?? 0,
  };
}

/* -------------------------
   Main YARA-Compatible Parser
------------------------- */
export async function parsePEYara(inputBytes) {
  if (inputBytes instanceof ArrayBuffer) inputBytes = new Uint8Array(inputBytes);

  let exe;
  try { exe = PE.NtExecutable.from(inputBytes); } 
  catch(e) { return { error: "Failed to parse PE", message: e.message }; }

  const sections = await parsePESections(exe, inputBytes);
  const imports = parseImports(exe);
  const exportsArr = parseExports(exe);
  const imphash = computeImpHash(imports);
  const digital_signature = detectAuthenticode(exe);
  const rich_header = detectRichHeader(inputBytes);
  const optional_header = parseOptionalHeaderFlat(exe);

  // Get optional header reference (supports both old and new pe-library versions)
  const optHeader = exe.newHeader?.optionalHeader || exe.optionalHeader;
  const coffHeader = exe.newHeader?.fileHeader || exe.coffHeader;

  // Convert entry_point from RVA to file offset (like we do for ELF)
  const entryPointRVA = optHeader?.addressOfEntryPoint ?? 0;
  let entryPointOffset = entryPointRVA;
  
  if (entryPointRVA > 0 && sections.length > 0) {
    // Find the section containing the entry point RVA
    for (const section of sections) {
      const sectionStart = section.virtual_address;
      const sectionEnd = sectionStart + section.virtual_size;
      
      if (entryPointRVA >= sectionStart && entryPointRVA < sectionEnd) {
        // Convert RVA to file offset: file_offset = RVA - virtual_address + raw_data_offset
        entryPointOffset = entryPointRVA - section.virtual_address + section.raw_data_offset;
        break;
      }
    }
  }

  const peObj = {
    machine: coffHeader?.machine ?? 0,
    entry_point: entryPointOffset,
    image_base: optHeader?.imageBase ?? 0,
    number_of_sections: sections.length,
    sections,
    imports,
    exports: exportsArr,
    imphash,
    digital_signature,
    rich_signature: rich_header, // matches YARA field name
    // Flatten optional header fields at top-level for YARA
    ...optional_header,
    file_size: inputBytes.length,
  };

  // Add YARA-compatible helper methods
  peObj.is_dll = () => {
    const characteristics = coffHeader?.characteristics ?? 0;
    return (characteristics & 0x2000) !== 0; // IMAGE_FILE_DLL
  };

  peObj.is_32bit = () => {
    const magic = optHeader?.magic ?? 0;
    return magic === 0x010b; // PE32
  };

  peObj.is_64bit = () => {
    const magic = optHeader?.magic ?? 0;
    return magic === 0x020b; // PE32+
  };

  return peObj;
}

/* -------------------------
   PE Module for YARA Conditions
   This wraps the parsed PE with YARA-compatible methods
------------------------- */
export function createPEModule(parsedPE) {
  if (!parsedPE || parsedPE.error) {
    return null;
  }

  return {
    // Direct properties
    machine: parsedPE.machine,
    entry_point: parsedPE.entry_point,
    image_base: parsedPE.image_base,
    number_of_sections: parsedPE.number_of_sections,
    sections: parsedPE.sections,
    imports: parsedPE.imports,
    exports: parsedPE.exports,
    imphash: parsedPE.imphash,
    rich_signature: parsedPE.rich_signature,
    digital_signature: parsedPE.digital_signature,
    
    // Optional header fields
    size_of_code: parsedPE.size_of_code,
    size_of_initialized_data: parsedPE.size_of_initialized_data,
    size_of_uninitialized_data: parsedPE.size_of_uninitialized_data,
    address_of_entry_point: parsedPE.address_of_entry_point,
    base_of_code: parsedPE.base_of_code,
    base_of_data: parsedPE.base_of_data,
    section_alignment: parsedPE.section_alignment,
    file_alignment: parsedPE.file_alignment,
    subsystem: parsedPE.subsystem,
    dll_characteristics: parsedPE.dll_characteristics,
    
    // YARA-compatible methods
    is_dll: parsedPE.is_dll,
    is_32bit: parsedPE.is_32bit,
    is_64bit: parsedPE.is_64bit,
    
    // Helper to check if a DLL is imported
    imports_dll: (dllName) => {
      const lower = dllName.toLowerCase();
      return parsedPE.imports.some(imp => imp.dll.toLowerCase() === lower);
    },
    
    // Helper to check if a specific function is imported from a DLL
    // Usage: pe.imports("kernel32.dll", "CreateProcess") or pe.imports("kernel32.dll")
    importsFunction: (dllName, functionName) => {
      const lower = dllName.toLowerCase();
      const imp = parsedPE.imports.find(imp => imp.dll.toLowerCase() === lower);
      if (!imp) return false;
      
      if (!functionName) return true; // Just check if DLL is imported
      
      const lowerFunc = functionName.toLowerCase();
      return imp.functions.some(fn => 
        fn.name && fn.name.toLowerCase() === lowerFunc
      );
    },
    
    // Helper to check if a function is exported
    exports_function: (functionName) => {
      const lower = functionName.toLowerCase();
      return parsedPE.exports.some(exp => exp.toLowerCase() === lower);
    },
    
    // PE constants (common values used in YARA rules)
    MACHINE_I386: 0x014c,
    MACHINE_AMD64: 0x8664,
    MACHINE_ARM: 0x01c0,
    MACHINE_ARM64: 0xaa64,
    
    SUBSYSTEM_NATIVE: 1,
    SUBSYSTEM_WINDOWS_GUI: 2,
    SUBSYSTEM_WINDOWS_CUI: 3,
    
    SECTION_CNT_CODE: 0x00000020,
    SECTION_CNT_INITIALIZED_DATA: 0x00000040,
    SECTION_CNT_UNINITIALIZED_DATA: 0x00000080,
    SECTION_MEM_EXECUTE: 0x20000000,
    SECTION_MEM_READ: 0x40000000,
    SECTION_MEM_WRITE: 0x80000000,
  };
}
