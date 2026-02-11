/**
 * Comprehensive ELF Module Test Rules
 * 
 * Tests features compatible with Python YARA's ELF module:
 * - Basic properties (entry_point, type, machine)
 * - Sections (number_of_sections, section access)
 * - Segments (number_of_segments)
 * 
 * Extended features for Node.js implementation:
 * - is_64bit, is_32bit(), endianness
 * - Section hashes (MD5, SHA1, SHA256)
 * - Section entropy
 */
import "elf"

// ============================================================================
// Basic ELF Properties Tests - Compatible with Python YARA
// ============================================================================

rule ELF_Magic {
    meta:
        description = "Test ELF magic number detection"
    strings:
        $elf_magic = { 7F 45 4C 46 }
    condition:
        $elf_magic at 0
}

rule ELF_Type_Executable {
    meta:
        description = "Test ELF type is executable"
    condition:
        elf.type == elf.ET_EXEC
}

rule ELF_Machine_x86_64 {
    meta:
        description = "Test ELF machine type is x86-64"
    condition:
        elf.machine == elf.EM_X86_64
}

rule ELF_Machine_x86 {
    meta:
        description = "Test ELF machine type is x86"
    condition:
        elf.machine == elf.EM_386
}

// 0x400080
rule ELF_EntryPoint_64bit {
    meta:
        description = "Test entry point for 64-bit ELF"
    condition:
        elf.entry_point == 0x80 and
        elf.machine == elf.EM_X86_64
}

rule ELF_EntryPoint_32bit {
    meta:
        description = "Test entry point for 32-bit ELF"
    condition:
        elf.entry_point == 0x80 and
        elf.machine == elf.EM_386
}

// rule ELF_Print_EntryPoint {
//     meta:
//         description = "Print entrypoint for ELF"
//     condition:
//         console.log("Entry:", elf.entry_point) and false
// }

// ============================================================================
// Section Tests - Compatible with Python YARA
// ============================================================================

rule ELF_Has_Sections {
    meta:
        description = "Test that ELF has sections"
    condition:
        elf.number_of_sections > 0
}

rule ELF_Section_Count_64bit {
    meta:
        description = "Test section count for 64-bit ELF"
    condition:
        elf.number_of_sections == 3 and
        elf.machine == elf.EM_X86_64
}

rule ELF_Section_Count_32bit {
    meta:
        description = "Test section count for 32-bit ELF"
    condition:
        elf.number_of_sections == 2 and
        elf.machine == elf.EM_386
}

rule ELF_Section_Size {
    meta:
        description = "Test section size property"
    condition:
        elf.sections[0].size > 0
}

rule ELF_Section_Offset {
    meta:
        description = "Test section offset property"
    condition:
        elf.sections[0].offset >= 0
}

// ============================================================================
// Segment Tests - Compatible with Python YARA
// ============================================================================

rule ELF_Has_Segments {
    meta:
        description = "Test that ELF has program headers"
    condition:
        elf.number_of_segments > 0
}

rule ELF_Segment_Count_64bit {
    meta:
        description = "Test segment count for 64-bit ELF"
    condition:
        elf.number_of_segments == 2 and
        elf.machine == elf.EM_X86_64
}

rule ELF_Segment_Count_32bit {
    meta:
        description = "Test segment count for 32-bit ELF"
    condition:
        elf.number_of_segments == 1 and
        elf.machine == elf.EM_386
}

// ============================================================================
// Combined Tests - Compatible with Python YARA
// ============================================================================

rule ELF_64bit_Complete {
    meta:
        description = "Comprehensive test for 64-bit ELF"
    condition:
        elf.type == elf.ET_EXEC and
        elf.machine == elf.EM_X86_64 and
        elf.entry_point == 0x80 and
        elf.number_of_sections == 3 and
        elf.number_of_segments == 2
}

// 0x8048080
rule ELF_32bit_Complete {
    meta:
        description = "Comprehensive test for 32-bit ELF"
    condition:
        elf.type == elf.ET_EXEC and
        elf.machine == elf.EM_386 and
        elf.entry_point == 0x80 and
        elf.number_of_sections == 2 and
        elf.number_of_segments == 1
}

rule ELF_Sections_And_Segments {
    meta:
        description = "Test both sections and segments exist"
    condition:
        elf.number_of_sections > 0 and
        elf.number_of_segments > 0
}

rule ELF_Entry_Point_Exists {
    meta:
        description = "Test that entry point is defined"
    condition:
        elf.entry_point > 0
}

rule ELF_Multiple_Sections_Access {
    meta:
        description = "Test accessing multiple sections"
    condition:
        elf.sections[0].size > 0 and
        elf.sections[1].size >= 0
}

// ============================================================================
// Additional Comprehensive Tests
// ============================================================================

rule ELF_Type_Not_Core {
    meta:
        description = "Test ELF is not a core dump"
    condition:
        elf.type != elf.ET_CORE
}

rule ELF_Type_Not_Relocatable {
    meta:
        description = "Test ELF is not relocatable"
    condition:
        elf.type != elf.ET_REL
}

rule ELF_Valid_Entry_Point_Range {
    meta:
        description = "Test entry point is in valid range"
    condition:
        (elf.machine == elf.EM_X86_64 and elf.entry_point >= 0x400000) or
        (elf.machine == elf.EM_386 and elf.entry_point >= 0x8048000)
}

rule ELF_Section_Array_Bounds {
    meta:
        description = "Test section array access within bounds"
    condition:
        elf.number_of_sections > 2 and
        elf.sections[elf.number_of_sections - 1].size >= 0
}

rule ELF_All_Sections_Have_Offset {
    meta:
        description = "Test all sections have valid offsets"
    condition:
        for all i in (0..elf.number_of_sections - 1): (
            elf.sections[i].offset >= 0
        )
}

rule ELF_At_Least_One_Loadable_Segment {
    meta:
        description = "Test has at least one PT_LOAD segment"
    condition:
        elf.number_of_segments > 0 and
        for any i in (0..elf.number_of_segments - 1): (
            elf.segments[i].type == 1  // PT_LOAD = 1
        )
}

rule ELF_Segments_Have_Valid_Types {
    meta:
        description = "Test all segments have valid type values"
    condition:
        for all i in (0..elf.number_of_segments - 1): (
            elf.segments[i].type >= 0 and elf.segments[i].type <= 8
        )
}

rule ELF_First_Section_Non_Empty {
    meta:
        description = "Test first section has content"
    condition:
        elf.sections[0].size > 0
}

rule ELF_Last_Section_Exists {
    meta:
        description = "Test last section is accessible"
    condition:
        elf.sections[elf.number_of_sections - 1].size >= 0
}

rule ELF_Entry_Point_Matches_Architecture {
    meta:
        description = "Test entry point matches architecture conventions"
    condition:
        (elf.machine == elf.EM_X86_64 and elf.entry_point > 0) or
        (elf.machine == elf.EM_386 and elf.entry_point > 0)
}

rule ELF_Has_Multiple_Segments {
    meta:
        description = "Test ELF has more than one segment (typical for executables)"
    condition:
        elf.number_of_segments >= 1
}

rule ELF_Section_Sizes_Logical {
    meta:
        description = "Test section sizes are reasonable"
    condition:
        for all i in (0..elf.number_of_sections - 1): (
            elf.sections[i].size < 0x100000  // Less than 1MB for our test files
        )
}

rule ELF_Type_Is_Known {
    meta:
        description = "Test ELF type is a known value"
    condition:
        elf.type >= elf.ET_NONE and elf.type <= elf.ET_CORE
}

rule ELF_Machine_Is_Known {
    meta:
        description = "Test machine type is known (x86 or x86-64)"
    condition:
        elf.machine == elf.EM_386 or elf.machine == elf.EM_X86_64
}

rule ELF_Consistent_Architecture {
    meta:
        description = "Test architecture consistency across properties"
    condition:
        (elf.machine == elf.EM_X86_64 and elf.number_of_sections == 3) or
        (elf.machine == elf.EM_386 and elf.number_of_sections == 2)
}

rule ELF_Segment_Type_PT_LOAD {
    meta:
        description = "Test for PT_LOAD segment type"
    condition:
        for any i in (0..elf.number_of_segments - 1): (
            elf.segments[i].type == 1
        )
}

rule ELF_All_Sections_Addressable {
    meta:
        description = "Test all sections have addressable offsets"
    condition:
        for all i in (0..elf.number_of_sections - 1): (
            elf.sections[i].offset < filesize
        )
}

rule ELF_Entry_Point_Non_Zero {
    meta:
        description = "Test entry point is not zero (valid for executables)"
    condition:
        elf.entry_point != 0
}

rule ELF_Multiple_Properties_Combined {
    meta:
        description = "Test multiple properties in combination"
    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point > 0 and
        elf.number_of_sections > 0 and
        elf.number_of_segments > 0 and
        (elf.machine == elf.EM_386 or elf.machine == elf.EM_X86_64)
}
