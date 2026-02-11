/**
 * Comprehensive PE Module Test Rules
 * 
 * Tests features compatible with Python YARA's PE module:
 * - Basic properties (entry_point, image_base, subsystem)
 * - Sections (number_of_sections, section properties)
 * - Machine type detection (32-bit vs 64-bit)
 * - Characteristics and subsystem values
 * 
 * Extended features for Node.js implementation:
 * - Section hashes (MD5, SHA1, SHA256)
 * - Section entropy
 * - Import/export analysis
 */
import "pe"

// ============================================================================
// Basic PE Properties Tests - Compatible with Python YARA
// ============================================================================

rule PE_Magic {
    meta:
        description = "Test PE magic number detection"
    strings:
        $mz_magic = { 4D 5A }
        $pe_magic = { 50 45 00 00 }
    condition:
        $mz_magic at 0 and $pe_magic
}

rule PE_Is_PE {
    meta:
        description = "Test PE format detection"
    condition:
        uint16(0) == 0x5A4D and // MZ
        uint32(uint32(0x3C)) == 0x00004550 // PE signature
}

rule PE_Machine_I386 {
    meta:
        description = "Test PE machine type is x86 (32-bit)"
    condition:
        pe.machine == pe.MACHINE_I386
}

rule PE_Machine_AMD64 {
    meta:
        description = "Test PE machine type is AMD64 (64-bit)"
    condition:
        pe.machine == pe.MACHINE_AMD64
}

rule PE_32bit {
    meta:
        description = "Test PE is 32-bit using is_32bit()"
    condition:
        pe.is_32bit()
}

rule PE_64bit {
    meta:
        description = "Test PE is 64-bit using is_64bit()"
    condition:
        pe.is_64bit()
}

rule PE_Entry_Point_Exists {
    meta:
        description = "Test that entry point is defined"
    condition:
        pe.entry_point > 0
}

rule PE_Entry_Point_32bit {
    meta:
        description = "Test entry point for 32-bit PE (file offset, not RVA)"
    condition:
        pe.entry_point == 0x200 and
        pe.machine == pe.MACHINE_I386
}

rule PE_Entry_Point_64bit {
    meta:
        description = "Test entry point for 64-bit PE (file offset, not RVA)"
    condition:
        pe.entry_point == 0x200 and
        pe.machine == pe.MACHINE_AMD64
}

rule PE_Image_Base_32bit {
    meta:
        description = "Test image base for 32-bit PE"
    condition:
        pe.image_base == 0x400000 and
        pe.machine == pe.MACHINE_I386
}

rule PE_Image_Base_64bit {
    meta:
        description = "Test image base for 64-bit PE"
    condition:
        pe.image_base == 0x140000000 and
        pe.machine == pe.MACHINE_AMD64
}

// ============================================================================
// Section Tests - Compatible with Python YARA
// ============================================================================

rule PE_Has_Sections {
    meta:
        description = "Test that PE has sections"
    condition:
        pe.number_of_sections > 0
}

rule PE_Section_Count_32bit {
    meta:
        description = "Test section count for 32-bit PE"
    condition:
        pe.number_of_sections == 2 and
        pe.machine == pe.MACHINE_I386
}

rule PE_Section_Count_64bit {
    meta:
        description = "Test section count for 64-bit PE"
    condition:
        pe.number_of_sections == 3 and
        pe.machine == pe.MACHINE_AMD64
}

rule PE_Has_Text_Section {
    meta:
        description = "Test for .text section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text"
        )
}

rule PE_Has_Data_Section {
    meta:
        description = "Test for .data section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data"
        )
}

rule PE_Section_Characteristics {
    meta:
        description = "Test section characteristics"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].characteristics & pe.SECTION_CNT_CODE != 0 or
            pe.sections[i].characteristics & pe.SECTION_CNT_INITIALIZED_DATA != 0
        )
}

rule PE_Executable_Section {
    meta:
        description = "Test for executable section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE != 0
        )
}

rule PE_Writable_Section {
    meta:
        description = "Test for writable section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].characteristics & pe.SECTION_MEM_WRITE != 0
        )
}

// ============================================================================
// Subsystem and Characteristics Tests
// ============================================================================

rule PE_Subsystem_CUI {
    meta:
        description = "Test PE subsystem is console"
    condition:
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI
}

rule PE_Not_DLL {
    meta:
        description = "Test PE is not a DLL"
    condition:
        not pe.is_dll()
}

// ============================================================================
// Combined and Validation Tests
// ============================================================================

rule PE_32bit_Complete {
    meta:
        description = "Comprehensive test for 32-bit PE"
    condition:
        pe.machine == pe.MACHINE_I386 and
        pe.is_32bit() and
        pe.entry_point == 0x1000 and
        pe.image_base == 0x400000 and
        pe.number_of_sections == 2 and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI
}

rule PE_64bit_Complete {
    meta:
        description = "Comprehensive test for 64-bit PE"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        pe.is_64bit() and
        pe.entry_point == 0x1000 and
        pe.image_base == 0x140000000 and
        pe.number_of_sections == 3 and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI
}

rule PE_Valid_Entry_Point {
    meta:
        description = "Test entry point is non-zero and reasonable"
    condition:
        pe.entry_point > 0 and
        pe.entry_point < 0x10000000
}

rule PE_Section_Array_Bounds {
    meta:
        description = "Test section array access within bounds"
    condition:
        pe.number_of_sections > 0 and
        pe.sections[pe.number_of_sections - 1].virtual_address >= 0
}

rule PE_All_Sections_Have_Name {
    meta:
        description = "Test all sections have names"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name != ""
        )
}

rule PE_All_Sections_Have_VA {
    meta:
        description = "Test all sections have virtual addresses"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_address > 0
        )
}

rule PE_Text_Section_Is_Executable {
    meta:
        description = "Test .text section is executable"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0
        )
}

rule PE_Data_Section_Is_Writable {
    meta:
        description = "Test .data section is writable"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data" and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) != 0
        )
}

rule PE_Architecture_Consistency {
    meta:
        description = "Test architecture consistency"
    condition:
        (pe.machine == pe.MACHINE_I386 and pe.is_32bit() and not pe.is_64bit()) or
        (pe.machine == pe.MACHINE_AMD64 and pe.is_64bit() and not pe.is_32bit())
}

rule PE_Section_Sizes_Logical {
    meta:
        description = "Test section sizes are reasonable"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].raw_data_size < 0x100000 and
            pe.sections[i].virtual_size < 0x100000
        )
}

rule PE_First_Section_Non_Empty {
    meta:
        description = "Test first section has content"
    condition:
        pe.sections[0].raw_data_size > 0
}

rule PE_Multiple_Sections_Access {
    meta:
        description = "Test accessing multiple sections"
    condition:
        pe.sections[0].virtual_address > 0 and
        pe.sections[1].virtual_address > pe.sections[0].virtual_address
}

rule PE_Machine_Type_Known {
    meta:
        description = "Test machine type is known"
    condition:
        pe.machine == pe.MACHINE_I386 or
        pe.machine == pe.MACHINE_AMD64
}

rule PE_Subsystem_Known {
    meta:
        description = "Test subsystem is known"
    condition:
        pe.subsystem == pe.SUBSYSTEM_NATIVE or
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI or
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI
}

rule PE_Image_Base_Aligned {
    meta:
        description = "Test image base is page-aligned"
    condition:
        (pe.image_base & 0xFFFF) == 0
}

rule PE_Entry_Point_In_Code_Section {
    meta:
        description = "Test entry point falls within a code section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.entry_point >= pe.sections[i].virtual_address and
            pe.entry_point < pe.sections[i].virtual_address + pe.sections[i].virtual_size and
            (pe.sections[i].characteristics & pe.SECTION_CNT_CODE) != 0
        )
}

rule PE_Has_Read_Only_Section {
    meta:
        description = "Test for read-only section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0 and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) == 0
        )
}

rule PE_Multiple_Properties_Combined {
    meta:
        description = "Test multiple properties in combination"
    condition:
        pe.entry_point > 0 and
        pe.image_base > 0 and
        pe.number_of_sections > 0 and
        (pe.machine == pe.MACHINE_I386 or pe.machine == pe.MACHINE_AMD64) and
        (pe.subsystem >= 1 and pe.subsystem <= 3)
}
