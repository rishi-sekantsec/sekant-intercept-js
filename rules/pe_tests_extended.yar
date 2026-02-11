/**
 * Extended Comprehensive PE Module Test Rules
 * 
 * This test suite expands coverage to identify gaps between Python YARA (reference)
 * and Node.js implementation, testing:
 * - Section properties (virtual_address, virtual_size, raw_data_offset, raw_data_size)
 * - Section characteristics (all flags combinations)
 * - Optional header fields
 * - Multiple section iteration patterns
 * - Edge cases and boundary conditions
 * - Arithmetic operations on PE fields
 * - Complex conditional logic
 */
import "pe"

// ============================================================================
// Section Property Tests - Detailed
// ============================================================================

rule PE_Section_Virtual_Address_Aligned {
    meta:
        description = "Test section virtual addresses are aligned"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].virtual_address & 0xFFF) == 0
        )
}

rule PE_Section_Raw_Data_Offset_Valid {
    meta:
        description = "Test section raw data offsets are valid"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].raw_data_offset >= 0x200
        )
}

rule PE_Section_Virtual_Size_Positive {
    meta:
        description = "Test sections have positive virtual size"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_size > 0
        )
}

rule PE_Section_Raw_Data_Size_Aligned {
    meta:
        description = "Test raw data sizes are file-aligned"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].raw_data_size == 0 or
            (pe.sections[i].raw_data_size & 0x1FF) == 0
        )
}

rule PE_Sections_Ordered_By_VA {
    meta:
        description = "Test sections are ordered by virtual address"
    condition:
        pe.number_of_sections < 2 or
        for all i in (0..pe.number_of_sections - 2): (
            pe.sections[i].virtual_address < pe.sections[i + 1].virtual_address
        )
}

rule PE_Text_Section_Properties {
    meta:
        description = "Test .text section has expected properties"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            pe.sections[i].virtual_address == 0x1000 and
            pe.sections[i].raw_data_size == 0x200
        )
}

rule PE_Data_Section_Properties {
    meta:
        description = "Test .data section has expected properties"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data" and
            pe.sections[i].virtual_address == 0x2000
        )
}

rule PE_RData_Section_Properties_64bit {
    meta:
        description = "Test .rdata section exists in 64-bit PE"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".rdata" and
            pe.sections[i].virtual_address == 0x3000
        )
}

// ============================================================================
// Section Characteristics Tests - All Flags
// ============================================================================

rule PE_Has_Code_Section {
    meta:
        description = "Test for section with code flag"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_CNT_CODE) != 0
        )
}

rule PE_Has_Initialized_Data_Section {
    meta:
        description = "Test for initialized data section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_CNT_INITIALIZED_DATA) != 0
        )
}

rule PE_Text_Section_Readable {
    meta:
        description = "Test .text section is readable"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0
        )
}

rule PE_Text_Section_Not_Writable {
    meta:
        description = "Test .text section is not writable"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) == 0
        )
}

rule PE_Data_Section_Readable {
    meta:
        description = "Test .data section is readable"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data" and
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0
        )
}

rule PE_Characteristics_Text_Exact {
    meta:
        description = "Test exact characteristics for .text section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            pe.sections[i].characteristics == 0x60000020
        )
}

rule PE_Characteristics_Data_Exact {
    meta:
        description = "Test exact characteristics for .data section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data" and
            pe.sections[i].characteristics == 0xC0000040
        )
}

rule PE_Characteristics_RData_Exact_64bit {
    meta:
        description = "Test exact characteristics for .rdata section in 64-bit"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".rdata" and
            pe.sections[i].characteristics == 0x40000040
        )
}

// ============================================================================
// Section Index and Count Tests
// ============================================================================

rule PE_Section_Count_Matches_Array {
    meta:
        description = "Test section count matches accessible sections"
    condition:
        pe.number_of_sections == 2 or pe.number_of_sections == 3
}

rule PE_First_Section_Accessible {
    meta:
        description = "Test first section is accessible"
    condition:
        pe.number_of_sections > 0 and
        pe.sections[0].name != ""
}

rule PE_Last_Section_Accessible_32bit {
    meta:
        description = "Test last section accessible for 32-bit"
    condition:
        pe.machine == pe.MACHINE_I386 and
        pe.number_of_sections == 2 and
        pe.sections[1].name != ""
}

rule PE_Last_Section_Accessible_64bit {
    meta:
        description = "Test last section accessible for 64-bit"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        pe.number_of_sections == 3 and
        pe.sections[2].name != ""
}

rule PE_All_Sections_Iterable {
    meta:
        description = "Test all sections can be iterated"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_address >= 0x1000 and
            pe.sections[i].virtual_address <= 0x10000
        )
}

// ============================================================================
// Optional Header Fields Tests
// ============================================================================

rule PE_Size_Of_Code_Positive {
    meta:
        description = "Test size of code is positive"
    condition:
        pe.size_of_code > 0
}

rule PE_Size_Of_Code_Expected {
    meta:
        description = "Test size of code matches expected value"
    condition:
        pe.size_of_code == 0x200
}

rule PE_Size_Of_Initialized_Data_Positive {
    meta:
        description = "Test size of initialized data is positive"
    condition:
        pe.size_of_initialized_data > 0
}

rule PE_Size_Of_Initialized_Data_Expected {
    meta:
        description = "Test size of initialized data matches expected"
    condition:
        pe.size_of_initialized_data == 0x200
}

rule PE_Base_Of_Code {
    meta:
        description = "Test base of code"
    condition:
        pe.base_of_code == 0x1000
}

rule PE_Base_Of_Data_32bit {
    meta:
        description = "Test base of data for 32-bit PE"
    condition:
        pe.machine == pe.MACHINE_I386 and
        pe.base_of_data == 0x2000
}

rule PE_Section_Alignment {
    meta:
        description = "Test section alignment"
    condition:
        pe.section_alignment == 0x1000
}

rule PE_File_Alignment {
    meta:
        description = "Test file alignment"
    condition:
        pe.file_alignment == 0x200
}

// ============================================================================
// Arithmetic and Comparison Tests
// ============================================================================

rule PE_Entry_Point_Math {
    meta:
        description = "Test arithmetic on entry point"
    condition:
        pe.entry_point * 2 == 0x400 and
        pe.entry_point + 0x100 == 0x300 and
        pe.entry_point - 0x100 == 0x100
}

rule PE_Image_Base_32bit_Math {
    meta:
        description = "Test arithmetic on 32-bit image base"
    condition:
        pe.machine == pe.MACHINE_I386 and
        pe.image_base \ 0x1000 == 0x400 and
        pe.image_base > 0x300000
}

rule PE_Image_Base_64bit_Math {
    meta:
        description = "Test arithmetic on 64-bit image base"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        pe.image_base == 0x140000000
}

rule PE_Section_Count_Math {
    meta:
        description = "Test arithmetic on section count"
    condition:
        pe.number_of_sections >= 2 and
        pe.number_of_sections <= 3 and
        pe.number_of_sections * 2 <= 6
}

rule PE_Section_Size_Comparison {
    meta:
        description = "Test section size comparisons"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_size >= pe.sections[i].raw_data_size or
            pe.sections[i].raw_data_size == 0x200
        )
}

// ============================================================================
// Complex Conditional Logic Tests
// ============================================================================

rule PE_Nested_Conditions_OR {
    meta:
        description = "Test nested OR conditions"
    condition:
        (pe.machine == pe.MACHINE_I386 or pe.machine == pe.MACHINE_AMD64) and
        (pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI or pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI)
}

rule PE_Nested_Conditions_AND {
    meta:
        description = "Test nested AND conditions"
    condition:
        pe.entry_point > 0 and pe.image_base > 0 and
        pe.number_of_sections > 0 and pe.number_of_sections < 10
}

rule PE_Multiple_Section_Checks {
    meta:
        description = "Test multiple section conditions"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text"
        ) and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data"
        )
}

rule PE_Section_Name_Variations {
    meta:
        description = "Test section name matching variations"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" or
            pe.sections[i].name == ".data" or
            pe.sections[i].name == ".rdata"
        )
}

rule PE_Section_Contains_Text {
    meta:
        description = "Test section name contains text"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name contains "text" or
            pe.sections[i].name contains "data"
        )
}

rule PE_Section_Starts_With_Dot {
    meta:
        description = "Test all sections start with dot"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name startswith "."
        )
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

rule PE_Zero_Section_Check {
    meta:
        description = "Test boundary check with zero index"
    condition:
        pe.number_of_sections > 0 and
        pe.sections[0].virtual_address > 0
}

rule PE_Max_Section_Index {
    meta:
        description = "Test maximum section index access"
    condition:
        pe.sections[pe.number_of_sections - 1].virtual_address > 0
}

rule PE_Entry_Point_Boundary {
    meta:
        description = "Test entry point within reasonable bounds"
    condition:
        pe.entry_point >= 0x200 and
        pe.entry_point <= 0x10000
}

rule PE_Section_VA_Range {
    meta:
        description = "Test section VAs are in expected range"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_address >= 0x1000 and
            pe.sections[i].virtual_address < 0x100000
        )
}

// ============================================================================
// Type and Format Validation Tests
// ============================================================================

rule PE_Is_32bit_XOR_64bit {
    meta:
        description = "Test PE is exactly one architecture"
    condition:
        pe.is_32bit() != pe.is_64bit()
}

rule PE_Machine_Matches_Bitness {
    meta:
        description = "Test machine type matches bitness"
    condition:
        (pe.machine == pe.MACHINE_I386 and pe.is_32bit()) or
        (pe.machine == pe.MACHINE_AMD64 and pe.is_64bit())
}

rule PE_Not_DLL_Not_Driver {
    meta:
        description = "Test PE is executable not DLL"
    condition:
        not pe.is_dll() and
        pe.subsystem != pe.SUBSYSTEM_NATIVE
}

rule PE_Console_Application {
    meta:
        description = "Test PE is console application"
    condition:
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        not pe.is_dll()
}

// ============================================================================
// For-Loop Pattern Tests
// ============================================================================

rule PE_For_Any_Pattern_1 {
    meta:
        description = "Test for-any with simple comparison"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_address >= 0x1000
        )
}

rule PE_For_Any_Pattern_2 {
    meta:
        description = "Test for-any with bitwise operation"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & 0x20000000) != 0
        )
}

rule PE_For_All_Pattern_1 {
    meta:
        description = "Test for-all with name check"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name != ""
        )
}

rule PE_For_All_Pattern_2 {
    meta:
        description = "Test for-all with size check"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].virtual_size > 0
        )
}

// ============================================================================
// Machine Type Extended Tests
// ============================================================================

rule PE_Machine_Not_ARM {
    meta:
        description = "Test machine is not ARM"
    condition:
        pe.machine != pe.MACHINE_ARM and
        pe.machine != pe.MACHINE_ARM64
}

rule PE_Machine_x86_Family {
    meta:
        description = "Test machine is x86 family"
    condition:
        pe.machine == pe.MACHINE_I386 or
        pe.machine == pe.MACHINE_AMD64
}

// ============================================================================
// Combined Complex Tests
// ============================================================================

rule PE_Comprehensive_32bit_Check {
    meta:
        description = "Comprehensive validation for 32-bit PE"
    condition:
        pe.machine == pe.MACHINE_I386 and
        pe.is_32bit() and
        pe.entry_point == 0x200 and
        pe.image_base == 0x400000 and
        pe.number_of_sections == 2 and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        pe.section_alignment == 0x1000 and
        pe.file_alignment == 0x200 and
        pe.size_of_code == 0x200 and
        pe.base_of_code == 0x1000 and
        pe.base_of_data == 0x2000 and
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name != "" and
            pe.sections[i].virtual_address > 0
        )
}

rule PE_Comprehensive_64bit_Check {
    meta:
        description = "Comprehensive validation for 64-bit PE"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        pe.is_64bit() and
        pe.entry_point == 0x200 and
        pe.image_base == 0x140000000 and
        pe.number_of_sections == 3 and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        pe.section_alignment == 0x1000 and
        pe.file_alignment == 0x200 and
        pe.size_of_code == 0x200 and
        pe.base_of_code == 0x1000 and
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name != "" and
            pe.sections[i].virtual_address > 0
        )
}

rule PE_All_Sections_Characteristics_Valid {
    meta:
        description = "Test all sections have valid characteristics"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            pe.sections[i].characteristics > 0 and
            pe.sections[i].characteristics < 0xFFFFFFFF
        )
}

rule PE_Section_Memory_Flags_Consistent {
    meta:
        description = "Test section memory flags are consistent"
    condition:
        for all i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0 or
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) != 0 or
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0
        )
}
