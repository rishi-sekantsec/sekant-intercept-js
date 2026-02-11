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
