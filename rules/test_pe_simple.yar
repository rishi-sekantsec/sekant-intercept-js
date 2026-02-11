import "pe"

rule PE_Has_Read_Only_Section {
    meta:
        description = "Test for read-only section"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0 and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) == 0
        )
}