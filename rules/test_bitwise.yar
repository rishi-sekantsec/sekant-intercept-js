import "pe"

rule Test_Bitwise_Read {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0
        )
}

rule Test_Bitwise_Write_Zero {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) == 0
        )
}

rule Test_Combined {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_READ) != 0 and
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) == 0
        )
}
