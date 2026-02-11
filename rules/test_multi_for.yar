import "pe"

rule Test_Multi_For {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text"
        ) and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data"
        )
}
