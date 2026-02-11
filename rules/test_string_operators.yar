import "pe"

rule Test_Contains_text {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name contains "text"
        )
}

rule Test_Contains_data {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name contains "data"
        )
}

rule Test_StartsWith {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name startswith "."
        )
}

rule Test_EndsWith_text {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name endswith "text"
        )
}

rule Test_EndsWith_data {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name endswith "data"
        )
}

rule Test_IContains_TEXT {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name icontains "TEXT"
        )
}

rule Test_IContains_DATA {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name icontains "DATA"
        )
}

rule Test_IStartsWith {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name istartswith "."
        )
}

rule Test_IEndsWith_TEXT {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name iendswith "TEXT"
        )
}

rule Test_IEndsWith_DATA {
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name iendswith "DATA"
        )
}
