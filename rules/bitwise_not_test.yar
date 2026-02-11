rule BitwiseNot_Simple {
    meta:
        description = "Test ~0 == -1"
    condition:
        ~0 == -1
}

rule BitwiseNot_Positive {
    meta:
        description = "Test ~5 == -6"
    condition:
        ~5 == -6
}

rule BitwiseNot_Hex {
    meta:
        description = "Test ~0xAA == -171"
    condition:
        ~0xAA == -171
}

rule BitwiseNot_Double {
    meta:
        description = "Test ~~5 == 5"
    condition:
        ~~5 == 5
}

rule BitwiseNot_DataAccess {
    meta:
        description = "Test ~uint8(4) with byte 0xAA at offset 4 (no parens needed!)"
    condition:
        ~uint8(4) == -171
}

rule BitwiseNot_Comparison {
    meta:
        description = "Test ~0x55 < 0"
    condition:
        ~0x55 < 0
}

rule BitwiseNot_Combined {
    meta:
        description = "Test (~0xAA) & 0xFF == 0x55"
    condition:
        (~0xAA) & 0xFF == 0x55
}

rule BitwiseNot_Arithmetic {
    meta:
        description = "Test ~5 + 10 == 4"
    condition:
        ~5 + 10 == 4
}
