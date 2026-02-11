// Comprehensive YARA Condition Grammar Test Suite
// Tests all supported condition matching features

// ===================================================================
// Section 1: Basic String Identifiers
// ===================================================================

rule StringIdentifier_Single
{
    strings:
        $a = "apple"
    condition:
        $a
}

rule StringIdentifier_Multiple
{
    strings:
        $a = "banana"
        $b = "cherry"
    condition:
        $a and $b
}

rule StringIdentifier_Or
{
    strings:
        $a = "dog"
        $b = "cat"
    condition:
        $a or $b
}

rule StringIdentifier_Not
{
    strings:
        $a = "elephant"
        $b = "mouse"
    condition:
        $a and not $b
}

// ===================================================================
// Section 2: Quantifiers - "of them"
// ===================================================================

rule Quantifier_AnyOfThem
{
    strings:
        $s1 = "one"
        $s2 = "two"
        $s3 = "three"
    condition:
        any of them
}

rule Quantifier_AllOfThem
{
    strings:
        $s1 = "alpha"
        $s2 = "beta"
        $s3 = "gamma"
    condition:
        all of them
}

rule Quantifier_NoneOfThem
{
    strings:
        $s1 = "absent1"
        $s2 = "absent2"
        $s3 = "absent3"
    condition:
        none of them
}

rule Quantifier_TwoOfThem
{
    strings:
        $s1 = "red"
        $s2 = "green"
        $s3 = "blue"
        $s4 = "yellow"
    condition:
        2 of them
}

rule Quantifier_PercentOfThem
{
    strings:
        $s1 = "first"
        $s2 = "second"
        $s3 = "third"
        $s4 = "fourth"
    condition:
        50% of them
}

// ===================================================================
// Section 3: Quantifiers - "of" with sets
// ===================================================================

rule Quantifier_AnyOfSet
{
    strings:
        $a = "lion"
        $b = "tiger"
        $c = "bear"
    condition:
        any of ($a, $b, $c)
}

rule Quantifier_AllOfSet
{
    strings:
        $a = "sun"
        $b = "moon"
        $c = "star"
    condition:
        all of ($a, $b, $c)
}

rule Quantifier_TwoOfSet
{
    strings:
        $a = "mercury"
        $b = "venus"
        $c = "earth"
        $d = "mars"
    condition:
        2 of ($a, $b, $c, $d)
}

// ===================================================================
// Section 4: Match Count (#a)
// ===================================================================

rule MatchCount_Equals
{
    strings:
        $a = "repeat"
    condition:
        #a == 2
}

rule MatchCount_GreaterThan
{
    strings:
        $a = "many"
    condition:
        #a > 1
}

rule MatchCount_LessThan
{
    strings:
        $a = "few"
    condition:
        #a < 5
}

rule MatchCount_Range
{
    strings:
        $a = "count"
    condition:
        #a >= 2 and #a <= 4
}

// ===================================================================
// Section 5: Match Offset (@a)
// ===================================================================

rule MatchOffset_AtZero
{
    strings:
        $a = "header"
    condition:
        $a at 0
}

rule MatchOffset_AtSpecific
{
    strings:
        $a = "middle"
    condition:
        $a at 100
}

rule MatchOffset_InRange
{
    strings:
        $a = "range"
    condition:
        $a in (0..50)
}

rule MatchOffset_FirstOffset
{
    strings:
        $a = "offset"
    condition:
        @a == 10
}

rule MatchOffset_IndexedOffset
{
    strings:
        $a = "indexed"
    condition:
        @a[1] == 20
}

// ===================================================================
// Section 6: Match Length (!a)
// ===================================================================

rule MatchLength_Equals
{
    strings:
        $a = "length"
    condition:
        !a == 6
}

rule MatchLength_GreaterThan
{
    strings:
        $a = /long\w+/
    condition:
        !a > 5
}

// ===================================================================
// Section 7: Logical Operators
// ===================================================================

rule Logical_And
{
    strings:
        $a = "both"
        $b = "present"
    condition:
        $a and $b
}

rule Logical_Or
{
    strings:
        $a = "either"
        $b = "or"
    condition:
        $a or $b
}

rule Logical_Not
{
    strings:
        $a = "yes"
        $b = "no"
    condition:
        $a and not $b
}

rule Logical_Complex
{
    strings:
        $a = "complex"
        $b = "logic"
        $c = "test"
    condition:
        ($a or $b) and not $c
}

// ===================================================================
// Section 8: Comparison Operators
// ===================================================================

rule Comparison_Equals
{
    strings:
        $a = "equal"
    condition:
        #a == 1
}

rule Comparison_NotEquals
{
    strings:
        $a = "notequal"
    condition:
        #a != 0
}

rule Comparison_GreaterThan
{
    strings:
        $a = "greater"
    condition:
        #a > 0
}

rule Comparison_LessThan
{
    strings:
        $a = "less"
    condition:
        $a and filesize < 10000
}

rule Comparison_GreaterOrEqual
{
    strings:
        $a = "gte"
    condition:
        #a >= 1
}

rule Comparison_LessOrEqual
{
    strings:
        $a = "lte"
    condition:
        #a <= 10
}

// ===================================================================
// Section 9: Arithmetic Operators
// ===================================================================

rule Arithmetic_Addition
{
    strings:
        $a = "add"
    condition:
        #a + 5 == 6
}

rule Arithmetic_Subtraction
{
    strings:
        $a = "subtract"
    condition:
        #a - 1 == 0
}

rule Arithmetic_Multiplication
{
    strings:
        $a = "multiply"
    condition:
        #a * 2 == 2
}

rule Arithmetic_Division
{
    strings:
        $a = "divide"
    condition:
        $a and filesize \ 100 > 0
}

rule Arithmetic_Modulo
{
    strings:
        $a = "modulo"
    condition:
        #a % 2 == 1
}

// ===================================================================
// Section 10: Bitwise Operators
// ===================================================================

rule Bitwise_And
{
    condition:
        uint8(0) & 0x80 == 0x80
}

rule Bitwise_Or
{
    condition:
        uint8(0) | 0x01 == 0x4D
}

rule Bitwise_Xor
{
    condition:
        uint8(0) ^ 0xFF == 0xB2
}

rule Bitwise_Not
{
    condition:
        ~uint8(0) & 0xFF == 0xB2
}

rule Bitwise_ShiftLeft
{
    condition:
        uint8(0) << 1 == 0x9A
}

rule Bitwise_ShiftRight
{
    condition:
        uint8(0) >> 1 == 0x26
}

// ===================================================================
// Section 11: Boolean Literals
// ===================================================================

rule Boolean_True
{
    condition:
        true
}

rule Boolean_False
{
    condition:
        false
}

rule Boolean_Expression
{
    strings:
        $a = "bool"
    condition:
        $a and true
}

// ===================================================================
// Section 12: Filesize
// ===================================================================

rule Filesize_Exact
{
    condition:
        filesize == 500
}

rule Filesize_Range
{
    condition:
        filesize > 100 and filesize < 1000
}

rule Filesize_WithString
{
    strings:
        $a = "size"
    condition:
        $a and filesize > 0
}

// ===================================================================
// Section 13: Entrypoint
// ===================================================================

rule Entrypoint_AtEntry
{
    strings:
        $a = "MZ"
    condition:
        $a at entrypoint
}

rule Entrypoint_InRange
{
    strings:
        $a = "entry"
    condition:
        $a in (entrypoint..entrypoint+100)
}

// ===================================================================
// Section 14: Data Access (uint8, uint16, uint32)
// ===================================================================

rule DataAccess_Uint8
{
    condition:
        uint8(0) == 0x4D
}

rule DataAccess_Uint16
{
    condition:
        uint16(0) == 0x5A4D
}

rule DataAccess_Uint32
{
    condition:
        uint32(0) == 0x00004D5A
}

rule DataAccess_Int8
{
    condition:
        int8(10) > 0
}

rule DataAccess_Int16
{
    condition:
        int16(10) > 0
}

rule DataAccess_Int32
{
    condition:
        int32(10) > 0
}

// ===================================================================
// Section 15: For Loops
// ===================================================================

rule ForLoop_AllOfThem
{
    strings:
        $a = "for1"
        $b = "for2"
        $c = "for3"
    condition:
        for all of them : ( # > 0 )
}

rule ForLoop_AnyOfThem
{
    strings:
        $a = "any1"
        $b = "any2"
        $c = "any3"
    condition:
        for any of them : ( # > 0 )
}

rule ForLoop_Range
{
    condition:
        for all i in (0..10) : ( uint8(i) > 0 )
}

// ===================================================================
// Section 16: Parentheses and Precedence
// ===================================================================

rule Precedence_Simple
{
    strings:
        $a = "prec1"
        $b = "prec2"
        $c = "prec3"
    condition:
        $a and $b or $c
}

rule Precedence_Parentheses
{
    strings:
        $a = "paren1"
        $b = "paren2"
        $c = "paren3"
    condition:
        $a and ($b or $c)
}

rule Precedence_Nested
{
    strings:
        $a = "nest1"
        $b = "nest2"
        $c = "nest3"
        $d = "nest4"
    condition:
        ($a or $b) and ($c or $d)
}

// ===================================================================
// Section 17: Dependent Rules (Commented out - not standard YARA)
// ===================================================================

// rule BaseRule_ForDependency
// {
//     strings:
//         $a = "dependency"
//     condition:
//         $a
// }

// rule DependentRule_UsesBase
// {
//     strings:
//         $b = "dependent"
//     condition:
//         BaseRule_ForDependency and $b
// }

// ===================================================================
// Section 18: Complex Combined Conditions
// ===================================================================

rule Complex_StringsAndCounts
{
    strings:
        $a = "complex1"
        $b = "complex2"
        $c = "complex3"
    condition:
        #a >= 1 and (#b > 0 or #c > 0) and filesize < 10000
}

rule Complex_OffsetsAndRanges
{
    strings:
        $a = "offsets"
        $b = "ranges"
    condition:
        $a at 0 and $b in (50..150)
}

rule Complex_AllFeatures
{
    strings:
        $a = "everything"
        $b = "together"
    condition:
        ($a at 0 or @a < 100) and 
        #b > 0 and 
        filesize > 100 and 
        uint8(0) == 0x4D
}
