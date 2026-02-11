/*
 * YARA Module Tests
 * Tests for Math, Hash, String, and Time modules
 */

import "math"
import "hash"
import "string"
import "time"

// =============================================================================
// MATH MODULE TESTS
// =============================================================================

rule Math_Entropy_Low {
    meta:
        description = "Test math.entropy() with low entropy data"
    condition:
        math.entropy(0, 100) < 2.0
}

rule Math_Entropy_High {
    meta:
        description = "Test math.entropy() with high entropy data"
    condition:
        math.entropy(500, 100) > 5.0
}

rule Math_Entropy_Full {
    meta:
        description = "Test math.entropy() on full file"
    condition:
        math.entropy(0, filesize) > 3.0
}

rule Math_Mean {
    meta:
        description = "Test math.mean() calculation"
    condition:
        math.mean(0, 10) < 128
}

rule Math_Min {
    meta:
        description = "Test math.min() to find minimum byte value"
    condition:
        math.min(0, filesize) == 0x00
}

rule Math_Max {
    meta:
        description = "Test math.max() to find maximum byte value"
    condition:
        math.max(0, filesize) == 0xFF
}

rule Math_Serial_Correlation {
    meta:
        description = "Test math.serial_correlation()"
    condition:
        math.serial_correlation(0, 100) < 1.0
}

// Monte Carlo Pi not available in Python YARA
// rule Math_Monte_Carlo_Pi {
//     meta:
//         description = "Test math.monte_carlo_pi_estimate()"
//     condition:
//         math.monte_carlo_pi_estimate(100, 200) >= 0.0
// }

rule Math_Deviation_Low {
    meta:
        description = "Test math.deviation() with low deviation data"
    condition:
        math.deviation(0, 100, 128.0) < 100.0
}

// =============================================================================
// HASH MODULE TESTS
// =============================================================================

rule Hash_MD5 {
    meta:
        description = "Test hash.md5() for specific data range"
    condition:
        hash.md5(0, 16) == "3dd0cd797a7399b56c470612887108eb"
}

rule Hash_MD5_Full {
    meta:
        description = "Test hash.md5() for entire file"
    condition:
        hash.md5(0, filesize) != ""
}

rule Hash_SHA1 {
    meta:
        description = "Test hash.sha1() for specific data range"
    condition:
        hash.sha1(0, 16) == "131c471c8b4edf662dd0ebf7adf3c3d7365838b9"
}

rule Hash_SHA256 {
    meta:
        description = "Test hash.sha256() for specific data range"
    condition:
        hash.sha256(0, 16) == "5e8b64da785f1572e6da780648eaaffa009152d297bde80f852f068b0ec2989f"
}

rule Hash_Checksum32 {
    meta:
        description = "Test hash.checksum32() calculation"
    condition:
        hash.checksum32(0, 100) > 0
}

rule Hash_CRC32 {
    meta:
        description = "Test hash.crc32() calculation"
    condition:
        hash.crc32(0, 100) > 0
}

// =============================================================================
// STRING MODULE TESTS
// =============================================================================

rule String_Length {
    meta:
        description = "Test string.length() function"
    condition:
        string.length("hello") == 5
}

rule String_ToInt_Decimal {
    meta:
        description = "Test string.to_int() with decimal string"
    condition:
        string.to_int("12345") == 12345
}

rule String_ToInt_Hex {
    meta:
        description = "Test string.to_int() with hex string"
    condition:
        string.to_int("0x42") == 66
}

rule String_ToInt_Octal {
    meta:
        description = "Test string.to_int() with octal string"
    condition:
        string.to_int("0755", 8) == 493
}

rule String_ToInt_Negative {
    meta:
        description = "Test string.to_int() with negative number"
    condition:
        string.to_int("-100") == -100
}

// =============================================================================
// TIME MODULE TESTS
// =============================================================================

rule Time_Now {
    meta:
        description = "Test time.now() returns a timestamp"
    condition:
        time.now() > 1700000000
}

// =============================================================================
// COMBINED MODULE TESTS
// =============================================================================

rule Combined_Math_And_Hash {
    meta:
        description = "Test combining math and hash modules"
    condition:
        math.entropy(0, 100) < 5.0 and hash.md5(0, filesize) != ""
}

rule Combined_String_Operations {
    meta:
        description = "Test multiple string operations"
    condition:
        string.length("test") == 4 and string.to_int("100") == 100
}

rule Combined_All_Modules {
    meta:
        description = "Test all modules together"
    condition:
        math.entropy(0, 100) >= 0.0 and
        hash.md5(0, 10) != "" and
        string.length("x") == 1 and
        time.now() > 0
}

// =============================================================================
// EDGE CASES
// =============================================================================

rule Math_Entropy_Single_Byte {
    meta:
        description = "Test math.entropy() with single byte"
    condition:
        math.entropy(0, 1) >= 0
}

rule Math_Entropy_Zero_Range {
    meta:
        description = "Test math.entropy() with zero-length range"
    condition:
        math.entropy(10, 10) >= 0
}

rule Hash_Empty_Range {
    meta:
        description = "Test hash with zero-length range"
    condition:
        hash.md5(10, 10) != ""
}

rule String_ToInt_Invalid {
    meta:
        description = "Test string.to_int() with invalid input handles gracefully"
    condition:
        string.to_int("not_a_number") == 0
}

rule Math_Comparison {
    meta:
        description = "Test math functions in comparison"
    condition:
        math.mean(0, 100) != math.mean(100, 200)
}
