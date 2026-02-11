rule HexStringTests
{
    strings:
        // Basic hex patterns
        $h1 = { 48 65 6C 6C 6F }  // "Hello"
        $h2 = { 54 45 53 54 }      // "TEST"
        $h3 = { DE AD BE EF }      // Deadbeef
        
        // Wildcards
        $h4 = { 41 ?? 43 }         // A_C (any byte in middle)
        $h5 = { 50 ?? ?? 54 }      // P__T (two wildcards)
        $h6 = { ?? 42 ?? }         // _B_ (wildcards on both sides)
        
        // Jumps
        $h7 = { 41 [1] 43 }        // A[1byte]C
        $h8 = { 41 [2-4] 45 }      // A[2-4bytes]E
        $h9 = { 41 [0-2] 42 }      // A[0-2bytes]B (can be adjacent)
        $h10 = { 58 [1-] 5A }      // X[1+bytes]Z (unbounded)
        
        // Alternation
        $h11 = { ( 41 | 42 | 43 ) }           // A or B or C
        $h12 = { 50 ( 41 | 45 | 49 ) 54 }     // PAT, PET, PIT
        $h13 = { ( 48 65 | 42 79 ) 21 }       // "He!" or "By!"
        
        // Simple hex pattern (nocase not supported on hex in Python YARA)
        $h14 = { 61 62 63 }                   // "abc"
        
        // Complex combinations
        $h15 = { 4D 5A [0-2] ( 90 | 00 ) }    // MZ header with optional bytes
        $h16 = { 50 ?? 54 [1-3] 21 }          // P_T[1-3]!
        $h17 = { ( 41 | 42 ) [2] 45 }         // (A|B)[2bytes]E
        
        // Negation - NOT operator (~)
        $h18 = { F4 23 ~00 62 B4 }            // Exact negation: NOT 0x00
        $h19 = { F4 23 ~?0 62 B4 }            // Masked negation: NOT ?0 (high nibble any, low must not be 0)
        $h20_neg = { 41 ~42 43 }              // A (NOT B) C
        $h21_neg = { 48 65 ~6C 6C 6F }        // He(NOT l)lo - won't match "Hello"
        $h22_neg = { ~00 ~00 ~00 }            // Three consecutive non-null bytes
        $h24_neg = { ~FF 41 42 }              // (NOT 0xFF) AB
        
        // Multiple wildcards and jumps
        $h26 = { ?? ?? 42 45 47 49 4E }       // __BEGIN
        $h27 = { 45 4E 44 ?? ?? }             // END__
        $h28 = { 41 [1-2] 42 [1-2] 43 }       // A[1-2]B[1-2]C
        
        // Long patterns
        $h29 = { 54 68 69 73 20 69 73 20 61 20 6C 6F 6E 67 20 70 61 74 74 65 72 6E }  // "This is a long pattern"
        
        // Single byte patterns
        $h30 = { 58 }                         // Single X
        $h31 = { ?? }                         // Any single byte (matches everything!)
        
        // Repeated patterns
        $h32 = { 41 41 41 }                   // AAA
        $h33 = { 00 00 00 00 }                // Four null bytes
        
        // Mixed case hex notation (should work the same)
        $h34 = { 4d 5a 90 00 }                // Lowercase hex
        $h35 = { 4D 5A 90 00 }                // Uppercase hex (same as h34)
        
        // Byte sequences with special bytes
        $h36 = { 00 01 02 03 04 05 }          // Sequential bytes
        $h37 = { FF FE FD FC }                // High bytes
        $h38 = { 0A 0D 00 }                   // LF CR NULL
        
        // Wildcard ranges (note: [0] not supported in Python YARA, removed h33)
        $h39 = { 41 [5-10] 42 }               // A[5-10bytes]B
        $h40 = { 41 [10-] 42 }                // A[10+bytes]B (at least 10)
        
        // Complex alternations
        $h41 = { ( 41 42 | 43 44 | 45 46 ) }  // AB or CD or EF
        $h42 = { 50 ( 41 | 42 | 43 | 44 | 45 ) 54 }  // P[A-E]T (5 options)
        
        // Nested patterns
        $h43 = { 41 ( 42 | ( 43 44 ) ) 45 }   // A(B|CD)E
        $h44 = { ( 41 | 42 ) ?? ( 43 | 44 ) } // (A|B)_(C|D)
        
        // Edge cases (note: [0-0] not supported in Python YARA, removed h40)
        $h45 = { ( 41 ) }                     // Single byte in alternation
        
        // Common file signatures
        $h46 = { 25 50 44 46 }                // PDF header "%PDF"
        $h47 = { 50 4B 03 04 }                // ZIP header
        $h48 = { 89 50 4E 47 0D 0A 1A 0A }    // PNG signature
        $h49 = { FF D8 FF }                   // JPEG header
        
        // Shellcode-like patterns
        $h50 = { 55 89 E5 }                   // x86 function prologue
        $h51 = { 90 90 90 }                   // NOP sled
        $h52 = { 5F 5E 5D C3 }                // x86 function epilogue
        
        // Embedded strings in hex
        $h53 = { 2F 62 69 6E 2F 73 68 00 }    // "/bin/sh\0"
        $h54 = { 52 4F 4F 54 }                // "ROOT"

    condition:
        any of them
}
