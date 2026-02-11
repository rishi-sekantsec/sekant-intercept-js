rule LiteralStringVariations
{
    meta:
        description = "Test every variation and modifier of literal strings in YARA"
        author = "GitHub Copilot"
        date = "2024"
    
    strings:
        // Basic literal string
        $a1 = "basic string"
        
        // Case insensitive
        $a2 = "case insensitive" nocase
        
        // Wide strings (UTF-16)
        $a3 = "wide string" wide
        
        // Wide + nocase
        $a4 = "wide nocase" wide nocase
        
        // ASCII strings (explicit)
        $a5 = "ascii string" ascii
        
        // ASCII + nocase
        $a6 = "ascii nocase" ascii nocase
        
        // ASCII + wide (both encodings)
        $a7 = "ascii and wide" ascii wide
        
        // ASCII + wide + nocase
        $a8 = "all modifiers" ascii wide nocase
        
        // XOR modifier (single byte)
        $a9 = "xor string" xor
        
        // XOR with range
        $a10 = "xor range" xor(1-255)
        
        // XOR + nocase
        // $a11 = "xor nocase" xor nocase
        
        // XOR + wide
        $a12 = "xor wide" xor wide
        
        // Base64 modifier
        $a13 = "base64 string" base64
        
        // Base64 wide
        $a14 = "base64 wide" base64wide
        
        // Base64 with custom alphabet
        // $a15 = "custom base64" base64("!@#$%^&*(){}[]ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        
        // Fullword modifier
        $a16 = "fullword" fullword
        
        // Fullword + nocase
        $a17 = "fullword nocase" fullword nocase
        
        // Private strings (not counted in rule match)
        $a18 = "private string" private
        
        // Escaped characters tests
        // Double quote escape
        $e1 = "text with \"quotes\" inside"
        
        // Backslash escape (use hex notation to avoid ambiguity)
        $e2 = "path\x5cto\x5cfile"  // \x5c = backslash
        
        // Carriage return
        $e3 = "line1\rline2"
        
        // Horizontal tab
        $e4 = "col1\tcol2\tcol3"
        
        // Newline
        $e5 = "first line\nsecond line"
        
        // Hexadecimal byte notation
        $e6 = "start\x41\x42\x43end"  // ABC in hex
        
        // Multiple escapes combined
        $e7 = "complex\t\"test\"\nwith\\escapes"
        
        // Tab with nocase
        $e8 = "data\tseparated" nocase
        
        // Fullword with special character boundary
        $e9 = "boundary" fullword
        
        // Hex bytes forming readable text
        $e10 = "\x48\x65\x6c\x6c\x6f"  // "Hello"
        
    condition:
        any of them
}