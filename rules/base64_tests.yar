rule Base64ComprehensiveTests
{
    meta:
        description = "Comprehensive base64 and base64wide tests for comparing implementations"
        author = "GitHub Copilot"
        date = "2024"
    
    strings:
        // Test 1: Simple ASCII base64
        $b1 = "hello world" base64
        
        // Test 2: Base64 with special characters
        $b2 = "test@123!" base64
        
        // Test 3: Short string base64
        $b3 = "ABC" base64
        
        // Test 4: Longer string base64
        $b4 = "The quick brown fox jumps over the lazy dog" base64
        
        // Test 5: Base64 standard encoding
        $b5 = "CaseSensitive" base64
        
        // Test 6: Base64wide (UTF-16 LE then base64)
        $b6 = "wide test" base64wide
        
        // Test 7: Numbers and symbols
        $b7 = "12345!@#$%" base64
        
        // Test 8: Single character
        $b8 = "X" base64
        
        // Test 9: URL-like string
        $b9 = "https://example.com/path" base64
        
        // Test 10: Mixed case original (base64 encodes as-is)
        $b10 = "MiXeD CaSe" base64

        $b11 = "This program cannot" base64
        
    condition:
        any of them
}
