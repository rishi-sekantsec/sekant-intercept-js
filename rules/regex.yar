rule ComprehensiveRegexTests
{
    meta:
        description = "Comprehensive regex pattern tests for YARA compatibility"
        author = "GitHub Copilot"
        date = "2024"
    
    strings:
        // Basic character classes
        $r1 = /[0-9]+/              // One or more digits
        $r2 = /[a-z]+/              // One or more lowercase letters
        $r3 = /[A-Z]+/              // One or more uppercase letters
        $r4 = /[a-zA-Z]+/           // One or more letters (any case)
        $r5 = /[a-zA-Z0-9]+/        // Alphanumeric
        
        // Quantifiers
        $r6 = /test?/               // Zero or one 't'
        $r7 = /test*/               // Zero or more 't'
        $r8 = /test+/               // One or more 't'
        $r9 = /test{3}/             // Exactly 3 't's
        $r10 = /test{2,4}/          // Between 2 and 4 't's
        $r11 = /test{2,}/           // At least 2 't's
        
        // Anchors and boundaries
        $r12 = /^start/             // Start of buffer/line
        $r13 = /end$/               // End of buffer/line
        $r14 = /\bword\b/           // Word boundaries
        
        // Special characters
        $r15 = /\d+/                // Digits (\d = [0-9])
        $r16 = /\w+/                // Word characters (\w = [a-zA-Z0-9_])
        $r17 = /\s+/                // Whitespace
        $r18 = /\D+/                // Non-digits
        $r19 = /\W+/                // Non-word characters
        $r20 = /\S+/                // Non-whitespace
        
        // Alternation and grouping
        $r21 = /(cat|dog|bird)/     // Alternation
        $r22 = /(red|blue) car/     // Grouped alternation
        $r23 = /gr(a|e)y/           // Gray or grey
        
        // Dot metacharacter
        $r24 = /a.b/                // Any character between a and b
        $r25 = /a.*b/               // Any characters (greedy)
        $r26 = /a.+b/               // One or more characters
        
        // Character escapes
        $r27 = /\./                 // Literal dot
        $r28 = /\*/                 // Literal asterisk
        $r29 = /\+/                 // Literal plus
        $r30 = /\?/                 // Literal question mark
        $r31 = /\[/                 // Literal bracket
        $r32 = /\]/                 // Literal bracket
        $r33 = /\(/                 // Literal parenthesis
        $r34 = /\)/                 // Literal parenthesis
        $r35 = /\\/                 // Literal backslash
        
        // Character class negation
        $r36 = /[^0-9]+/            // Not digits
        $r37 = /[^a-z]+/            // Not lowercase
        
        // Complex patterns
        $r38 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/  // IPv4-like
        $r39 = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/  // Email-like
        $r40 = /https?:\/\/[^\s]+/  // URL pattern
        
        // Regex with modifiers
        $r41 = /pattern/i           // Case insensitive
        $r42 = /multi line/s        // Dot matches newline
        
        // Hex in regex
        $r43 = /\x41\x42\x43/       // ABC in hex
        $r44 = /test\x20data/       // Space as \x20
        
        // Mixed content
        $r45 = /version\s+\d+\.\d+\.\d+/  // Version number
        $r46 = /error:\s*.*/              // Error message
        $r47 = /(\w+)=(\w+)/              // Key=value pairs
        
        // Greedy vs non-greedy
        $r48 = /a.*?b/              // Non-greedy
        $r49 = /a.+?b/              // Non-greedy one or more
        
        // Optional groups
        $r50 = /(https?:\/\/)?example\.com/  // Optional protocol
        
    condition:
        any of them
}
