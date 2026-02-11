// Test Comment
/* This is a multi
line
Comment
 ... * * *
 test
 */ 
rule BasicStringMatching
{
    meta:
        description = "Simple YARA rule demonstrating different string types"
        author = "Test"
    
    strings:
        // Literal string matching
        $literal = "MALWARE" ascii wide nocase
        
        // Regular expression matching
        $regex = /[A-Z]{3}-\d{4}-[A-Z]{2}/ ascii
        
        // Hexadecimal pattern matching
        $hex = { 4D 5A 90 00 ?? ?? ?? ?? [4-6] E8 }
    
    condition:
        any of them
}