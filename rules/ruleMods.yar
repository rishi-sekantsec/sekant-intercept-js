// Test rule modifiers, tags, and metadata

// Basic rule with no modifiers
rule BasicRule
{
    strings:
        $s1 = "basic"
    condition:
        $s1
}

// Private rule (should not appear in results)
private rule PrivateRule
{
    strings:
        $s1 = "private"
    condition:
        $s1
}

// Global rule (should always be evaluated)
global rule GlobalRule
{
    strings:
        $s1 = "global"
    condition:
        $s1
}

// Private global rule (should not appear in results but always evaluated)
private global rule PrivateGlobalRule
{
    strings:
        $s1 = "privateglobal"
    condition:
        $s1
}

// Rule with single tag
rule SingleTagRule : tag1
{
    strings:
        $s1 = "singletag"
    condition:
        $s1
}

// Rule with multiple tags
rule MultipleTagsRule : tag1 tag2 tag3
{
    strings:
        $s1 = "multipletags"
    condition:
        $s1
}

// Rule with metadata
rule MetadataRule
{
    meta:
        author = "Test Author"
        description = "Test description"
        version = "1.0"
        
    strings:
        $s1 = "metadata"
    condition:
        $s1
}

// Rule with metadata and tags
rule MetadataTagsRule : malware trojan
{
    meta:
        author = "Security Researcher"
        date = "2025-11-16"
        severity = "high"
        reference = "https://example.com/analysis"
        
    strings:
        $s1 = "metadatatags"
    condition:
        $s1
}

// Private rule with metadata and tags (should not appear in results)
private rule PrivateMetadataTagsRule : tag1 tag2
{
    meta:
        author = "Private Author"
        internal = true
        
    strings:
        $s1 = "privatemetatags"
    condition:
        $s1
}

// Rule with various metadata types
rule VariousMetadataTypesRule
{
    meta:
        string_value = "text"
        integer_value = 42
        boolean_value = true
        negative_int = -100
        
    strings:
        $s1 = "variousmeta"
    condition:
        $s1
}

// Rule with empty strings (should still match)
rule EmptyStringsRule : test
{
    meta:
        description = "Tests empty condition"
        
    condition:
        true
}

// Rule that depends on another rule
rule DependentRule
{
    meta:
        depends_on = "BasicRule"
        
    strings:
        $s1 = "dependent"
    condition:
        BasicRule and $s1
}

// Global rule with tags and metadata
global rule GlobalTagsMetaRule : system critical
{
    meta:
        author = "System"
        always_check = true
        priority = 1
        
    strings:
        $s1 = "globaltagsmeta"
    condition:
        $s1
}

// Rule with special characters in metadata
rule SpecialCharsMetaRule
{
    meta:
        description = "Special chars: \" \\ / \n \t"
        unicode_text = "Hello 世界 🌍"
        path = "C:\\Windows\\System32"
        
    strings:
        $s1 = "specialmeta"
    condition:
        $s1
}

// Rule with many tags
rule ManyTagsRule : tag1 tag2 tag3 tag4 tag5 tag6 tag7 tag8 tag9 tag10
{
    meta:
        tag_count = 10
        
    strings:
        $s1 = "manytags"
    condition:
        $s1
}

// Rule referencing a private rule (private rules can still be used in conditions)
rule UsesPrivateRule
{
    meta:
        uses = "PrivateRule"
        
    strings:
        $s1 = "usesprivate"
    condition:
        PrivateRule and $s1
}

// Rule with no strings, only condition
rule NoStringsRule : utility
{
    meta:
        type = "utility"
        has_strings = false
        
    condition:
        true
}

// Rule with metadata containing numbers
rule NumericMetadataRule
{
    meta:
        version_major = 2
        version_minor = 5
        version_patch = 10
        confidence = 95
        weight = 100
        
    strings:
        $s1 = "numericmeta"
    condition:
        $s1
}

// Private rule with only condition (should not appear)
private rule PrivateConditionOnlyRule
{
    meta:
        hidden = true
        
    condition:
        false
}

// Rule with URL in metadata
rule URLMetadataRule : reference
{
    meta:
        url = "https://github.com/example/repo"
        cve = "CVE-2024-12345"
        mitre_attack = "T1234"
        
    strings:
        $s1 = "urlmeta"
    condition:
        $s1
}

// Rule testing all combinations
rule AllFeaturesRule : feature_test production
{
    meta:
        author = "Comprehensive Test"
        description = "Tests all features together"
        version = "2.0"
        date = "2025-11-16"
        severity = "medium"
        confidence = 85
        tested = true
        
    strings:
        $s1 = "allfeatures"
        $s2 = "complete"
    condition:
        any of them
}

// Global private rule with everything (should not appear but always evaluated)
private global rule HiddenGlobalRule : hidden internal
{
    meta:
        visibility = "none"
        purpose = "background check"
        
    strings:
        $s1 = "hiddenglobal"
    condition:
        $s1
}
