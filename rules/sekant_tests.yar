/*
 * YARA Rules for Sekant Module Testing
 * 
 * These rules test the sekant custom module which provides metadata
 * about file downloads including filename, MIME type, URLs, and context.
 */

// Test 1: Basic filename matching
rule SekantBasicFilename
{
    meta:
        description = "Test basic filename field access"
        
    condition:
        sekant.filename == "download_sample1.txt"
}

// Test 2: MIME type detection
rule SekantMimeTypePDF
{
    meta:
        description = "Detect PDF files based on MIME type"
        
    condition:
        sekant.mime == "application/pdf"
}

// Test 3: Download URL matching
rule SekantDownloadURL
{
    meta:
        description = "Match specific download URLs"
        
    condition:
        sekant.downloadUrl == "https://example.com/downloads/file.exe"
}

// Test 4: Unfamiliar site detection
rule SekantUnfamiliarSite
{
    meta:
        description = "Flag downloads from unfamiliar sites"
        
    condition:
        sekant.unfamiliarSite == true
}

// Test 5: Search referral detection
rule SekantSearchReferral
{
    meta:
        description = "Detect files referred by search engines"
        
    condition:
        sekant.referred_by_search == true
}

// Test 6: AI site detection
rule SekantAISite
{
    meta:
        description = "Detect downloads from AI-related sites"
        
    condition:
        sekant.considered_ai_site == true
}

// Test 7: Hosting site detection
rule SekantHostingSite
{
    meta:
        description = "Detect downloads from hosting sites"
        
    condition:
        sekant.considered_hosting_site == true
}

// Test 8: Combined conditions - Suspicious executable
rule SekantSuspiciousExecutable
{
    meta:
        description = "Detect suspicious executable downloads"
        severity = "high"
        
    condition:
        sekant.mime == "application/x-msdownload" and
        sekant.unfamiliarSite == true and
        sekant.filesize < 1000000
}

// Test 9: Phishing detection with URL context
rule SekantPhishingDetection
{
    meta:
        description = "Detect potential phishing based on URL context"
        severity = "critical"
        
    condition:
        sekant.url_context contains "login" and
        sekant.mime == "text/html" and
        sekant.unfamiliarSite == true
}

// Test 10: File size checks
rule SekantLargeDownload
{
    meta:
        description = "Detect large downloads"
        
    condition:
        sekant.filesize > 10000000
}

// Test 11: IP-based download detection
rule SekantIPDownload
{
    meta:
        description = "Detect downloads from IP addresses instead of domains"
        
    condition:
        sekant.ip != ""
}

// Test 12: Referrer analysis
rule SekantReferrerCheck
{
    meta:
        description = "Check referrer information"
        
    condition:
        sekant.referrer contains "google.com"
}

// Test 13: Tab URL matching
rule SekantTabURL
{
    meta:
        description = "Match the tab URL where download originated"
        
    condition:
        sekant.tabUrl contains "example.com"
}

// Test 14: Complex multi-condition rule
rule SekantComplexDetection
{
    meta:
        description = "Complex detection with multiple sekant fields"
        severity = "medium"
        
    condition:
        (sekant.mime == "application/pdf" or 
         sekant.mime == "application/x-msdownload") and
        sekant.filesize < 5000000 and
        (sekant.unfamiliarSite == true or 
         sekant.considered_hosting_site == true) and
        sekant.referred_by_search == false
}

// Test 15: Negative condition testing
rule SekantNotFromSearch
{
    meta:
        description = "Files NOT from search engines"
        
    condition:
        sekant.referred_by_search == false
}

// Test 16: String contains operations
rule SekantURLContains
{
    meta:
        description = "Test URL contains operations"
        
    condition:
        sekant.downloadUrl contains "suspicious" or
        sekant.tabUrl contains "malicious"
}

// Test 17: Empty field detection
rule SekantEmptyIP
{
    meta:
        description = "Detect when IP field is empty"
        
    condition:
        sekant.ip == ""
}

// Test 18: All fields populated check
rule SekantAllFieldsPopulated
{
    meta:
        description = "Verify all fields are populated"
        
    condition:
        sekant.filename != "" and
        sekant.mime != "" and
        sekant.downloadUrl != "" and
        sekant.tabUrl != ""
}

// Test 19: Truthy evaluation - file has metadata
rule SekantHasMetadata
{
    meta:
        description = "Using truthy evaluation to check if metadata exists"
        
    condition:
        sekant.filename and sekant.mime and sekant.downloadUrl
}

// Test 20: Truthy evaluation - file missing metadata
rule SekantMissingMetadata
{
    meta:
        description = "Detect files with missing metadata using falsy evaluation"
        
    condition:
        not sekant.filename or not sekant.mime
}

// Test 21: Truthy boolean check
rule SekantSimpleBooleanCheck
{
    meta:
        description = "Simple truthy check for boolean fields"
        
    condition:
        sekant.unfamiliarSite
}

// Test 22: Complex truthy/falsy logic
rule SekantComplexTruthyLogic
{
    meta:
        description = "Complex logic with truthy/falsy evaluation"
        
    condition:
        (sekant.filename and sekant.mime) and
        (not sekant.ip or sekant.unfamiliarSite)
}
