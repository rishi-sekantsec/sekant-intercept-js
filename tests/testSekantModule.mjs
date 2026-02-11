/**
 * Comprehensive test suite for YARA Sekant Module
 * 
 * Tests the sekant custom module which provides metadata about file downloads:
 * - filename: Name of the downloaded file
 * - mime: MIME type of the file
 * - file_size: Size of the file in bytes
 * - download_url: URL from which the file was downloaded
 * - tab_url: URL of the tab where download was initiated
 * - unfamiliar_site: Boolean indicating if site is unfamiliar
 * - url_context: Context information about the URL
 * - ip: IP address if download is from IP instead of domain
 * - referrer: HTTP referrer header
 * - referred_by_search: Boolean indicating if referred by search engine
 * - considered_ai_site: Boolean indicating if site is AI-related
 * - considered_hosting_site: Boolean indicating if site is a hosting service
 */

import { readFileSync } from 'fs';
import { YaraScanner } from '../yaraScanner.mjs';
import { SekantYaraModule } from '../yaraSekantModule.mjs';
import {
  numberedTest as test,
  assertEquals,
  assertTrue,
  assertFalse,
  printSummary
} from './testingFramework.mjs';

console.log('='.repeat(70));
console.log('YARA Sekant Module - Comprehensive Test Suite');
console.log('='.repeat(70));

// Helper to load test files
function loadTestFile(filename) {
  return readFileSync(`test_files/${filename}`);
}

// Helper to transform scanner results into expected format
function transformResults(resultsArray) {
  return {
    matchedRules: resultsArray.map(r => r.rule),
    results: resultsArray
  };
}

// =============================================================================
// Section 1: Basic Field Access Tests
// =============================================================================
console.log('\n📦 Section 1: Basic Field Access');

await test('1.1: Access filename field', async () => {
  const rules = `
    rule TestFilename {
      condition:
        sekant.filename == "sample.txt"
    }
  `;
  
  const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
  
  const metadata = {
    filename: "sample.txt",
    mime: "text/plain",
    file_size: 5
  };
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestFilename'));
});

await test('1.2: Access MIME type field', async () => {
  const rules = `
    rule TestMime {
      condition:
        sekant.mime == "application/pdf"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "document.pdf",
    mime: "application/pdf",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestMime'));
});

await test('1.3: Access filesize field', async () => {
  const rules = `
    rule TestFilesize {
      condition:
        sekant.file_size > 0 and sekant.file_size < 10000
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "sample.txt",
    mime: "text/plain",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestFilesize'));
});

await test('1.4: Access downloadUrl field', async () => {
  const rules = `
    rule TestDownloadUrl {
      condition:
        sekant.download_url == "https://example.com/file.exe"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "file.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    download_url: "https://example.com/file.exe"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestDownloadUrl'));
});

await test('1.5: Access tabUrl field', async () => {
  const rules = `
    rule TestTabUrl {
      condition:
        sekant.tab_url contains "example.com"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "sample.txt",
    mime: "text/plain",
    file_size: data.length,
    tab_url: "https://example.com/page.html"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestTabUrl'));
});

// =============================================================================
// Section 2: Boolean Field Tests
// =============================================================================
console.log('\n📦 Section 2: Boolean Field Tests');

await test('2.1: Test unfamiliarSite true condition', async () => {
  const rules = `
    rule TestUnfamiliarSite {
      condition:
        sekant.unfamiliar_site == true
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "suspicious.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    unfamiliar_site: true
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestUnfamiliarSite'));
});

await test('2.2: Test unfamiliarSite false condition', async () => {
  const rules = `
    rule TestFamiliarSite {
      condition:
        sekant.unfamiliar_site == false
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "trusted.txt",
    mime: "text/plain",
    file_size: data.length,
    unfamiliar_site: false
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestFamiliarSite'));
});

await test('2.3: Test referred_by_search field', async () => {
  const rules = `
    rule TestSearchReferral {
      condition:
        sekant.referred_by_search == true
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample4.json');
  
  const metadata = {
    filename: "config.json",
    mime: "application/json",
    file_size: data.length,
    referred_by_search: true,
    referrer: "https://google.com/search"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestSearchReferral'));
});

await test('2.4: Test considered_ai_site field', async () => {
  const rules = `
    rule TestAISite {
      condition:
        sekant.considered_ai_site == true
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "ai_generated.txt",
    mime: "text/plain",
    file_size: data.length,
    considered_ai_site: true,
    download_url: "https://chatgpt.com/download"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestAISite'));
});

await test('2.5: Test considered_hosting_site field', async () => {
  const rules = `
    rule TestHostingSite {
      condition:
        sekant.considered_hosting_site == true
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "shared_file.pdf",
    mime: "application/pdf",
    file_size: data.length,
    considered_hosting_site: true,
    download_url: "https://dropbox.com/s/xyz/file.pdf"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestHostingSite'));
});

// =============================================================================
// Section 3: String Operations (contains, ==, !=)
// =============================================================================
console.log('\n📦 Section 3: String Operations');

await test('3.1: URL contains operation', async () => {
  const rules = `
    rule TestUrlContains {
      condition:
        sekant.download_url contains "download"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample5.html');
  
  const metadata = {
    filename: "page.html",
    mime: "text/html",
    file_size: data.length,
    download_url: "https://example.com/downloads/page.html"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestUrlContains'));
});

await test('3.2: Referrer contains operation', async () => {
  const rules = `
    rule TestReferrerContains {
      condition:
        sekant.referrer contains "google"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "result.txt",
    mime: "text/plain",
    file_size: data.length,
    referrer: "https://www.google.com/search?q=test"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestReferrerContains'));
});

await test('3.3: url_context contains operation', async () => {
  const rules = `
    rule TestUrlContext {
      condition:
        sekant.url_context contains "login"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample5.html');
  
  const metadata = {
    filename: "login_page.html",
    mime: "text/html",
    file_size: data.length,
    url_context: "login_form_detected"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestUrlContext'));
});

await test('3.4: IP field not empty', async () => {
  const rules = `
    rule TestIPPresent {
      condition:
        sekant.ip != ""
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "suspicious.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    ip: "192.168.1.100",
    download_url: "http://192.168.1.100/malware.exe"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestIPPresent'));
});

await test('3.5: IP field empty', async () => {
  const rules = `
    rule TestNoIP {
      condition:
        sekant.ip == ""
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "normal.txt",
    mime: "text/plain",
    file_size: data.length,
    download_url: "https://example.com/file.txt"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestNoIP'));
});

// =============================================================================
// Section 4: Complex Compound Conditions
// =============================================================================
console.log('\n📦 Section 4: Complex Compound Conditions');

await test('4.1: Suspicious executable detection', async () => {
  const rules = `
    rule SuspiciousExecutable {
      condition:
        sekant.mime == "application/x-msdownload" and
        sekant.unfamiliar_site == true and
        sekant.file_size < 1000000
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "update.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    unfamiliar_site: true,
    download_url: "https://unknown-site.xyz/update.exe"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('SuspiciousExecutable'));
});

await test('4.2: Phishing page detection', async () => {
  const rules = `
    rule PhishingDetection {
      condition:
        sekant.mime == "text/html" and
        sekant.unfamiliar_site == true and
        sekant.url_context contains "credentials"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample5.html');
  
  const metadata = {
    filename: "login.html",
    mime: "text/html",
    file_size: data.length,
    unfamiliar_site: true,
    url_context: "credentials_form_detected"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('PhishingDetection'));
});

await test('4.3: OR conditions with multiple MIME types', async () => {
  const rules = `
    rule DocumentDownload {
      condition:
        (sekant.mime == "application/pdf" or 
         sekant.mime == "application/msword" or
         sekant.mime == "application/json") and
        sekant.file_size > 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample4.json');
  
  const metadata = {
    filename: "data.json",
    mime: "application/json",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('DocumentDownload'));
});

await test('4.4: Combined URL and site analysis', async () => {
  const rules = `
    rule HostedMalware {
      condition:
        sekant.considered_hosting_site == true and
        sekant.unfamiliar_site == false and
        (sekant.mime == "application/x-msdownload" or
         sekant.mime == "application/x-executable")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "tool.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    considered_hosting_site: true,
    unfamiliar_site: false,
    download_url: "https://github.com/user/repo/releases/tool.exe"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('HostedMalware'));
});

await test('4.5: Search engine referral with unfamiliar site', async () => {
  const rules = `
    rule SearchEngineUnfamiliar {
      condition:
        sekant.referred_by_search == true and
        sekant.unfamiliar_site == true and
        sekant.referrer contains "search"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "result.pdf",
    mime: "application/pdf",
    file_size: data.length,
    referred_by_search: true,
    unfamiliar_site: true,
    referrer: "https://google.com/search?q=free+pdf"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('SearchEngineUnfamiliar'));
});

// =============================================================================
// Section 5: Edge Cases and Boundary Conditions
// =============================================================================
console.log('\n📦 Section 5: Edge Cases and Boundary Conditions');

await test('5.1: Missing optional fields', async () => {
  const rules = `
    rule MinimalMetadata {
      condition:
        sekant.filename != "" and
        sekant.mime != ""
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "minimal.txt",
    mime: "text/plain",
    file_size: data.length
    // No optional fields provided
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('MinimalMetadata'));
});

await test('5.2: Empty string values', async () => {
  const rules = `
    rule EmptyFields {
      condition:
        sekant.ip == "" and
        sekant.referrer == ""
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "test.txt",
    mime: "text/plain",
    file_size: data.length,
    ip: "",
    referrer: ""
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('EmptyFields'));
});

await test('5.3: Zero filesize', async () => {
  const rules = `
    rule ZeroSize {
      condition:
        sekant.file_size == 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = new Uint8Array([]);
  
  const metadata = {
    filename: "empty.txt",
    mime: "text/plain",
    file_size: 0
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('ZeroSize'));
});

await test('5.4: Very long URL', async () => {
  const longUrl = "https://example.com/" + "a".repeat(2000) + "/file.exe";
  
  const rules = `
    rule LongURL {
      condition:
        sekant.download_url contains "aaaaaa"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "file.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    download_url: longUrl
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('LongURL'));
});

await test('5.5: Special characters in filename', async () => {
  const rules = `
    rule SpecialCharsFilename {
      condition:
        sekant.filename contains "file (1).txt"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "file (1).txt",
    mime: "text/plain",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('SpecialCharsFilename'));
});

// =============================================================================
// Section 6: Realistic Scenario Tests
// =============================================================================
console.log('\n📦 Section 6: Realistic Scenario Tests');

await test('6.1: Legitimate file from trusted source', async () => {
  const rules = `
    rule TrustedDownload {
      condition:
        sekant.unfamiliar_site == false and
        sekant.referred_by_search == false and
        sekant.considered_hosting_site == false
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "report.pdf",
    mime: "application/pdf",
    file_size: data.length,
    download_url: "https://company.com/reports/annual.pdf",
    tab_url: "https://company.com/downloads",
    unfamiliar_site: false,
    referred_by_search: false,
    considered_hosting_site: false
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TrustedDownload'));
});

await test('6.2: File from AI chatbot', async () => {
  const rules = `
    rule AIGeneratedFile {
      condition:
        sekant.considered_ai_site == true and
        (sekant.mime == "text/plain" or 
         sekant.mime == "application/json")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample4.json');
  
  const metadata = {
    filename: "response.json",
    mime: "application/json",
    file_size: data.length,
    download_url: "https://chatgpt.com/export/conversation.json",
    tab_url: "https://chatgpt.com/c/xyz123",
    considered_ai_site: true
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('AIGeneratedFile'));
});

await test('6.3: Suspicious download from IP address', async () => {
  const rules = `
    rule IPBasedDownload {
      condition:
        sekant.ip != "" and
        sekant.unfamiliar_site == true and
        sekant.mime == "application/x-msdownload"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "installer.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    download_url: "http://203.0.113.42/downloads/installer.exe",
    ip: "203.0.113.42",
    unfamiliar_site: true
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('IPBasedDownload'));
});

await test('6.4: File shared from cloud storage', async () => {
  const rules = `
    rule CloudSharedFile {
      condition:
        sekant.considered_hosting_site == true and
        (sekant.download_url contains "dropbox" or
         sekant.download_url contains "drive.google" or
         sekant.download_url contains "onedrive")
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "SharedDoc.pdf",
    mime: "application/pdf",
    file_size: data.length,
    download_url: "https://www.dropbox.com/s/abc123/SharedDoc.pdf",
    considered_hosting_site: true
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('CloudSharedFile'));
});

await test('6.5: Phishing HTML from search result', async () => {
  const rules = `
    rule PhishingFromSearch {
      condition:
        sekant.mime == "text/html" and
        sekant.referred_by_search == true and
        sekant.unfamiliar_site == true and
        sekant.url_context contains "login"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample5.html');
  
  const metadata = {
    filename: "secure-login.html",
    mime: "text/html",
    file_size: data.length,
    download_url: "https://suspicious-bank-site.xyz/login.html",
    tab_url: "https://suspicious-bank-site.xyz/secure",
    referred_by_search: true,
    unfamiliar_site: true,
    referrer: "https://www.google.com/search?q=bank+login",
    url_context: "login_form"
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('PhishingFromSearch'));
});

// =============================================================================
// Section 7: Multiple Rules Matching
// =============================================================================
console.log('\n📦 Section 7: Multiple Rules Matching');

await test('7.1: Multiple rules should match same file', async () => {
  const rules = `
    rule RuleOne {
      condition:
        sekant.mime == "application/pdf"
    }
    
    rule RuleTwo {
      condition:
        sekant.file_size > 0
    }
    
    rule RuleThree {
      condition:
        sekant.filename contains ".pdf"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "document.pdf",
    mime: "application/pdf",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertEquals(result.matchedRules.length, 3);
  assertTrue(result.matchedRules.includes('RuleOne'));
  assertTrue(result.matchedRules.includes('RuleTwo'));
  assertTrue(result.matchedRules.includes('RuleThree'));
});

await test('7.2: Some rules match, some don\'t', async () => {
  const rules = `
    rule MatchingRule {
      condition:
        sekant.mime == "text/html"
    }
    
    rule NonMatchingRule {
      condition:
        sekant.mime == "application/pdf"
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample5.html');
  
  const metadata = {
    filename: "page.html",
    mime: "text/html",
    file_size: data.length
  };
  
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertEquals(result.matchedRules.length, 1);
  assertTrue(result.matchedRules.includes('MatchingRule'));
  assertFalse(result.matchedRules.includes('NonMatchingRule'));
});

// =============================================================================
// Section 8: Integration with Real Rules File
// =============================================================================
console.log('\n📦 Section 8: Integration with Real Rules File');

await test('8.1: Test with rules from sekant_tests.yar', async () => {
  const rulesContent = readFileSync('rules/sekant_tests.yar', 'utf-8');
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRuleSource(rulesContent);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "download_sample1.txt",
    mime: "text/plain",
    file_size: data.length,
    download_url: "https://example.com/downloads/sample.txt",
    tab_url: "https://example.com/page",
    unfamiliar_site: false
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  // Should match SekantBasicFilename
  assertTrue(result.matchedRules.includes('SekantBasicFilename'));
});

await test('8.2: Test PDF detection from rules file', async () => {
  const rulesContent = readFileSync('rules/sekant_tests.yar', 'utf-8');
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRuleSource(rulesContent);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "document.pdf",
    mime: "application/pdf",
    file_size: data.length
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  // Should match SekantMimeTypePDF
  assertTrue(result.matchedRules.includes('SekantMimeTypePDF'));
});

await test('8.3: Test complex detection from rules file', async () => {
  const rulesContent = readFileSync('rules/sekant_tests.yar', 'utf-8');
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRuleSource(rulesContent);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    filename: "suspicious.exe",
    mime: "application/x-msdownload",
    file_size: data.length,
    download_url: "https://example.com/downloads/file.exe",
    unfamiliar_site: true
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  // Should match multiple rules including SekantSuspiciousExecutable
  assertTrue(result.matchedRules.includes('SekantSuspiciousExecutable'));
  assertTrue(result.matchedRules.includes('SekantDownloadURL'));
  assertTrue(result.matchedRules.includes('SekantUnfamiliarSite'));
});

// =============================================================================
// Section 9: Truthy/Falsy Evaluation Tests
// =============================================================================
console.log('\n📦 Section 9: Truthy/Falsy Evaluation');

await test('9.1: String field truthy when present', async () => {
  const rules = `
    rule TestTruthyFilename {
      condition:
        sekant.filename
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "myfile.txt"
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestTruthyFilename'));
});

await test('9.2: String field falsy when empty', async () => {
  const rules = `
    rule TestFalsyFilename {
      condition:
        not sekant.filename
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: ""
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestFalsyFilename'));
});

await test('9.3: Boolean field truthy check', async () => {
  const rules = `
    rule TestTruthyBoolean {
      condition:
        sekant.unfamiliar_site
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample3.exe');
  
  const metadata = {
    unfamiliar_site: true
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestTruthyBoolean'));
});

await test('9.4: Boolean field falsy check', async () => {
  const rules = `
    rule TestFalsyBoolean {
      condition:
        not sekant.referred_by_search
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    referred_by_search: false
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestFalsyBoolean'));
});

await test('9.5: Combined truthy checks', async () => {
  const rules = `
    rule TestCombinedTruthy {
      condition:
        sekant.filename and sekant.mime and sekant.download_url
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample2.pdf');
  
  const metadata = {
    filename: "doc.pdf",
    mime: "application/pdf",
    download_url: "https://example.com/doc.pdf"
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestCombinedTruthy'));
});

// =============================================================================
// Section 10: Missing Metadata Handling
// =============================================================================
console.log('\n📦 Section 10: Missing Metadata Handling');

await test('10.1: Scan with completely empty metadata', async () => {
  const rules = `
    rule TestEmptyMetadata {
      condition:
        not sekant.filename and
        not sekant.mime and
        not sekant.download_url
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const result = transformResults(await scanner.scan(data, {}));
  
  // Should not crash and should match the rule
  assertTrue(result.matchedRules.includes('TestEmptyMetadata'));
});

await test('10.2: Scan with null metadata', async () => {
  const rules = `
    rule TestNullMetadata {
      condition:
        filesize > 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  // Should not crash with null metadata
  const result = transformResults(await scanner.scan(data, null));
  
  assertTrue(result.matchedRules.includes('TestNullMetadata'));
});

await test('10.3: Scan with undefined metadata', async () => {
  const rules = `
    rule TestUndefinedMetadata {
      condition:
        filesize > 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  // Should not crash with undefined metadata
  const result = transformResults(await scanner.scan(data, undefined));
  
  assertTrue(result.matchedRules.includes('TestUndefinedMetadata'));
});

await test('10.4: Missing string fields default to empty', async () => {
  const rules = `
    rule TestMissingStringDefaults {
      condition:
        sekant.filename == "" and
        sekant.mime == "" and
        sekant.download_url == "" and
        sekant.ip == ""
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const result = transformResults(await scanner.scan(data, {}));
  
  assertTrue(result.matchedRules.includes('TestMissingStringDefaults'));
});

await test('10.5: Missing boolean fields default to false', async () => {
  const rules = `
    rule TestMissingBooleanDefaults {
      condition:
        sekant.unfamiliar_site == false and
        sekant.referred_by_search == false and
        sekant.considered_ai_site == false and
        sekant.considered_hosting_site == false
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const result = transformResults(await scanner.scan(data, {}));
  
  assertTrue(result.matchedRules.includes('TestMissingBooleanDefaults'));
});

await test('10.6: Partial metadata with missing fields', async () => {
  const rules = `
    rule TestPartialMetadata {
      condition:
        sekant.filename and
        not sekant.download_url and
        sekant.unfamiliar_site == false
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    filename: "test.txt"
    // downloadUrl and unfamiliarSite missing
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestPartialMetadata'));
});

await test('10.7: Safe access to missing nested properties', async () => {
  const rules = `
    rule TestSafeAccess {
      condition:
        sekant.filename contains "test" or
        not sekant.download_url
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {};
  
  // Should not crash when using contains on empty string
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestSafeAccess'));
});

await test('10.8: Zero filesize explicitly set', async () => {
  const rules = `
    rule TestZeroFilesize {
      condition:
        sekant.file_size == 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = new Uint8Array([]);
  
  const metadata = {
    file_size: 0
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestZeroFilesize'));
});

await test('10.9: Missing filesize defaults to 0', async () => {
  const rules = `
    rule TestMissingFilesize {
      condition:
        sekant.file_size == 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    // filesize not provided
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestMissingFilesize'));
});

await test('10.10: Complex rule with mixed present and missing fields', async () => {
  const rules = `
    rule TestMixedFields {
      condition:
        sekant.mime == "text/plain" and
        not sekant.download_url and
        not sekant.unfamiliar_site and
        sekant.file_size >= 0
    }
  `;
  
  const scanner = new YaraScanner();
  const sekantModule = new SekantYaraModule();
  scanner.setModules({ sekant: sekantModule });
  scanner.addRules(rules);
  const data = loadTestFile('download_sample1.txt');
  
  const metadata = {
    mime: "text/plain"
    // All other fields missing
  };
  
  const result = transformResults(await scanner.scan(data, metadata));
  
  assertTrue(result.matchedRules.includes('TestMixedFields'));
});

// =============================================================================
// Print Summary
// =============================================================================
console.log('\n' + '='.repeat(70));
printSummary();
console.log('='.repeat(70));
