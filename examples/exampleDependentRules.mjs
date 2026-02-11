/**
 * Example: Using Dependent Rules in YARA
 * 
 * Demonstrates how rules can reference other rules in their conditions,
 * allowing for hierarchical and modular rule design.
 */

import { InterceptScanner } from '../src/interceptScanner.mjs';

async function demonstrateDependentRules() {
  console.log('Dependent Rules in YARA\n');
  console.log('='.repeat(70));
  
  const scanner = new InterceptScanner();
  
  // Example: Malware detection with hierarchical rules
  const malwareRules = `
    rule HasPEHeader {
      strings:
        $mz = "MZ"
      condition:
        $mz at 0
    }
    
    rule HasSuspiciousAPI {
      strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
      condition:
        any of them
    }
    
    rule HasNetworkActivity {
      strings:
        $net1 = "URLDownloadToFile"
        $net2 = "InternetOpenUrl"
        $net3 = "socket"
      condition:
        any of them
    }
    
    rule SuspiciousExecutable {
      condition:
        HasPEHeader and HasSuspiciousAPI
    }
    
    rule PotentialMalware {
      condition:
        SuspiciousExecutable and HasNetworkActivity
    }
  `;
  
  scanner.addRules(malwareRules);
  
  // Test data 1: File with PE header and suspicious APIs
  console.log('\n--- Test 1: File with PE header and suspicious APIs ---');
  const data1 = Buffer.from('MZ\x00\x00CreateRemoteThread\x00WriteProcessMemory');
  const result1 = await scanner.scan(data1);
  
  console.log('Matched rules:');
  result1.forEach(match => {
    console.log(`  - ${match.rule}`);
  });
  
  // Test data 2: File with everything (full malware signature)
  console.log('\n--- Test 2: File with complete malware signature ---');
  const data2 = Buffer.from('MZ\x00\x00CreateRemoteThread\x00URLDownloadToFile');
  const result2 = await scanner.scan(data2);
  
  console.log('Matched rules:');
  result2.forEach(match => {
    console.log(`  - ${match.rule}`);
  });
  
  // Test data 3: File with only network activity (no PE header)
  console.log('\n--- Test 3: File with only network activity ---');
  const data3 = Buffer.from('socket\x00InternetOpenUrl');
  const result3 = await scanner.scan(data3);
  
  console.log('Matched rules:');
  if (result3.length === 0) {
    console.log('  (none - PotentialMalware requires PE header)');
  } else {
    result3.forEach(match => {
      console.log(`  - ${match.rule}`);
    });
  }
  
  console.log('\n' + '='.repeat(70));
  console.log('\nDependent rules benefits:');
  console.log('  • Modular rule design - break complex logic into simple components');
  console.log('  • Reusability - base rules can be used by multiple high-level rules');
  console.log('  • Clarity - easier to understand and maintain rule hierarchies');
  console.log('  • Efficiency - YARA evaluates dependencies automatically');
  console.log('  • Logical composition - combine rules with AND, OR, NOT operators');
}

demonstrateDependentRules().catch(console.error);
