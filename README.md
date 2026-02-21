# Intercept.js: Context-Aware YARA Runtime Detection for JavaScript Environments

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Browser%20%7C%20Node%20%7C%20Edge-green.svg)](https://github.com/sekantsec/sekant-intercept-js)
<!-- [![Modern JS](https://img.shields.io/badge/ECMAScript-2024%2B-yellow.svg)](https://github.com/sekantsec/sekant-intercept-js) -->

**Intercept.js** is a pure JavaScript, YARA-compatible detection engine that combines byte-level pattern matching with runtime context inside sandboxed JavaScript environments (browsers, serverless runtimes, Electron). It is designed for application-layer inspection where traditional OS-level security tools lack visibility.

While compatible with standard YARA syntax and modules (PE, ELF, Math, Hash, String, Time), Intercept.js extends detection beyond traditional file scanning by allowing rules to **combine content inspection with contextual metadata**, such as domain novelty, sender reputation, MIME discrepancies, user gesture state, referrer, and runtime origin.

This enables expressive logic such as:
- Executable header and downloaded from a newly observed domain
- Suspicious document with macro and received from unknown sender
- Script payload and inserted via clipboard without user interaction
- Binary content and MIME type mismatch

The repository includes 900+ unit and integration tests and documentation detailing grammar support and differences from libyara.

---

## Use-Cases (MITRE ATT&CK)

* **Neutralize Malicious Paste (T1204.004):** Detect malicious blobs in clipboard buffers before they reach the OS shell.
* **Secure Ingress (T1105):** Block unsafe binary blobs and downloads within browsers.
* **Phishing Mitigation (T1566.001):** Perform EDR-like email attachment scanning with email metadata context.
* **Data Loss Prevention (T1020 / T1115):** Monitor application buffers for PII, secret keys, or exfiltration patterns.

---

## Example Videos

### Running in a webpage without network access

[![Watch: Running in a webpage](https://img.youtube.com/vi/w8wsU_hWOz8/0.jpg)](https://youtu.be/w8wsU_hWOz8 "Watch Intercept.js run in a webpage without NW access")

### Running in a browser extension to scan downloads

[![Watch: Blocking Downloads](https://img.youtube.com/vi/92jDpF19Eso/0.jpg)](https://youtu.be/92jDpF19Eso "Watch Intercept.js block downloads in the browser")

---

## Technical Overview

Intercept.js avoids native bindings and instead leverages V8’s optimized RegExp engine and JavaScript runtime characteristics:

* **Aho-Corasick Engine:** High-efficiency multi-pattern string matching for thousands of rules in O(n) time.
* **Hex-to-Regex JIT:** Translates YARA hex strings (with wildcards and jumps) into optimized V8 Regular Expressions for efficient execution.
* **AST Evaluation:** Uses a custom Lexer and Parser to convert YARA conditions into an Abstract Syntax Tree with short-circuit logic.
* **Resource Safety:** Strict match caps to defend against "ReDoS" (Regex Denial of Service) and memory exhaustion.
* **Common Module Support:** Native JS implementation of pe, elf, math, hash, time, and string modules.
* **Custom Modules:** Plugin architecture enables use-case specific contextual information to be used in evaluation (e.g. domain reputation for download source).

---

## ⚡ Quick Start

### Installation

```bash
git clone https://github.com/sekantsec/sekant-intercept-js.git
cd sekant-intercept-js
npm install
npm run build
npm run example:scanner
```

### Run Examples

Quickly verify the engine with built-in examples:

| Command | Description |
| :--- | :--- |
| `npm run example:scanner` | Basic scanning demonstration. |
| `npm run example:modules` | Demonstrates PE, ELF, Math, and Hash modules. |
| `npm run example:advanced` | Advanced logic (boolean literals, conditions, filesize). |


#### Example output for `example:scanner`
``` 

> sekant-intercept-js@1.0.0 example:scanner
> node examples/exampleYaraScanner.mjs

======================================================================
YARA Scanner End-to-End Examples
======================================================================

--- Example 1: Simple Malware Detection ---

Detected rules: [ 'SuspiciousExecutable' ]
Tags: []
Matched strings:
  $api1: 1 occurrence(s)
  $api2: 1 occurrence(s)

--- Example 2: Document Analysis ---

Document analysis results:
  Detected rules: [ 'SuspiciousDocument' ]
  File size: 1024 bytes
  Entropy (0-1000): 5.172002498773881

...

Combined module analysis:
  File size: 512 bytes
  Entropy: 6.99
  MD5: 415a38bfcba9069445293e4db8bb0e82
  Scan time: 2026-02-21T14:54:04.247Z
  Detected rules: ComplexAnalysis

======================================================================
Examples complete!
======================================================================

```

### Basic Usage (InterceptScanner)

```javascript
import { InterceptScanner } from './src/interceptScanner.mjs';

const rules = 'rule Suspicious_Stager { strings: $ps = "powershell.exe" nocase condition: $ps }';
const scanner = new InterceptScanner(rules);

// Scan clipboard data (as Uint8Array)
const clipboardData = new TextEncoder().encode(await navigator.clipboard.readText());
const results = await scanner.scan(clipboardData);

if (results.length > 0) {
  console.warn("Security Alert: Malicious paste blocked!");
}
```

---

## Architecture & Deployment

Intercept.js is optimized for modern, "OS-less" deployment.

| Target | Environment | Use Case |
| :--- | :--- | :--- |
| **Browsers** | Chrome/Edge/Safari | Real-time clipboard & download protection. |
| **Email Clients** | Outlook / Apple Mail | Configurable attachment scanning. |
| **Serverless** | Cloudflare Workers | Edge-based payload sanitization. |
| **Electron** | Main/Preload Script | In-app protection for Slack/VS Code forks. |
| **Automation** | macOS JXA / GNOME | Low-overhead desktop security services. |

---

## Supported Modules & Extensibility

Intercept.js includes native JavaScript implementations of standard YARA modules, ensuring compatibility without external dependencies.

*   **PE Module**: Parse Windows PE headers, sections, imports, and exports.
*   **ELF Module**: Analyze Linux/Unix ELF headers and sections.
*   **Math Module**: Entropy calculation, min/max, and statistical functions.
*   **Hash Module**: MD5, SHA1, SHA256, and CRC32 calculation.
*   **Time Module**: Date/time comparisons.
*   **String Module**: String length and transformation utilities.

### Custom Modules
You can easily extend the engine by injecting custom JS objects as modules. This allows rules to query application-specific context (e.g., `http.url`, `user.role`, `browser.userAgent`) without modifying the core engine.

See [Custom Module Overview](docs/developer/CUSTOM_MODULE_OVERVIEW.md) for implementation details.

---

## Documentation Map

We provide detailed documentation for different audiences:

### General Usage
*   **[YARA Grammar Support](docs/general/YARA_GRAMMAR_SUPPORT.md)**: What features (hex, loops, regex) are supported.
*   **[Engine Differences](docs/general/ENGINE_DIFFERENCES.md)**: Critical differences between this JS engine and C-based libyara.

### Developer & Architecture
*   **[Architecture Overview](docs/developer/0_GENERAL_OVERVIEW.md)**: High-level design of the scanning pipeline.
*   **[AST Reference](docs/developer/AST_REFERENCE.md)**: Internal structure of parsed conditions.
*   **[Output Reference](docs/developer/SCAN_OUTPUT_REFERENCE.md)**: Structure of scanner output.


### Module Reference
*   **[Standard Modules](docs/modules/STANDARD_MODULES.md)**: API reference for built-in modules.
*   **[PE Module Details](docs/modules/PE_MODULE.md)**: Specifics of the PE parser.
*   **[Custom Module Details](docs/modules/CUSTOM_MODULE_OVERVIEW.md)**: Overview of Custom Modules.

---

## Testing

We utilize **Vitest** for component testing and integration validation. The repository includes 900+ tests covering several layers:

### Run All Tests
To execute the full test suite:
```bash
npm run vitest
```

### Test Categories

**1. Core Engine (Unit Tests)**
Validate individual components like string matching, condition parsing, and the Aho-Corasick automaton.
```bash
npm run vitest vitest/testComprehensiveStringMatcher.test.mjs
npm run vitest vitest/testConditionsMatch.test.mjs
npm run vitest vitest/testAhoCorasickComprehensive.test.mjs
```

**2. Module Verification**
Ensure that built-in modules (PE, ELF, Math, Hash) correctly parse file formats and calculate values.
```bash
npm run vitest vitest/testPEModule.test.mjs
npm run vitest vitest/testELFModule.test.mjs
npm run vitest vitest/testMathModule.test.mjs
```

**3. Advanced Logic**
Test complex YARA features like loops, bitwise operations, and boolean logic.
```bash
npm run vitest vitest/testForLoopsComprehensive.test.mjs
npm run vitest vitest/testBitwiseOperators.test.mjs
```

**4. End-to-End Integration**
Validators for the full `YaraScanner` pipeline against realistic rules and payloads.
```bash
npm run vitest vitest/testYaraScanner.test.mjs
npm run vitest vitest/testComprehensive.test.mjs
```

---

## ⚡ Performance & Limitations

Intercept.js is designed for **safety and portability**, not raw throughput supremacy over C-based YARA.

- **Partial YARA Compatibility** - Not all YARA condition constructs are fully implemented. Gaps and edge-cases are documented [Engine Differences](docs/general/ENGINE_DIFFERENCES.md).
- **In-Memory Scanning** - The engine operates on fully loaded byte buffers making extremely large files impractical to scan. Stream support is planned.
- **Module Evaluation Scope** - Custom Modules currently receive raw content and context, but not the intermediate scan facts during pattern matching. Support is planned.
- **Execution Speed**: Although V8's JIT compiler optimizes RegEx heavy rules significantly, it is not meant to match C-based YARA performance.

---

## FAQ

### Why not compile libyara to WebAssembly (WASM)?

Intercept.js intentionally avoids native bindings and WebAssembly. While compiling libyara to WASM is technically possible, the primary constraints in sandboxed JavaScript environments are portability, memory bounds, and integration with runtime metadata — not raw CPU throughput.

A pure JavaScript implementation:

- Simplifies auditing and embedding in browsers, serverless runtimes, and extensions  
- Avoids cross-environment WASM compatibility issues  
- Integrates naturally with host-provided runtime context  
- Reduces debugging and operational complexity  

### How complete is YARA compatibility?

Intercept.js supports the majority of commonly used YARA condition constructs, including literal, regex, and hex strings, along with common modules (PE, ELF, Math, Hash, String, Time). Some advanced or less commonly used constructs are not yet implemented. Documented differences are available in the [Engine Differences](docs/general/ENGINE_DIFFERENCES.md) guide.

### How does performance compare to C-based YARA?

Intercept.js is not intended to outperform native C-based libyara in raw throughput. It is optimized for practical performance within JavaScript runtimes using Aho-Corasick multi-pattern matching and V8’s optimized RegExp engine. The goal is predictable, efficient evaluation inside application-layer environments where native engines may not be practical to deploy.

### Is rule evaluation deterministic?

Yes. Rule evaluation is deterministic and side-effect free. Custom modules expose structured metadata to the rule engine but do not execute arbitrary code defined inside rules.

---

## Real-World Usage

Intercept.js is used by **Sekant Security** to secure browsers:

### 1. Download Protection
Intercept.js inspects file downloads in-flight to identify malicious artifacts before they are written to disk.

### 2. Clipboard Sanitization
Intercept.js scans clipboard content copied within browsers in real-time, detecting obfuscated / malicious payloads before execution.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTION_GUIDELINES.md](docs/developer/CONTRIBUTION_GUIDELINES.md) for details on how to get started.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

## Security Policy

If you discover a security vulnerability within Intercept.js (e.g., a way to bypass detection or cause a Denial of Service via a crafted rule), please report it privately to `support@sekantsecurity.com` rather than opening a public issue.

---

## License & Attribution

This project is licensed under the **Apache License 2.0**.

**Copyright 2026 Rishi Kant (Sekant Security Inc.)**

Included Third-Party Software:
* **pe-library** (MIT License) - Used for PE header parsing.
* **spark-md5** (MIT License) - Used for Hash support.

See the LICENSE and NOTICE files for full details.