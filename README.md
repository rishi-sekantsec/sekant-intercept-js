# Sekant Intercept.js: An Embeddable YARA-Compatible Content Inspection Engine for Edge Deployments

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Browser%20%7C%20Node%20%7C%20Edge-green.svg)](https://github.com/sekantsec/sekant-intercept-js)
[![Modern JS](https://img.shields.io/badge/ECMAScript-2024%2B-yellow.svg)](https://github.com/sekantsec/sekant-intercept-js)

**Intercept.js** is a clean-room, zero-dependency YARA engine implemented in native JavaScript. It is designed to disrupt the attacker toolchain at the **application edge**—before malicious payloads ever touch the disk.

By decoupling YARA from libyara and OS-level hooks, Intercept.js enables **signature-based defense** in sandboxed environments where native binaries cannot run, such as Chrome Extensions, Microsoft Office Add-ins, Email Clients, Electron Apps, and Serverless Workers.

---

## 🛡️ Strategic Security Use-Cases (MITRE ATT&CK)

* **Endpoint Protection (T1204.004):** Neutralize Malicious Paste/Clipboard attacks by scanning stagers in real-time within the browser.
* **Secure Ingress (T1105):** Inspect binary blobs, downloads, and email attachments at the point of origin.
* **Phishing Mitigation (T1566.001):** Perform client-side attachment scanning for E2EE environments where server-side scanning is blind.
* **Data Loss Prevention (T1020 / T1115):** Monitor application buffers for PII, secret keys, or exfiltration patterns within the memory space.

---

## 🚀 Technical Innovation

Unlike Node wrappers that rely on native C++ bindings, Intercept.js leverages the **V8 engine's JIT capabilities** to achieve high performance:

* **Aho-Corasick Engine:** High-efficiency multi-pattern string matching for thousands of rules in O(n) time.
* **Hex-to-Regex JIT:** Translates YARA hex strings (with wildcards and jumps) into optimized V8 Regular Expressions for machine-speed execution.
* **AST Evaluation:** Uses a custom Lexer and Parser to convert YARA conditions into an Abstract Syntax Tree with short-circuit logic.
* **Resource Safety:** Strict match caps and execution timeouts to prevent "ReDoS" (Regex Denial of Service) and memory exhaustion.
* **Common Module Support:** Native JS implementation of pe, elf, math, hash, time, and string modules.
* **Custom Modules:** Plugin architecture enables use-case specific contextual information to be used in evaluation (e.g. domain reputaton for download source).


---

## ⚡ Quick Start

### Installation
`npm install sekant-intercept-js`

### 🏃‍♂️ Run Examples

Quickly verify the engine with built-in examples:

| Command | Description |
| :--- | :--- |
| `npm run example:scanner` | Basic scanning demonstration. |
| `npm run example:modules` | Demonstrates PE, ELF, Math, and Hash modules. |
| `npm run example:advanced` | Advanced logic (boolean literals, conditions, filesize). |

### Basic Usage (InterceptScanner)

```javascript
import { InterceptScanner } from 'sekant-intercept-js';

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

## 🏗️ Architecture & Deployment

Intercept.js is optimized for modern, "OS-less" deployment.

| Target | Environment | Use Case |
| :--- | :--- | :--- |
| **Browsers** | Chrome/Edge/Safari | Real-time clipboard & download protection. |
| **Email Clients** | Outlook / Apple Mail | Configurable attachment scanning. |
| **Serverless** | Cloudflare Workers | Edge-based payload sanitization. |
| **Electron** | Main/Preload Script | In-app protection for Slack/VS Code forks. |
| **Automation** | macOS JXA / GNOME | Low-overhead desktop security services. |


---

## � Supported Modules & Extensibility

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

## ⚡ Performance & Limitations

Intercept.js is designed for **safety and portability**, not raw throughput supremacy over C-based YARA.

*   **Execution Speed**: Pure JS execution is typically 2-10x slower than native C code, though V8's JIT compiler optimizes RegEx heavy rules significantly.
*   **Memory Usage**: Scanning large files (>100MB) in a browser environment may trigger garbage collection pauses. We recommend streaming or chunking for large datasets.
*   **Engine Differences**: While we support ~95% of standard YARA features, some niche features (like `import "cuckoo"`) are not applicable in a browser/edge context. See [Engine Differences](docs/general/ENGINE_DIFFERENCES.md) for a full audit.

---

## 📚 Documentation Map

We provide detailed documentation for different audiences:

### General Usage
*   **[YARA Grammar Support](docs/general/YARA_GRAMMAR_SUPPORT.md)**: What features (hex, loops, regex) are supported.
*   **[Engine Differences](docs/general/ENGINE_DIFFERENCES.md)**: Critical differences between this JS engine and C-based libyara.

### Developer & Architecture
*   **[Architecture Overview](docs/developer/0_GENERAL_OVERVIEW.md)**: High-level design of the scanning pipeline.
*   **[AST Reference](docs/developer/AST_REFERENCE.md)**: Internal structure of parsed conditions.
*   **[Performance Profiling](docs/developer/PERFORMANCE_PROFILING.md)**: How to profile and optimize scan performance.

### Module Reference
*   **[Standard Modules](docs/modules/STANDARD_MODULES.md)**: API reference for built-in modules.
*   **[PE Module Details](docs/modules/PE_MODULE.md)**: Specifics of the PE parser.

---

## �🧪 Testing

We utilize **Vitest** for component testing and integration validation. The repository includes extensive test coverage across several layers:

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

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTION_GUIDELINES.md](docs/general/CONTRIBUTION_GUIDELINES.md) for details on how to get started.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

## 🔐 Security Policy

If you discover a security vulnerability within Intercept.js (e.g., a way to bypass detection or cause a Denial of Service via a crafted rule), please report it privately to `security@sekant.io` rather than opening a public issue.

---

## 📄 License & Attribution

This project is licensed under the **Apache License 2.0**.

**Copyright 2026 Rishi Kant (Sekant Security Inc.)**

Included Third-Party Software:
* **pe-library** (MIT License) - Used for PE header parsing.
* **spark-md5** (MIT License) - Used for Hash support.

See the LICENSE and NOTICE files for full details.