# Custom Module Overview

## Introduction

The core YARA scanner supports standard modules (`pe`, `elf`, `math`, etc.) but is designed to be extensible. The **Custom Module Interface** allows developers to inject new functionality—such as proprietary file format parsers, threat intelligence lookups, or custom math helpers—directly into the scanning logic.

## Module Logic

Unlike standard modules which are hardcoded into the scanner's factory, custom modules follow a lifecycle managed by the `InterceptScanner`.

### Base Functions

Every custom module inherits the `BaseCustomModule` interface:

1. **`constructor()`**:
    -  Must implement
    -  Sets the module namespace by calling `super(moduleName)` 
    -  Note: moduleName should not conflict with standard module names or keywords
2.  **`async load()`**:
    -   Optional to implement
    -   **One-time initialization**. usage: Fetching databases, compiling regexes, loading big resources.
    -   Called lazily on the first scan that requires the module.
3.  **`async initialize(data, metadata)`**:
    -  Must implement
    -   **Per-scan processing**. Receives the raw file byte array.
    -   Returns an "interim result" object (e.g., raw parsed JSON).
4.  **`createModule(interimResults)`**:
    -  Must implement
    -   **Per-scan Object Creation**. Converts the interim result into the final object exposed to the JS runtime.
    -   Example: Converts raw JSON `{"score": 10}` into an object with methods if needed.

## Integration in Scanner

To use a custom module, register it with the scanner instance before scanning:

```javascript
import { MyCustomModule } from './myModules.js';

const myCustomModule = new MyCustomModule();
// Optional: call `await myCustomModule.load();`
const customModulesMap = {};
customModulesMap[myCustomModule.getName()] = myCustomModule;

// Register with scanner during scanner creation
const scanner = new InterceptScanner({ modules: customModulesMap });

...

const metadata = { ... }; // JSON object with fields based on custom module needs
scanner.scan(payloadBytes, metadata);

```

Once registered, the scanner automatically:
1.  Calls `load()` if it hasn't successfully run yet.
2.  Calls `initialize(data)` for every new file scanned.
3.  Calls `createModule()` to populate `ScanFacts.modules.<name>`.

## Example Implementation

```javascript
export class ReputationModule extends BaseCustomModule {
    constructor() {
        super("reputation");
    }
    
    async load() { 
        this.db = await loadDatabase(); // Expensive/Async
        this.loaded = true;
    }

    async initialize(data, metadata) {
        const hash = crypto.createHash('md5').update(data).digest('hex');
        return { hash };
    }

    createModule(interim) {
        // The object returned here is exactly what 'reputation' refers to in YARA
        return {
            score: (lookupType) => this.db.check(interim.hash, lookupType),
            is_malicious: this.db.isBad(interim.hash)
        };
    }
}
```

## Restrictions

1.  **Reserved Names**: You cannot name a module `pe`, `elf`, `math`, `hash`, `string`, `time`, `filesize`, or `entrypoint`.
2.  **Return Types**: Functions exposed to YARA must return values compatible with the evaluator (boolean, number, string, or undefined).

---
**Last Updated:** 2026-07-22
