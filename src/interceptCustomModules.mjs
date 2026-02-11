/*
 * Copyright 2026 Rishi Kant (Sekant Security Inc.)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Sekant Intercept Custom Modules Interface
 * 
 * This file defines the interface for custom modules that can be registered
 * with the InterceptScanner. Custom modules extend functionality beyond the
 * standard modules (pe, elf, math, hash, string, time).
 * 
 * ============================================================================
 * MODULE LIFECYCLE
 * ============================================================================
 * 
 * 1. load()
 *    - Called once when module needs initialization (lazy loading during first scan)
 *    - Use for: fetching databases, compiling patterns, loading resources
 *    - Must catch errors internally and set loaded flag to false on failure
 * 
 * 2. initialize(data, metadata)
 *    - Called per scan to process the file data
 *    - Receives: Uint8Array data and metadata object
 *    - Returns: Interim results object (any structure you need)
 *    - Must return {} if module not loaded
 * 
 * 3. createModule(interimResults)
 *    - Called per scan to create final module object for condition evaluation
 *    - Receives: Results from initialize()
 *    - Returns: Object with properties/functions accessible in YARA conditions
 *    - Must return {} if module not loaded
 * 
 * ============================================================================
 * REQUIRED INTERFACE
 * ============================================================================
 * 
 * getName(): string
 *   - Returns module keyword used in YARA conditions (e.g., "mymodule")
 *   - Must be lowercase alphanumeric for consistency
 *   - Cannot conflict with reserved names (see RESERVED_MODULE_NAMES)
 * 
 * isLoaded(): boolean
 *   - Returns whether load() completed successfully
 *   - Used by scanner to determine if load() needs to be called
 * 
 * load(): Promise<void>
 *   - One-time initialization
 *   - Should catch errors and set internal loaded flag to false
 *   - Called lazily on first scan if isLoaded() returns false
 * 
 * initialize(data, metadata): Promise<Object>
 *   - Process file data and return interim results
 *   - data: Uint8Array of file being scanned
 *   - metadata: {filesize, hasPE, hasELF, timestamp, ...}
 *   - Must return {} if not loaded
 * 
 * createModule(interimResults): Object
 *   - Create final module object from interim results
 *   - Returns object with properties/functions for conditions
 *   - Must return {} if not loaded
 * 
 * ============================================================================
 * USAGE IN YARA RULES
 * ============================================================================
 * 
 * rule ExampleRule {
 *   condition:
 *     mymodule.property == value and
 *     mymodule.method(arg1, arg2)
 * }
 * 
 * ============================================================================
 * ERROR HANDLING
 * ============================================================================
 * 
 * - load() failures: Catch internally, set loaded=false, log warning
 * - initialize() failures: Return {}, log warning
 * - createModule() failures: Return {}
 * - Graceful degradation: Conditions using unavailable modules → undefined/false
 * 
 * ============================================================================
 * MODULE NAME RESTRICTIONS
 * ============================================================================
 * 
 * Cannot use reserved keywords (case-insensitive):
 * pe, elf, math, hash, string, time, filesize, entrypoint
 */

/**
 * Base Custom Module Class
 * 
 * Extend this class to create your custom module. Override all methods.
 * 
 * @example
 * class MyModule extends BaseCustomModule {
 *   constructor() {
 *     super();
 *     this._loaded = false;
 *   }
 * 
 *   getName() {
 *     return 'mymodule';
 *   }
 * 
 *   isLoaded() {
 *     return this._loaded;
 *   }
 * 
 *   async load() {
 *     try {
 *       // Your initialization logic
 *       this._loaded = true;
 *     } catch (error) {
 *       console.warn(`MyModule: Load failed: ${error.message}`);
 *       this._loaded = false;
 *     }
 *   }
 * 
 *   async initialize(data, metadata) {
 *     if (!this._loaded) return {};
 *     // Process data and return results
 *     return { result: 'value' };
 *   }
 * 
 *   createModule(interimResults) {
 *     if (!this._loaded) return {};
 *     return {
 *       property: interimResults.result,
 *       method: (arg) => arg * 2,
 *     };
 *   }
 * }
 */
export class BaseCustomModule {

  constructor(name) {
    // Initialization logic if needed
    this._isLoaded = false;
    this._name = name;
    if (!isValidModuleName(name)) {
      throw new Error(`Invalid module name: "${name}". It is either reserved or malformed.`);
    }
  }

  /**
   * Returns the module keyword for YARA conditions
   * @returns {string} Module name (must be unique and not reserved)
   */
  getName() {
    return this._name;
  }

  /**
   * Returns whether the module loaded successfully
   * @returns {boolean} Load status
   */
  isLoaded() {
    return this._isLoaded;
  }

  /**
   * One-time initialization
   * Should catch errors internally and set loaded flag
   * @returns {Promise<boolean>} Load success status
   */
  async load() {
    this._isLoaded = true;
    return this._isLoaded;
  }

  /**
   * Process file data per scan
   * @param {Uint8Array} data - File data being scanned
   * @param {Object} metadata - Scan metadata (filesize, hasPE, hasELF, timestamp)
   * @returns {Promise<Object>} Interim results (any structure)
   */
  async initialize(data, metadata) { // eslint-disable-line no-unused-vars
    throw new Error('CustomModule.initialize() must be implemented');
  }

  /**
   * Create final module object for condition evaluation
   * @param {Object} interimResults - Results from initialize()
   * @returns {Object} Module object with properties and/or functions
   */
  createModule(interimResults) { // eslint-disable-line no-unused-vars
    throw new Error('CustomModule.createModule() must be implemented');
  }
}

/**
 * Reserved Module Keywords (case-insensitive)
 * These names cannot be used for custom modules
 */
export const RESERVED_MODULE_NAMES = [
  'pe',
  'elf',
  'math',
  'hash',
  'string',
  'time',
  'filesize',
  'entrypoint',
];

/**
 * Validate custom module name against reserved keywords
 * @param {string} name - Module name to validate
 * @returns {boolean} True if name is valid (not reserved)
 */
export function isValidModuleName(name) {
  if (!name || typeof name !== 'string') {
    return false;
  }
  
  const nameLower = name.toLowerCase();
  return !RESERVED_MODULE_NAMES.includes(nameLower);
}
