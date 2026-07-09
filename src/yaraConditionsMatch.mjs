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
 * YARA Condition Matching Engine
 *
 * Evaluates YARA rule conditions against scan results.
 * Supports:
 * - String identifiers ($a, $b, #a, @a)
 * - Rule identifiers (dependent rules: RuleA, RuleB)
 * - Module functions (pe.*, elf.*, math.*, hash.*, time.*, string.*)
 * - Boolean operators (and, or, not)
 * - Comparison operators (==, !=, <, >, <=, >=)
 * - Arithmetic operators (+, -, *, \, %)
 * - Bitwise operators (&, |, ^, ~, <<, >>)
 * - String operators (contains, matches, startswith, endswith, icontains, iequals)
 * - Proximity operators (at, in range, within)
 * - Quantifiers (all, any, none, X of them)
 * - Set membership (in)
 * - For expressions (for any/all of them)
 * - Filesize checks
 * - Entrypoint checks
 *
 * @see https://yara.readthedocs.io/en/stable/writingrules.html
 */

/**
 * Scan Facts Structure
 *
 * This is the standardized format for scan results that will be evaluated
 * against YARA rule conditions.
 *
 * @typedef {Object} ScanFacts
 * @property {Uint8Array} data - The raw file data being scanned
 * @property {number} filesize - Size of the file in bytes
 * @property {number} entrypoint - Entry point offset (for PE/ELF files)
 * @property {Object.<string, StringMatchResult>} strings - String match results
 * @property {Object} modules - Module instances (pe, elf, math, hash, time, string)
 * @property {Object.<string, boolean>} matchedRules - Map of rule names to match status (for dependent rules)
 * @property {Object} metadata - Additional metadata about the scan
 *
 * @typedef {Object} StringMatchResult
 * @property {string} identifier - String identifier (e.g., "$a", "$hex1")
 * @property {boolean} matched - Whether the string matched at all
 * @property {number} count - Number of matches
 * @property {Array<MatchInstance>} matches - Array of individual match instances
 * @property {Array<number>} offsets - Array of match offsets (for quick access)
 * @property {number} length - Length of the matched string (if fixed)
 *
 * @typedef {Object} MatchInstance
 * @property {number} offset - Offset where the match occurred
 * @property {number} length - Length of the matched data
 * @property {string} [data] - Optional matched data (for debugging)
 *
 * Example ScanFacts:
 * {
 *   data: Uint8Array([...]),
 *   filesize: 1024,
 *   entrypoint: 0x1000,
 *   strings: {
 *     "$a": {
 *       identifier: "$a",
 *       matched: true,
 *       count: 3,
 *       matches: [
 *         { offset: 10, length: 5, data: "hello" },
 *         { offset: 100, length: 5, data: "hello" },
 *         { offset: 500, length: 5, data: "hello" }
 *       ],
 *       offsets: [10, 100, 500],
 *       length: 5
 *     },
 *     "$b": {
 *       identifier: "$b",
 *       matched: false,
 *       count: 0,
 *       matches: [],
 *       offsets: [],
 *       length: null
 *     }
 *   },
 *   modules: {
 *     pe: { ... },      // PE module instance
 *     elf: { ... },     // ELF module instance
 *     math: { ... },    // Math module instance
 *     hash: { ... },    // Hash module instance
 *     time: { ... },    // Time module instance
 *     string: { ... }   // String module instance
 *   },
 *   metadata: {
 *     filename: "sample.exe",
 *     scanTime: Date.now(),
 *     scanner: "yara-js"
 *   }
 * }
 */

/**
 * Create a standard ScanFacts object from scan results
 * @param {Uint8Array} data - File data
 * @param {Object} stringMatches - String match results from scanner
 * @param {Object} modules - Module instances
 * @param {Object} options - Additional options
 * @returns {ScanFacts}
 */
export function createScanFacts(data, stringMatches = {}, modules = {}, options = {}) {
  // Normalize string matches to standard format
  const normalizedStrings = {};

  for (const [identifier, result] of Object.entries(stringMatches)) {
    if (Array.isArray(result)) {
      // Convert array of matches to standard format
      normalizedStrings[identifier] = {
        identifier,
        matched: result.length > 0,
        count: result.length,
        matches: result,
        offsets: result.map((m) => m.offset),
        // length: result.length > 0 ? result[0].length : null
      };
    } else if (typeof result === "object" && result !== null) {
      // Already in standard format or close to it
      normalizedStrings[identifier] = {
        identifier,
        matched: result.matched ?? result.count > 0,
        count: result.count ?? 0,
        matches: result.matches ?? [],
        offsets: result.offsets ?? (result.matches || []).map((m) => m.offset),
        // length: result.length ?? result.matches?.length,
        ...result,
      };
    }
  }

  return {
    data,
    filesize: data.length,
    entrypoint: options.entrypoint ?? 0,
    isFileSizeCapped: options.isFileSizeCapped ?? false,
    maxFileSize: options.maxFileSize ?? 1024 * 1024, // Default 1MB
    strings: normalizedStrings,
    modules: modules || {},
    matchedRules: options.matchedRules || {}, // Map of rule names to match status
    metadata: options.metadata || {},
  };
}

/**
 * YARA Condition Evaluator
 */
export class ConditionEvaluator {
  constructor(scanFacts) {
    this.facts = scanFacts;
    this.data = scanFacts.data;
    this.filesize = scanFacts.filesize;
    this.entrypoint = scanFacts.entrypoint;
    this.isFileSizeCapped = scanFacts.isFileSizeCapped ?? false;
    this.maxFileSize = scanFacts.maxFileSize ?? 1024 * 1024;
    this.strings = scanFacts.strings;
    this.modules = scanFacts.modules;
    this.matchedRules = scanFacts.matchedRules || {}; // Map of rule names to match status
  }

  /**
   * Check if any operand is undefined (YARA semantics)
   * According to YARA docs: "All remaining operators, including the not operator,
   * return undefined if any of their operands is undefined"
   * @param {...*} operands - One or more operands to check
   * @returns {boolean} True if any operand is undefined
   */
  isAnyUndefined(...operands) {
    return operands.some((operand) => operand === undefined);
  }

  /**
   * Evaluate a YARA condition expression
   * @param {string|Object} condition - Condition string or AST
   * @returns {Promise<boolean>} Result of condition evaluation
   */
  async evaluate(condition) {
    if (typeof condition === "string") {
      condition = this.parseCondition(condition);
    }
    return await this.evaluateNode(condition);
  }

  /**
   * Parse a condition string into an AST
   * This is a simplified parser - in production, use a proper parser
   * @param {string} condition
   * @returns {Object} AST node
   */
  parseCondition(condition) {
    // This would normally use a proper parser (e.g., PEG.js, antlr)
    // For now, return a simple structure
    // In practice, the rule compiler would generate this AST
    throw new Error("String parsing not implemented - pass AST directly");
  }

  /**
   * Evaluate an AST node
   * @param {Object} node
   * @returns {Promise<*>} Evaluation result
   */
  async evaluateNode(node) {
    if (node === null || node === undefined) {
      return false;
    }

    const type = node.type;

    switch (type) {
      // Literals
      case "boolean":
        return node.value;
      case "number":
        return node.value;
      case "string":
        return node.value;
      case "identifier":
        return this.resolveIdentifier(node.name);

      // Rule identifiers (dependent rules)
      case "ruleIdentifier":
        return this.evaluateRuleIdentifier(node);

      // String identifiers
      case "stringIdentifier":
        return this.evaluateStringIdentifier(node);
      case "stringCount":
        return this.getStringCount(node.identifier);
      case "stringOffset": {
        // Evaluate index if it's an expression (e.g., for loop variable)
        let index = node.index;
        if (typeof index === "object") {
          index = await this.evaluateNode(index);
        }
        return this.getStringOffset(node.identifier, index);
      }
      case "stringLength": {
        // Evaluate index if it's an expression (e.g., for loop variable)
        let index = node.index;
        if (typeof index === "object") {
          index = await this.evaluateNode(index);
        }
        return this.getStringLength(node.identifier, index);
      }

      // Logical operators
      case "and": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        // YARA: treat undefined as false in AND operation
        if (left === undefined || left === false) return false;
        if (right === undefined || right === false) return false;
        return true;
      }
      case "or": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        // YARA: treat undefined as false in OR operation
        const leftBool = left === undefined ? false : left;
        const rightBool = right === undefined ? false : right;
        return leftBool || rightBool;
      }
      case "not": {
        const operand = await this.evaluateNode(node.operand);
        // YARA: not of undefined returns undefined
        if (this.isAnyUndefined(operand)) return undefined;
        return !operand;
      }
      case "defined":
        return await this.evaluateDefined(node.operand);

      // Comparison operators
      case "equal":
        return await this.evaluateEqual(node);
      case "notEqual":
        return await this.evaluateNotEqual(node);
      case "lessThan":
        return await this.evaluateLessThan(node);
      case "greaterThan":
        return await this.evaluateGreaterThan(node);
      case "lessThanOrEqual":
        return await this.evaluateLessThanOrEqual(node);
      case "greaterThanOrEqual":
        return await this.evaluateGreaterThanOrEqual(node);

      // Arithmetic operators
      case "add": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left + right;
      }
      case "subtract": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left - right;
      }
      case "multiply": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left * right;
      }
      case "divide": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return Math.floor(left / right);
      }
      case "modulo": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left % right;
      }

      // Bitwise operators (use signed 32-bit integers to match standard YARA behavior)
      case "bitwiseAnd": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left & right;
      }
      case "bitwiseOr": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left | right;
      }
      case "bitwiseXor": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left ^ right;
      }
      case "bitwiseNot": {
        const operand = await this.evaluateNode(node.operand);
        if (this.isAnyUndefined(operand)) return undefined;
        return ~operand;
      }
      case "shiftLeft": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left << right;
      }
      case "shiftRight": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return undefined;
        return left >> right;
      }

      // String operators
      case "contains":
        return await this.stringContains(node.left, node.right, false);
      case "icontains":
        return await this.stringContains(node.left, node.right, true);
      case "startswith":
        return await this.stringStartsWith(node.left, node.right, false);
      case "istartswith":
        return await this.stringStartsWith(node.left, node.right, true);
      case "endswith":
        return await this.stringEndsWith(node.left, node.right, false);
      case "iendswith":
        return await this.stringEndsWith(node.left, node.right, true);
      case "iequals":
        return await this.stringEquals(node.left, node.right, true);
      case "matches":
        return await this.stringMatches(node.left, node.right);

      // Set membership
      case "in":
        return await this.evaluateInOperator(node);

      // Range
      case "range":
        return { start: await this.evaluateNode(node.start), end: await this.evaluateNode(node.end) };

      // Quantifiers
      case "all":
        return await this.evaluateAll(node.items);
      case "any":
        return await this.evaluateAny(node.items);
      case "none":
        return await this.evaluateNone(node.items);
      case "quantified":
        return await this.evaluateQuantified(node);

      // For expressions
      case "for":
        return await this.evaluateFor(node);

      // Member access (e.g., pe.entry_point)
      case "memberAccess":
        return await this.evaluateMemberAccess(node);

      // Array access (e.g., pe.sections[0])
      case "arrayAccess":
        return await this.evaluateArrayAccess(node);

      // Function call
      case "functionCall":
        return await this.evaluateFunctionCall(node);

      // Data access (uint8, uint16, etc.)
      case "dataAccess":
        return this.evaluateDataAccess(node);

      // At expression ($a at 0x100)
      case "at":
        return await this.evaluateAt(node);

      // In range expression ($a in (0..100))
      case "inRange":
        return await this.evaluateInRange(node);

      // Within expression ($a within N of $b)
      case "within":
        return await this.evaluateWithin(node);

      // Module function call (e.g., string.to_int(), time.now())
      case "moduleFunction":
        return await this.evaluateModuleFunction(node);

      default:
        throw new Error(`Unknown node type: ${type}`);
    }
  }

  /**
   * Resolve a simple identifier (filesize, entrypoint, modules, etc.)
   */
  resolveIdentifier(name) {
    // Check for loop context first (for iterator variables like 'i')
    if (this.forContext && name in this.forContext) {
      return this.forContext[name];
    }

    const splitName = name?.split(".");
    name = splitName[0];

    switch (name) {
      case "filesize":
        return this.filesize;
      case "entrypoint":
        // entrypoint can be 0 (valid for non-binary files or PE at offset 0)
        if (typeof this.entrypoint !== "number") {
          throw new Error("Entrypoint is not defined");
        }
        return this.entrypoint;
      default:
        // Check if it's a module name (pe, elf, hash, math, string, time)
        if (this.modules && name in this.modules) {
          if (!this.modules[name]) return this.modules[name]; // Nothing to do
          let currentObj = this.modules;
          for (const key of splitName) {
            currentObj = currentObj[key];
            if (!currentObj) return currentObj;
          }
          return currentObj;
        }
        // Return undefined for known module names when module is unavailable
        // This allows graceful handling of missing modules (e.g., ELF module for non-ELF files)
        if (["pe", "elf", "hash", "math", "string", "time"].includes(name)) {
          return undefined;
        }
        throw new Error(`Unknown identifier: ${name}`);
    }
  }

  /**
   * Check if left side is filesize identifier
   */
  isFilesizeNode(node) {
    return node && node.type === "identifier" && node.name === "filesize";
  }

  /**
   * Evaluate equal comparison with filesize special handling
   */
  async evaluateEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);

    // YARA: comparison with undefined returns undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    // Special handling: if file is capped and comparing filesize == N where N >= maxFileSize
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true; // Assume any filesize >= maxFileSize when capped
    }
    if (this.isFilesizeNode(node.right) && this.isFileSizeCapped && left >= this.maxFileSize) {
      return true;
    }

    return left === right;
  }

  /**
   * Evaluate not equal comparison with filesize special handling
   */
  async evaluateNotEqual(node) {
    const result = await this.evaluateEqual(node);
    // YARA: not equal with undefined returns undefined
    if (this.isAnyUndefined(result)) return undefined;
    return !result;
  }

  /**
   * Evaluate less than comparison with filesize special handling
   */
  async evaluateLessThan(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);

    // YARA: comparison with undefined returns undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    // Normal comparison - filesize < N uses actual value
    return left < right;
  }

  /**
   * Evaluate greater than comparison with filesize special handling
   */
  async evaluateGreaterThan(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);

    // YARA: comparison with undefined returns undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    // Special handling: if file is capped and comparing filesize > N where N >= maxFileSize
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true; // File could be larger than the cap
    }

    // Normal comparison
    return left > right;
  }

  /**
   * Evaluate less than or equal comparison with filesize special handling
   */
  async evaluateLessThanOrEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);

    // YARA: comparison with undefined returns undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    // Normal comparison - filesize <= N uses actual value
    return left <= right;
  }

  /**
   * Evaluate greater than or equal comparison with filesize special handling
   */
  async evaluateGreaterThanOrEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);

    // YARA: comparison with undefined returns undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    // Special handling: if file is capped and comparing filesize >= N where N >= maxFileSize
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true; // File could be larger than or equal to the cap
    }

    // Normal comparison
    return left >= right;
  }

  /**
   * Evaluate string identifier ($a)
   * In for loops, if identifier is '$', use the current loop variable
   */
  evaluateStringIdentifier(node) {
    let identifier = node.identifier;

    // In for loops with string iteration, '$' refers to the current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    const stringInfo = this.strings[identifier];

    if (!stringInfo) {
      return false;
    }

    return stringInfo.matched && stringInfo.count > 0;
  }

  /**
   * Evaluate rule identifier (dependent rule reference)
   * Returns true if the referenced rule matched, false otherwise
   */
  evaluateRuleIdentifier(node) {
    const ruleName = node.name;

    // Check if rule has been evaluated
    if (!(ruleName in this.matchedRules)) {
      // Rule not found or not yet evaluated
      // In YARA, referencing an undefined rule is typically an error,
      // but we'll return false for now
      return false;
    }

    return this.matchedRules[ruleName] === true;
  }

  /**
   * Get string match count (#a)
   * In for loops, if identifier is '$', use the current loop variable
   */
  getStringCount(identifier) {
    // Handle for loop context: if identifier is '$', use current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    const stringInfo = this.strings[identifier];
    return stringInfo ? stringInfo.count : 0;
  }

  /**
   * Get string match offset (@a or @a[1])
   * In for loops, supports @a[i] where i is the iterator variable
   * YARA uses 1-indexed: @a[1] = first match, @a[2] = second match, etc.
   */
  getStringOffset(identifier, index = 0) {
    // Handle for loop context: if identifier is '$', use current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    // If index is an identifier in for context, resolve it
    if (typeof index === "string" && this.forContext && index in this.forContext) {
      index = this.forContext[index];
    }

    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.offsets || stringInfo.offsets.length === 0) {
      return undefined;
    }

    // YARA uses 1-indexed arrays: @a or @a[1] = first match, @a[2] = second match
    // Convert to 0-indexed for JavaScript arrays
    // Special case: @a (without index) and @a[0] both return first match
    const arrayIndex = index === 0 ? 0 : index - 1;
    return stringInfo.offsets[arrayIndex];
  }

  /**
   * Get string match length (!a or !a[1])
   * In for loops, supports !a[i] where i is the iterator variable
   * YARA uses 1-indexed: !a[1] = first match length, !a[2] = second match length, etc.
   */
  getStringLength(identifier, index = 0) {
    // Handle for loop context: if identifier is '$', use current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    // If index is an identifier in for context, resolve it
    if (typeof index === "string" && this.forContext && index in this.forContext) {
      index = this.forContext[index];
    }

    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.matches || stringInfo.matches.length === 0) {
      return undefined;
    }

    // YARA uses 1-indexed arrays: !a or !a[1] = first match, !a[2] = second match
    // Convert to 0-indexed for JavaScript arrays
    // Special case: !a (without index) and !a[0] both return first match
    const arrayIndex = index === 0 ? 0 : index - 1;
    const match = stringInfo.matches[arrayIndex];
    return match ? match.length : undefined;
  }

  /**
   * Evaluate 'all of them' or 'all of ($a*, $b*)'
   */
  evaluateAll(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return false;

    return identifiers.every((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    });
  }

  /**
   * Evaluate 'any of them' or 'any of ($a*, $b*)'
   */
  evaluateAny(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return false;

    return identifiers.some((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    });
  }

  /**
   * Evaluate 'none of them'
   */
  evaluateNone(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return true;

    return identifiers.every((id) => {
      const stringInfo = this.strings[id];
      return !stringInfo || !stringInfo.matched || stringInfo.count === 0;
    });
  }

  /**
   * Evaluate quantified expression (e.g., '2 of them', '50% of them')
   */
  evaluateQuantified(node) {
    const identifiers = this.resolveStringSet(node.items);
    if (identifiers.length === 0) return false;

    const matchCount = identifiers.filter((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    }).length;

    const quantifier = node.quantifier;

    if (quantifier.type === "number") {
      return matchCount >= quantifier.value;
    } else if (quantifier.type === "percentage") {
      const required = Math.ceil((identifiers.length * quantifier.value) / 100);
      return matchCount >= required;
    } else if (quantifier.type === "range") {
      const min = quantifier.min;
      const max = quantifier.max;
      return matchCount >= min && matchCount <= max;
    }

    return false;
  }

  /**
   * Resolve string set (e.g., 'them', '$a*', '($a, $b, $c)')
   */
  resolveStringSet(items) {
    if (items === "them") {
      return Object.keys(this.strings);
    }

    if (Array.isArray(items)) {
      // Process each item in the array, expanding wildcards
      const resolved = [];
      for (const item of items) {
        if (item.includes("*")) {
          // Expand wildcard pattern
          const pattern = item.replace(/\*/g, ".*").replace(/\$/g, "\\$");
          const regex = new RegExp("^" + pattern + "$");
          const matches = Object.keys(this.strings).filter((id) => regex.test(id));
          resolved.push(...matches);
        } else {
          resolved.push(item);
        }
      }
      return resolved;
    }

    if (typeof items === "string") {
      // Handle wildcard patterns like '$a*'
      if (items.includes("*")) {
        const pattern = items.replace(/\*/g, ".*").replace(/\$/g, "\\$");
        const regex = new RegExp("^" + pattern + "$");
        return Object.keys(this.strings).filter((id) => regex.test(id));
      }
      return [items];
    }

    return [];
  }

  /**
   * Evaluate 'for' expression
   * e.g., 'for any of them : ($ at entrypoint)'
   * e.g., 'for all i in (1..5) : (@a[i] < @a[i+1])'
   * e.g., 'for 50% of them : ($ in (0..100))'
   * e.g., 'for all of ($api*) : ($ at entrypoint)'
   */
  async evaluateFor(node) {
    const quantifier = node.quantifier; // 'any', 'all', 'none', number, or percentage object
    const variable = node.variable; // iterator variable (e.g., 'i', '$')
    const set = node.set; // what to iterate over
    const condition = node.condition; // condition to evaluate

    let items = [];

    if (set.type === "stringSet") {
      // Iterating over string identifiers
      items = this.resolveStringSet(set.items);

      if (items.length === 0) {
        // For "all", empty set means true; for "any", empty set means false
        if (quantifier === "all") return true;
        return false;
      }
    } else if (set.type === "range") {
      // Iterating over numeric range
      const startVal = await this.evaluateNode(set.start);
      const endVal = await this.evaluateNode(set.end);

      if (typeof startVal !== "number" || typeof endVal !== "number") {
        throw new Error(`Invalid range values: ${startVal} to ${endVal}`);
      }

      for (let i = startVal; i <= endVal; i++) {
        items.push(i);
      }

      if (items.length === 0) {
        if (quantifier === "all") return true;
        return false;
      }
    } else {
      // Evaluate the set directly
      const evaluated = await this.evaluateNode(set);
      if (Array.isArray(evaluated)) {
        items = evaluated;
      } else {
        items = [evaluated];
      }
    }

    if (items.length === 0) {
      // Empty set: "all" is vacuously true, others are false
      if (quantifier === "all") return true;
      return false;
    }

    // Store original context
    const originalContext = this.forContext || {};

    // Evaluate condition for each item (sequentially to maintain order)
    const results = [];
    for (const item of items) {
      // Set the iterator variable in the context
      this.forContext = { ...originalContext, [variable]: item };

      try {
        // Evaluate the condition with the current item
        const result = await this.evaluateNode(condition);
        results.push(!!result); // Coerce to boolean
      } catch (error) {
        // If evaluation fails, treat as false
        console.warn(`For loop condition evaluation failed for item ${item}:`, error.message);
        results.push(false);
      }
    }

    // Restore original context
    this.forContext = originalContext;

    // Apply quantifier to results
    const trueCount = results.filter((r) => r).length;

    if (quantifier === "any") {
      return trueCount > 0;
    } else if (quantifier === "all") {
      return trueCount === items.length;
    } else if (quantifier === "none") {
      return trueCount === 0;
    } else if (typeof quantifier === "number") {
      // Exact count: "2 of them" means at least 2
      return trueCount >= quantifier;
    } else if (quantifier && quantifier.type === "percentage") {
      // Percentage: "50% of them" means at least 50%
      const required = Math.ceil((items.length * quantifier.value) / 100);
      return trueCount >= required;
    } else if (quantifier && quantifier.type === "number") {
      // Number from object
      return trueCount >= quantifier.value;
    }

    return false;
  }

  /**
   * Evaluate member access (e.g., pe.entry_point, math.entropy(0, 100))
   */
  async evaluateMemberAccess(node) {
    const obj = await this.evaluateNode(node.object);
    const property = node.property;

    if (obj === undefined || obj === null) {
      return undefined;
    }

    if (typeof property === "string") {
      return obj[property];
    } else {
      // Computed property access
      const prop = await this.evaluateNode(property);
      return obj[prop];
    }
  }

  /**
   * Evaluate array access (e.g., pe.sections[0], elf.sections[1])
   */
  async evaluateArrayAccess(node) {
    const obj = await this.evaluateNode(node.object);
    const index = await this.evaluateNode(node.index);

    if (obj === undefined || obj === null) {
      return undefined;
    }

    if (!Array.isArray(obj)) {
      return undefined;
    }

    // Handle negative indices (not standard in YARA but useful)
    const actualIndex = index < 0 ? obj.length + index : index;

    if (actualIndex < 0 || actualIndex >= obj.length) {
      return undefined;
    }

    return obj[actualIndex];
  }

  /**
   * Evaluate function call
   */
  async evaluateFunctionCall(node) {
    const func = await this.evaluateNode(node.function);
    const args = await Promise.all(node.arguments.map((arg) => this.evaluateNode(arg)));

    if (typeof func !== "function") {
      throw new Error(`Not a function: ${node.function}`);
    }

    const result = func(...args);
    // Handle both sync and async functions
    return result instanceof Promise ? await result : result;
  }

  /**
   * Evaluate data access (uint8, uint16, uint32, int8, int16, int32)
   */
  async evaluateDataAccess(node) {
    const offset = await this.evaluateNode(node.offset);
    const dataType = node.dataType;
    const endian = node.endian || "little"; // 'little' or 'big'

    if (offset < 0 || offset >= this.data.length) {
      return undefined;
    }

    const view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
    const littleEndian = endian === "little";

    try {
      switch (dataType) {
        case "uint8":
          return view.getUint8(offset);
        case "uint16":
          return view.getUint16(offset, littleEndian);
        case "uint32":
          return view.getUint32(offset, littleEndian);
        case "int8":
          return view.getInt8(offset);
        case "int16":
          return view.getInt16(offset, littleEndian);
        case "int32":
          return view.getInt32(offset, littleEndian);
        default:
          throw new Error(`Unknown data type: ${dataType}`);
      }
    } catch (e) {
      return undefined;
    }
  }

  /**
   * Evaluate 'defined' operator
   * Checks if an expression is defined (not undefined, not null)
   */
  async evaluateDefined(operand) {
    try {
      const value = await this.evaluateNode(operand);
      // Consider undefined and null as not defined
      return value !== undefined && value !== null;
    } catch {
      // If evaluation throws an error, the expression is not defined
      return false;
    }
  }

  /**
   * Evaluate 'at' expression ($a at 0x100 or "string" at 0)
   * In for loops, if identifier is '$', use the current loop variable
   */
  async evaluateAt(node) {
    let identifier = node.identifier;

    // Handle string literal nodes (e.g., "PDF" at 0)
    if (typeof identifier === "object" && identifier.type === "string") {
      const offset = await this.evaluateNode(node.offset);
      const stringValue = identifier.value;
      const stringBytes = new TextEncoder().encode(stringValue);

      // Check if the string exists at the specified offset
      if (offset < 0 || offset + stringBytes.length > this.data.length) {
        return false;
      }

      // Compare byte by byte
      for (let i = 0; i < stringBytes.length; i++) {
        if (this.data[offset + i] !== stringBytes[i]) {
          return false;
        }
      }
      return true;
    }

    // In for loops with string iteration, '$' refers to the current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    const offset = await this.evaluateNode(node.offset);
    const stringInfo = this.strings[identifier];

    if (!stringInfo || !stringInfo.offsets) {
      return false;
    }

    return stringInfo.offsets.includes(offset);
  }

  /**
   * Evaluate 'in range' expression ($a in (0..100))
   * In for loops, if identifier is '$', use the current loop variable
   */
  async evaluateInRange(node) {
    let identifier = node.identifier;

    // In for loops with string iteration, '$' refers to the current string
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }

    const range = await this.evaluateNode(node.range);
    const stringInfo = this.strings[identifier];

    if (!stringInfo || !stringInfo.offsets) {
      return false;
    }

    return stringInfo.offsets.some((offset) => offset >= range.start && offset <= range.end);
  }

  /**
   * Evaluate 'within' expression ($a within N of $b)
   * Checks if any occurrence of $a is within N bytes of any occurrence of $b
   *
   * Distance is measured from start offset to start offset (YARA standard behavior).
   * Returns true if the absolute distance between any pair of matches is <= N.
   *
   * @param {Object} node - AST node with identifier, distance, reference
   * @returns {Promise<boolean>} True if any match is within distance
   *
   * TODO: Performance optimization needed for large match sets
   * - Current O(n*m) complexity could be slow with many matches
   * - Consider: early termination, sorted offset arrays with binary search,
   *   or distance caching for repeated evaluations
   */
  async evaluateWithin(node) {
    let identifier = node.identifier;
    let reference = node.reference;

    // Handle for-loop context: if identifier is '$', use current loop variable
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    if (reference === "$" && this.forContext && this.forContext["$"]) {
      reference = this.forContext["$"];
    }

    const distance = await this.evaluateNode(node.distance);
    const stringInfo = this.strings[identifier];
    const refInfo = this.strings[reference];

    // Handle missing/empty matches - return false if either string has no matches
    if (!stringInfo || !stringInfo.offsets || stringInfo.offsets.length === 0) {
      return false;
    }
    if (!refInfo || !refInfo.offsets || refInfo.offsets.length === 0) {
      return false;
    }

    // Check if any occurrence of identifier is within distance of any occurrence of reference
    // YARA measures distance from start offset to start offset (not considering match lengths)
    // TODO: Performance - consider optimizing this nested loop for large match sets
    for (const offset of stringInfo.offsets) {
      for (const refOffset of refInfo.offsets) {
        const dist = Math.abs(offset - refOffset);
        if (dist <= distance) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Evaluate module function call (e.g., string.to_int($version), time.now())
   */
  async evaluateModuleFunction(node) {
    const { module, function: functionName, args } = node;

    // Get the module from available modules
    const moduleObj = this.modules[module];
    if (!moduleObj) {
      // Return undefined when module is not available (e.g., pe module for non-PE files)
      // This allows conditions like "pe.imports(...)" to evaluate to undefined/false
      return undefined;
    }

    // Get the function from the module
    const func = moduleObj[functionName];
    if (typeof func !== "function") {
      // Return undefined if function not found in module
      return undefined;
    }

    // Evaluate arguments
    const evaluatedArgs = await Promise.all(
      args.map(async (arg) => {
        const result = await this.evaluateNode(arg);

        // For string identifiers, get the actual matched string value
        if (arg.type === "stringIdentifier") {
          const stringInfo = this.strings[arg.identifier];
          if (stringInfo && stringInfo.matches && stringInfo.matches.length > 0) {
            // Get the first match value
            const match = stringInfo.matches[0];
            if (match.value) {
              return match.value;
            }
            // If no value stored, try to extract from data
            if (this.data && match.offset !== undefined && match.length !== undefined) {
              const bytes = this.data.slice(match.offset, match.offset + match.length);
              return new TextDecoder().decode(bytes);
            }
          }
          return "";
        }

        return result;
      }),
    );

    // Call the function with evaluated arguments
    try {
      const result = func.apply(moduleObj, evaluatedArgs);
      // Handle both sync and async module functions
      return result instanceof Promise ? await result : result;
    } catch (error) {
      throw new Error(`Error calling ${module}.${functionName}: ${error.message}`);
    }
  }

  /**
   * Evaluate 'in' operator (value in (set))
   */
  async evaluateInOperator(node) {
    const value = await this.evaluateNode(node.value);
    const set = await this.evaluateNode(node.set);

    // YARA: in operator returns undefined if operands are undefined
    if (this.isAnyUndefined(value, set)) return undefined;

    if (Array.isArray(set)) {
      return set.includes(value);
    } else if (set && typeof set === "object" && set.start !== undefined && set.end !== undefined) {
      // Range
      return value >= set.start && value <= set.end;
    }

    return false;
  }

  /**
   * String contains (case-sensitive or insensitive)
   */
  async stringContains(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);

    // YARA: string operators return undefined if operands are undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }

    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }

    return left.includes(right);
  }

  /**
   * String starts with
   */
  async stringStartsWith(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);

    // YARA: string operators return undefined if operands are undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }

    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }

    return left.startsWith(right);
  }

  /**
   * String ends with
   */
  async stringEndsWith(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);

    // YARA: string operators return undefined if operands are undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }

    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }

    return left.endsWith(right);
  }

  /**
   * String equals (case-insensitive)
   */
  async stringEquals(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);

    // YARA: string operators return undefined if operands are undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }

    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }

    return left === right;
  }

  /**
   * String matches regex
   */
  async stringMatches(leftNode, rightNode) {
    const left = await this.evaluateNode(leftNode);
    const right = await this.evaluateNode(rightNode);

    // YARA: string operators return undefined if operands are undefined
    if (this.isAnyUndefined(left, right)) return undefined;

    if (typeof left !== "string") {
      return false;
    }

    let regex;
    if (right instanceof RegExp) {
      regex = right;
    } else if (typeof right === "string") {
      regex = new RegExp(right);
    } else {
      return false;
    }

    return regex.test(left);
  }
}

/**
 * Helper function to evaluate a condition against scan facts
 * @param {Object} condition - Condition AST
 * @param {ScanFacts} scanFacts - Scan results
 * @returns {Promise<boolean>} Evaluation result
 */
export async function evaluateCondition(condition, scanFacts) {
  const evaluator = new ConditionEvaluator(scanFacts);
  return evaluator.evaluate(condition);
}

/**
 * Batch evaluate multiple rules against scan facts
 * @param {Array<Object>} rules - Array of rule objects with condition
 * @param {ScanFacts} scanFacts - Scan results
 * @returns {Promise<Array<Object>>} Array of results { rule, matched, error }
 */
export async function evaluateRules(rules, scanFacts) {
  const evaluator = new ConditionEvaluator(scanFacts);
  const results = [];

  for (const rule of rules) {
    try {
      const matched = await evaluator.evaluate(rule.condition);
      results.push({
        rule: rule.name || rule.id,
        matched,
        error: null,
      });
    } catch (error) {
      results.push({
        rule: rule.name || rule.id,
        matched: false,
        error: error.message,
      });
    }
  }

  return results;
}

export default {
  createScanFacts,
  ConditionEvaluator,
  evaluateCondition,
  evaluateRules,
};
