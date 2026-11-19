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
 * YARA Scanner - End-to-End Implementation
 *
 * Complete YARA rule scanner that integrates:
 * - Rule compilation (yaraRuleCompiler.mjs)
 * - String pattern matching (yaraStringMatch.mjs)
 * - Aho-Corasick fast scanning (ahocorasickEngine.mjs)
 * - Condition parsing and evaluation (yaraConditionsMatch.mjs)
 * - Module support (math, hash, pe, etc.)
 */

import { AhoCorasick } from "./ahocorasickEngine.mjs";
import { parseYaraRuleGroup, parseInterceptFilterRuleGroup } from "./yaraRuleCompiler.mjs";
import { createScanFacts, evaluateCondition } from "./yaraConditionsMatch.mjs";
import { parseConditionToAST } from "./yaraConditionParser.mjs";
import { parsePEYara, createPEModule } from "./peModule.mjs";
import { parseELFYaraFull, createELFModule } from "./elfModule.mjs";
import { createMathModule } from "./mathModule.mjs";
import { createHashModule } from "./hashModule.mjs";
import { time as timeModule } from "./timeModule.mjs";
import { string as stringModule } from "./stringModule.mjs";
import { createPerformanceTracker } from "./performanceInstrumentation.mjs";
import { MAX_MATCHES } from "./yaraStringMatch.mjs";
import { isValidModuleName } from "./interceptCustomModules.mjs";

/**
 * Longest candidate buffer handed to filter rules. Longer matches keep the candidate and skip
 * filtering, so a filter never decides on a truncated prefix.
 */
export const MAX_FILTER_RULE_BUFFER_SIZE = 4096;

const FILTER_MODULE_BUILTINS = new Set(["string", "time", "math", "hash"]);

function hashBytes(bytes) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

/**
 * InterceptScanner - A JavaScript implementation of YARA rule scanning engine
 *
 * This class provides functionality to compile YARA rules and scan binary data
 * for pattern matches. It uses Aho-Corasick algorithm for fast multi-pattern
 * matching and supports YARA modules (PE, ELF, math, hash, string, time).
 *
 * @class InterceptScanner
 *
 * @example
 * // Basic usage
 * const scanner = new InterceptScanner();
 * scanner.compile(`
 *   rule ExampleRule {
 *     strings:
 *       $a = "malware"
 *       $b = /suspicious[0-9]+/
 *     condition:
 *       any of them
 *   }
 * `);
 * const results = await scanner.scan(binaryData);
 *
 * @example
 * // Results structure
 * [
 *   {
 *     rule: "ExampleRule",           // Name of the matched rule
 *     namespace: "default",           // Namespace (default if not specified)
 *     tags: ["tag1", "tag2"],        // Rule tags
 *     metadata: {                     // Rule metadata
 *       author: "...",
 *       description: "..."
 *     },
 *     strings: {                      // Matched strings with details
 *       "$a": {
 *         identifier: "$a",           // String identifier
 *         matched: true,              // Whether string was found
 *         count: 2,                   // Number of occurrences
 *         matches: [                  // Array of match details
 *           { offset: 100, length: 7 },
 *           { offset: 250, length: 7 }
 *         ],
 *         offsets: [100, 250],        // Array of match offsets
 *         length: 7                   // Length of matched string
 *       },
 *       "$b": {
 *         identifier: "$b",
 *         matched: false,
 *         count: 0,
 *         matches: [],
 *         offsets: [],
 *         length: null
 *       }
 *     }
 *   }
 * ]
 *
 * @property {Array} compiledRules - Array of compiled YARA rules
 * @property {AhoCorasick|null} ac - Aho-Corasick automaton for fast pattern matching
 * @property {boolean} autoParsePE - Automatically parse PE files (default: true)
 * @property {boolean} autoParseELF - Automatically parse ELF files (default: true)
 * @property {number} maxFileSize - Maximum file size for filesize operator (default: 1MB)
 * @property {number} maxMatches - Maximum matches recorded per string (default: 100)
 * @property {Object} modules - Available YARA modules (string, time, pe, elf, math, hash)
 */
export class InterceptScanner {
  constructor(options = {}) {
    this.compiledRules = [];
    this.compiledFilterRules = [];
    this.filterIndex = new Map();
    this.filterDiagnostics = [];
    this.filterScanDiagnostics = null;
    this.filterDecisionCache = new Map();
    this.filterModuleCache = new Map();
    this.ac = null;
    this.autoParsePE = true; // Automatically parse PE files
    this.autoParseELF = true; // Automatically parse ELF files
    this.maxFileSize = 1024 * 1024; // 1MB default limit for filesize operator
    this.setModules(options.modules);
    this.customModules = options.modules || {};
    this.matchLimits = { maxMatches: options.maxMatches ?? MAX_MATCHES };
    const timingOptions = {
      enabled: options.timing?.enabled ?? options.timing?.enableTiming ?? options.enableTiming ?? false,
      autoPrint: options.timing?.autoPrint ?? options.autoPrint ?? false,
      logger: options.timing?.logger ?? options.timingLogger ?? options.logger,
    };
    this.timingTracker = createPerformanceTracker(timingOptions);
  }

  /**
   * Add YARA rules from text (Same as addRules, but named compile for clarity)
   * @param {string} rulesText - YARA rules in text format
   */
  compile(rulesText) {
    const tracker = this.timingTracker;
    const timingEnabled = tracker?.isEnabled();
    const start = timingEnabled ? tracker.now() : 0;

    const filterGroup = parseInterceptFilterRuleGroup(rulesText, this.compiledFilterRules || [], {
      limits: this.matchLimits,
      availableModules: this.getAvailableModuleNames(),
    });
    this.compiledFilterRules = filterGroup.rules;
    this.filterDiagnostics = filterGroup.diagnostics || [];
    this.compiledRules = parseYaraRuleGroup(rulesText, this.compiledRules || [], { limits: this.matchLimits });
    this.validateFilterRegistry();
    this.rebuildFilterIndex();

    this.ac = null; // Reset AC automaton to force rebuild

    if (timingEnabled) {
      tracker.recordCompile(tracker.now() - start);
    } else if (tracker) {
      tracker.clearCompile();
    }
  }

  /**
   * Add YARA rules from text
   * @param {string} rulesText - YARA rules in text format
   */
  addRules(rulesText) {
    this.compile(rulesText);
  }

  /**
   * Remove all YARA rules
   */
  clearRules() {
    this.compiledRules = [];
    this.compiledFilterRules = [];
    this.filterIndex = new Map();
    this.filterDiagnostics = [];
    this.filterScanDiagnostics = null;
    this.filterDecisionCache = new Map();
    this.filterModuleCache = new Map();
    this.ac = null;
  }

  /**
   * Set modules for condition evaluation
   * @param {Object} modules - Module instances (pe, elf, math, hash, etc.)
   */
  setModules(modules) {
    this.modules = { string: stringModule, time: timeModule, ...(modules || {}) };
  }

  setTiming(timingOptions = {}) {
    this.timingTracker.updateOptions(timingOptions);
  }

  enableTiming(enable = true, logger) {
    this.timingTracker.enable(enable, logger);
  }

  getTiming() {
    return this.timingTracker.getSnapshot();
  }

  /**
   * Deduplicate candidate matches
   * @param {Array} candidates - Array of candidate matches from AC
   * @returns {Array} Deduplicated candidates
   */
  deduplicateCandidates(candidates) {
    const unique = new Map();
    for (const candidate of candidates) {
      const key = `${candidate.id}:${candidate.varName}:${candidate.offset}`;
      if (!unique.has(key)) {
        unique.set(key, candidate);
      }
    }
    return Array.from(unique.values());
  }

  /**
   * Verify candidates with full string matchers
   * @param {Array} candidates - Candidate matches
   * @param {Uint8Array} data - File data
   * @param {Array} rules - Compiled rules
   * @returns {Array} Verified matches
   */
  verifyCandidates(candidates, data, rules) {
    const verified = [];

    for (const candidate of candidates) {
      const rule = rules.find((r) => r.id === candidate.id);
      if (!rule) continue;

      const strDef = rule.strings[candidate.varName];
      if (!strDef || !strDef.matcher) continue;

      // For text and regex with literal prefix, verify at the candidate offset. `verifyAt` demands
      // a match starting exactly there; the plain window-scan form would also return a neighbouring
      // occurrence, which duplicates that match and loses this candidate's own.
      if (strDef.type === "text" || (strDef.type === "regex" && strDef.literalPrefix)) {
        const matches = typeof strDef.matcher.verifyAt === "function"
          ? strDef.matcher.verifyAt(data, candidate.offset)
          : strDef.matcher(data, candidate.offset);
        if (matches && matches.length > 0) {
          verified.push({
            ...candidate,
            matches: matches,
          });
        }
      } else {
        // For other types, just accept the candidate
        verified.push(candidate);
      }
    }

    return verified;
  }

  /**
   * Build string match results per rule. Reject filters are applied here, before any facts are
   * produced, so `#a`, `@a`, and `$a at N` only see surviving matches.
   * @param {Array} verifiedCandidates - Verified matches
   * @param {Array} rules - Compiled rules
   * @param {Uint8Array} data - File data
   * @param {Object} metadata - Scan metadata to pass to custom modules
   * @returns {Promise<Object>} String matches organized by rule
   */
  async buildStringMatches(verifiedCandidates, rules, data, metadata = {}) {
    const ruleMatches = {};

    // Initialize match structure for each rule
    for (const rule of rules) {
      ruleMatches[rule.id] = {};
      for (const varName of Object.keys(rule.strings)) {
        // Use variable name as-is since compiler now ensures proper prefixes ($ or .anon)
        // If coming from old compiler without $, add it for named strings
        const matchKey = varName.startsWith('$') || varName.startsWith('.') ? varName : `$${varName}`;
        const anonymousKey = matchKey.startsWith('.') ? `\$${matchKey}` : matchKey;
        
        // For compatibility with rest of system that expects $.anon for anonymous
        const finalKey = varName.startsWith('.') ? `\$${varName}` : matchKey;

        ruleMatches[rule.id][finalKey] = {
          identifier: finalKey,
          matched: false,
          count: 0,
          matches: [],
          offsets: [],
          // length: null,
          private: rule.strings[varName].private,
        };
      }
    }

    // Populate with verified matches
    for (const candidate of verifiedCandidates) {
       // Handle key lookup (handle $.anon for anonymous)
       const finalKey = candidate.varName.startsWith('.') ? `\$${candidate.varName}` : candidate.varName;
       // Fallback for strict $ requirement
       const lookupKey = ruleMatches[candidate.id][finalKey] ? finalKey : (finalKey.startsWith('$') ? finalKey : `\$${finalKey}`);
       
      const matchInfo = ruleMatches[candidate.id][lookupKey];
      const ownerRule = rules.find((rule) => rule.id === candidate.id);
      const strDef = ownerRule?.strings?.[candidate.varName];

      if (candidate.matches && candidate.matches.length > 0) {
        const keptMatches = strDef?.reject?.length
          ? await this.filterMatches(strDef, candidate.matches, data, metadata, {
              ruleName: ownerRule?.name,
              varName: candidate.varName,
            })
          : candidate.matches;
        if (keptMatches.length === 0) continue;

        // Has detailed match information
        const prunedList = keptMatches.length > this.maxMatches ? keptMatches.slice(0, this.maxMatches) : keptMatches;
        matchInfo.matched = true;
        matchInfo.count += prunedList.length;
        matchInfo.matches.push(...prunedList);
        matchInfo.offsets.push(...prunedList.map((m) => m.offset));
        // if (prunedList[0].length) {
        //   matchInfo.length = prunedList[0].length;
        // }
      } else {
        // Simple match
        matchInfo.matched = true;
        matchInfo.count += 1;
        matchInfo.matches.push({
          offset: candidate.offset,
          length: candidate.length || 0,
        });
        matchInfo.offsets.push(candidate.offset);
        // if (candidate.length) {
        //   matchInfo.length = candidate.length;
        // }
      }
    }

    // Run string matches that could not be optimized via AC
    let dataAsHexString = null;
    for (const rule of rules) {
      for (const [varName, strDef] of Object.entries(rule.strings)) {
        if (strDef.type === "text" || (strDef.type === "regex" && strDef.literalPrefix?.length > 0)) continue; // Should be part of AC verified candidates

        // Handle key lookup (handle $.anon for anonymous)
        const finalKey = varName.startsWith('.') ? `\$${varName}` : varName;
        const lookupKey = ruleMatches[rule.id][finalKey] ? finalKey : (finalKey.startsWith('$') ? finalKey : `\$${finalKey}`);
        
        const matchInfo = ruleMatches[rule.id][lookupKey];

        // Build cache hex string if needed
        if (strDef.type === "hex" && dataAsHexString === null) {
          dataAsHexString = Array.from(data)
            .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
            .join("");
        }

        // Run full matcher over entire data (-1 means find ALL matches, not verify at offset 0)
        let matches = strDef.type === "hex" && dataAsHexString !== null ? strDef.matcher(dataAsHexString, -1) : strDef.matcher(data, -1);
        if (strDef.reject?.length && matches && matches.length > 0) {
          matches = await this.filterMatches(strDef, matches, data, metadata, { ruleName: rule.name, varName });
        }
        if (matches && matches.length > 0) {
          const prunedList = matches.length > this.maxMatches ? matches.slice(0, this.maxMatches) : matches;
          matchInfo.matched = true;
          matchInfo.count += prunedList.length;
          if (matchInfo.matches.length === 0) {
            matchInfo.matches = prunedList; // Replace if empty
          } else {
            matchInfo.matches.push(...prunedList);
          }
          matchInfo.offsets.push(...prunedList.map((m) => m.offset));
          // if (prunedList[0].length) {
          //   matchInfo.length = prunedList[0].length;
          // }
        }
      }
    }

    return ruleMatches;
  }

  /**
   * Reject filter registry / gate helpers
   */

  validateFilterRegistry() {
    const ruleNames = new Set(this.compiledRules.map((rule) => rule.name));
    for (const filter of this.compiledFilterRules) {
      if (ruleNames.has(filter.name)) {
        throw new Error(`Filter rule "${filter.name}" collides with a rule of the same name`);
      }
    }

    const filterNames = new Set(this.compiledFilterRules.map((filter) => filter.name));
    for (const rule of this.compiledRules) {
      for (const [varName, strDef] of Object.entries(rule.strings || {})) {
        for (const filterName of strDef.reject ?? []) {
          if (!filterNames.has(filterName)) {
            this.filterDiagnostics.push({
              code: "unknown-filter-rule",
              severity: "warning",
              message: `String ${varName} in rule "${rule.name}" references unknown filter rule "${filterName}"`,
              rule: rule.name,
              string: varName,
              filter: filterName,
            });
          }
        }
      }
    }
  }

  rebuildFilterIndex() {
    this.filterIndex = new Map(this.compiledFilterRules.map((rule) => [rule.name, rule]));
  }

  /**
   * Module keywords available to filter conditions. Custom modules are addressed by the keyword
   * their `getName()` returns, which need not match the key they were registered under.
   */
  getAvailableModuleNames() {
    const names = new Set(Object.keys(this.modules || {}));
    for (const moduleValue of Object.values(this.modules || {})) {
      if (typeof moduleValue?.getName === "function") {
        names.add(moduleValue.getName());
      }
    }
    return [...names];
  }

  ensureFilterScanDiagnostics() {
    if (!this.filterScanDiagnostics) {
      this.filterScanDiagnostics = { oversized: new Map(), errors: new Map(), rejections: new Map() };
    }
    return this.filterScanDiagnostics;
  }

  resetFilterScanState() {
    this.filterScanDiagnostics = { oversized: new Map(), errors: new Map(), rejections: new Map() };
    this.filterDecisionCache = new Map();
    this.filterModuleCache = new Map();
  }

  async filterMatches(strDef, matches, data, metadata, context = {}) {
    if (!strDef || !Array.isArray(strDef.reject) || strDef.reject.length === 0) return matches;

    const kept = [];
    for (const match of matches) {
      if (await this.isRejectedMatch(strDef, match, data, metadata, context)) continue;
      kept.push(match);
    }
    return kept;
  }

  async isRejectedMatch(strDef, match, data, metadata, { ruleName, varName } = {}) {
    const filterNames = strDef?.reject;
    if (!Array.isArray(filterNames) || filterNames.length === 0) return false;

    const length = match?.length ?? 0;
    if (length <= 0) return false;

    const diagnostics = this.ensureFilterScanDiagnostics();

    if (length > MAX_FILTER_RULE_BUFFER_SIZE) {
      const key = `${ruleName}:${varName}:${match.offset}:${length}`;
      if (!diagnostics.oversized.has(key)) {
        diagnostics.oversized.set(key, {
          code: "filter-buffer-too-large",
          severity: "warning",
          message: `Candidate for ${varName} in rule "${ruleName}" is ${length} bytes, exceeding MAX_FILTER_RULE_BUFFER_SIZE (${MAX_FILTER_RULE_BUFFER_SIZE}); filters were skipped`,
          rule: ruleName,
          string: varName,
        });
      }
      return false;
    }

    const buffer = data.subarray(match.offset, match.offset + length);

    for (const filterName of filterNames) {
      const filter = this.filterIndex.get(filterName);
      if (!filter) continue; // Unknown names are ignored (diagnosed at compile time)

      if (await this.getFilterDecision(filter, buffer, metadata)) {
        diagnostics.rejections.set(filterName, (diagnostics.rejections.get(filterName) ?? 0) + 1);
        return true;
      }
    }

    return false;
  }

  async getFilterDecision(filter, buffer, metadata) {
    const cacheKey = `${filter.name}:${buffer.length}:${hashBytes(buffer)}`;
    const cached = this.filterDecisionCache.get(cacheKey);
    if (cached && cached.buffer.length === buffer.length && cached.buffer.every((byte, i) => byte === buffer[i])) {
      return cached.rejected;
    }

    const rejected = await this.evaluateFilterRule(filter, buffer, metadata);
    this.filterDecisionCache.set(cacheKey, { buffer, rejected });
    return rejected;
  }

  async evaluateFilterRule(filter, buffer, metadata = {}) {
    try {
      const stringMatches = this.matchFilterStrings(filter, buffer);
      const modules = await this.createFilterModules(filter, buffer, metadata);
      const scanFacts = createScanFacts(buffer, stringMatches, modules, {
        entrypoint: 0,
        filesize: buffer.length,
        isFileSizeCapped: false,
        maxFileSize: this.maxFileSize,
        matchedRules: {},
        metadata: { ruleName: filter.name },
      });

      let ast = filter.conditionAST;
      if (!ast) {
        try {
          ast = this.parseSimpleCondition(filter.condition, scanFacts.strings);
        } catch {
          ast = { type: "boolean", value: false };
        }
        filter.conditionAST = ast;
      }

      return (await evaluateCondition(ast, scanFacts)) === true;
    } catch (error) {
      this.recordFilterError(filter.name, error);
      return false;
    }
  }

  matchFilterStrings(filter, buffer) {
    const stringMatches = {};

    for (const [varName, strDef] of Object.entries(filter.strings || {})) {
      if (typeof strDef.matcher !== "function") {
        stringMatches[varName] = [];
        continue;
      }

      try {
        const matches = strDef.matcher(buffer, -1);
        stringMatches[varName] = Array.isArray(matches) ? matches : [];
      } catch (error) {
        this.recordFilterError(filter.name, error);
        stringMatches[varName] = [];
      }
    }

    return stringMatches;
  }

  async createFilterModules(filter, buffer, metadata = {}) {
    const modules = {
      string: this.modules.string,
      time: this.modules.time,
      math: createMathModule(buffer),
      hash: createHashModule(buffer),
    };

    const usedModules = filter.usedModules ?? [];
    if (usedModules.length === 0) return modules;

    // Custom modules are resolved by their `getName()` keyword, not their registration key.
    const customModules = new Map();
    for (const moduleValue of Object.values(this.modules || {})) {
      if (typeof moduleValue?.getName === "function") {
        customModules.set(moduleValue.getName(), moduleValue);
      }
    }

    for (const moduleName of usedModules) {
      if (FILTER_MODULE_BUILTINS.has(moduleName)) continue;

      const moduleValue = customModules.get(moduleName);
      if (!moduleValue) continue;

      const cacheKey = `${moduleName}:${buffer.length}:${hashBytes(buffer)}`;
      if (this.filterModuleCache.has(cacheKey)) {
        modules[moduleName] = this.filterModuleCache.get(cacheKey);
        continue;
      }

      if (typeof moduleValue.isLoaded === "function" && !moduleValue.isLoaded() && typeof moduleValue.load === "function") {
        await moduleValue.load();
      }

      let moduleObject = moduleValue;
      if (typeof moduleValue.initialize === "function" && typeof moduleValue.createModule === "function") {
        const interimResults = await moduleValue.initialize(buffer, {
          ...(metadata || {}),
          filesize: buffer.length,
          hasPE: false,
          hasELF: false,
          timestamp: Date.now(),
        });
        moduleObject = moduleValue.createModule(interimResults);
      }

      this.filterModuleCache.set(cacheKey, moduleObject);
      modules[moduleName] = moduleObject;
    }

    return modules;
  }

  recordFilterError(filterName, error) {
    const diagnostics = this.ensureFilterScanDiagnostics();
    const message = error?.message ?? String(error);
    const key = `${filterName}:${message}`;
    if (diagnostics.errors.has(key)) return;

    diagnostics.errors.set(key, {
      code: "filter-error",
      severity: "warning",
      message: `Filter rule "${filterName}" failed and was treated as not rejecting: ${message}`,
      filter: filterName,
    });
  }

  attachResultDiagnostics(results) {
    const diagnostics = [...this.filterDiagnostics];

    if (this.filterScanDiagnostics) {
      diagnostics.push(...this.filterScanDiagnostics.errors.values());
      diagnostics.push(...this.filterScanDiagnostics.oversized.values());
      for (const [filterName, count] of this.filterScanDiagnostics.rejections) {
        diagnostics.push({
          code: "filter-rejection-count",
          severity: "info",
          message: `Filter rule "${filterName}" rejected ${count} candidate(s)`,
          filter: filterName,
        });
      }
    }

    Object.defineProperty(results, "diagnostics", {
      value: diagnostics,
      enumerable: false,
      configurable: true,
    });

    return results;
  }

  /**
   * Evaluate named filter rules against a buffer directly.
   *
   * Result shape matches `scan()` (matched rules only). Unknown names are skipped silently.
   * Custom modules are initialized from the supplied metadata, exactly as `scan()` does.
   *
   * @param {Uint8Array|string} data - Buffer to evaluate
   * @param {Object} metadata - Scan metadata for custom modules
   * @param {string[]} ruleNames - Filter rule names to evaluate
   * @returns {Promise<Array>} Matched filter rules
   */
  async scanFilterRules(data, metadata = {}, ruleNames = []) {
    if (typeof data === "string") {
      data = new TextEncoder().encode(data);
    }

    this.resetFilterScanState();

    const matchedRules = [];

    for (const filterName of Array.isArray(ruleNames) ? ruleNames : []) {
      const filter = this.filterIndex.get(filterName);
      if (!filter) continue;

      let scanFacts = null;
      let matched = false;

      try {
        const stringMatches = this.matchFilterStrings(filter, data);
        const modules = await this.createFilterModules(filter, data, metadata);
        scanFacts = createScanFacts(data, stringMatches, modules, {
          entrypoint: 0,
          filesize: data.length,
          isFileSizeCapped: data.length >= this.maxFileSize,
          maxFileSize: this.maxFileSize,
          matchedRules: {},
          metadata: { ruleName: filter.name },
        });

        let ast = filter.conditionAST;
        if (!ast) {
          try {
            ast = this.parseSimpleCondition(filter.condition, scanFacts.strings);
          } catch {
            ast = { type: "boolean", value: false };
          }
          filter.conditionAST = ast;
        }

        matched = (await evaluateCondition(ast, scanFacts)) === true;
      } catch (error) {
        this.recordFilterError(filter.name, error);
        matched = false;
      }

      if (matched && scanFacts) {
        const filteredStrings = {};
        for (const [key, value] of Object.entries(scanFacts.strings)) {
          // Anonymous strings surface as `.anon_N` in raw facts; drop them and private strings,
          // matching the normal rule output shape.
          if (key.startsWith(".") || key.startsWith("$.")) continue;
          if (value.private || filter.strings[key]?.private) continue;
          filteredStrings[key] = value;
        }

        matchedRules.push({
          rule: filter.name,
          namespace: "default",
          tags: filter.tags || [],
          metadata: filter.metadata || {},
          strings: filteredStrings,
        });
      }
    }

    return this.attachResultDiagnostics(matchedRules);
  }

  /**
   * Evaluate rule conditions
   * @param {Object} ruleMatches - String matches per rule
   * @param {Array} rules - Compiled rules
   * @param {Uint8Array} data - File data
   * @param {Object} metadata - Scan metadata to pass to custom modules
   * @param {Object} timingContext - Timing context for performance tracking
   * @returns {Array} Rules that matched
   */
  async evaluateConditions(ruleMatches, rules, data, metadata = {}, timingContext = null) {
    const matchedRules = [];
    // Track which rules have matched (for dependent rules)
    const ruleMatchStatus = {};
    const tracker = timingContext?.tracker;
    const modulesTiming = timingContext?.modules;

    // Try to parse PE if auto-parse is enabled and PE module not already provided
    let peModule = this.modules.pe;
    if (this.autoParsePE && !peModule) {
      const start = tracker ? tracker.now() : 0;
      try {
        // Check for MZ signature
        if (data.length > 2 && data[0] === 0x4d && data[1] === 0x5a) {
          const parsedPE = await parsePEYara(data);
          if (parsedPE && !parsedPE.error) {
            peModule = createPEModule(parsedPE);
          }
        } else {
          // Data does not have MZ signature, skipping PE parse.
        }
      } catch {
        // PE parsing failed, continue without PE module
      } finally {
        if (tracker && modulesTiming) {
          tracker.accumulateModule(modulesTiming, "pe", tracker.now() - start);
        }
      }
    }

    // Try to parse ELF if auto-parse is enabled and ELF module not already provided
    let elfModule = this.modules.elf;
    if (this.autoParseELF && !elfModule) {
      const start = tracker ? tracker.now() : 0;
      try {
        // Check for ELF magic signature (0x7F 'E' 'L' 'F')
        if (data.length > 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) {
          const parsedELF = await parseELFYaraFull(data);
          if (parsedELF && !parsedELF.error) {
            elfModule = createELFModule(parsedELF);
          }
        }
      } catch {
        // ELF parsing failed, continue without ELF module
      } finally {
        if (tracker && modulesTiming) {
          tracker.accumulateModule(modulesTiming, "elf", tracker.now() - start);
        }
      }
    }

    // Merge PE, ELF, math & hash modules with existing modules
    const modulesWithBinary = {
      ...this.modules,
      ...(peModule && { pe: peModule }),
      ...(elfModule && { elf: elfModule }),
    };

    const mathStart = tracker ? tracker.now() : 0;
    modulesWithBinary.math = createMathModule(data);
    if (tracker && modulesTiming) {
      tracker.accumulateModule(modulesTiming, "math", tracker.now() - mathStart);
    }

    const hashStart = tracker ? tracker.now() : 0;
    modulesWithBinary.hash = createHashModule(data);
    if (tracker && modulesTiming) {
      tracker.accumulateModule(modulesTiming, "hash", tracker.now() - hashStart);
    }

    // Initialize custom modules from this.modules
    // Check each module to see if it's a custom module (has getName() method and non-reserved name)
    // `modulesWithBinary` already holds the same instances under their registration keys, so the
    // collision that matters is two *custom* modules claiming one keyword — tracked separately.
    const claimedKeywords = new Set();
    for (const [key, moduleValue] of Object.entries(this.modules)) {
      try {
        // Check if this is a custom module by seeing if it has the custom module interface
        if (typeof moduleValue?.getName === 'function') {
          const moduleName = moduleValue.getName();
          
          // Validate it's not a reserved name
          if (!isValidModuleName(moduleName)) {
            console.warn(`InterceptScanner: Custom module "${moduleName}" has reserved name - skipping initialization`);
            continue;
          }

          // Load module if not already loaded (lazy loading)
          if (typeof moduleValue.isLoaded === 'function' && !moduleValue.isLoaded()) {
            const loadStart = tracker ? tracker.now() : 0;
            if (typeof moduleValue.load === 'function') {
              await moduleValue.load();
            }
            if (tracker && modulesTiming) {
              tracker.accumulateModule(modulesTiming, `${moduleName}_load`, tracker.now() - loadStart);
            }
          }

          // Initialize and create module for this scan
          const moduleStart = tracker ? tracker.now() : 0;
          
          // Merge passed metadata with computed values
          const scanMetadata = {
            ...metadata,
            filesize: data.length,
            hasPE: !!peModule,
            hasELF: !!elfModule,
            timestamp: Date.now(),
          };
          
          let moduleObject = moduleValue;
          if (typeof moduleValue.initialize === 'function' && typeof moduleValue.createModule === 'function') {
            const interimResults = await moduleValue.initialize(data, scanMetadata);
            moduleObject = moduleValue.createModule(interimResults);
          }

          if (tracker && modulesTiming) {
            tracker.accumulateModule(modulesTiming, moduleName, tracker.now() - moduleStart);
          }

          // Conditions reach a custom module by the keyword its `getName()` returns — the key it was
          // registered under is irrelevant. Two instances sharing a name therefore overwrite each
          // other, and the rule silently reads the wrong URL/facts. Say so once per scan.
          if (claimedKeywords.has(moduleName)) {
            console.warn(`InterceptScanner: duplicate custom module name "${moduleName}" - the later instance replaces the earlier one`);
          }
          claimedKeywords.add(moduleName);

          // Add to modules available for condition evaluation
          modulesWithBinary[moduleName] = moduleObject;
        }
      } catch (error) {
        console.warn(`InterceptScanner: Error initializing custom module "${key}": ${error.message}`);
      }
    }

    // Extract global rules first
    const globalRules = rules.filter((rule) => rule.global);
    for (const rule of globalRules) {
      const result = await this.evaluateRuleCondition(
        ruleMatches,
        rule,
        data,
        ruleMatchStatus,
        { peModule, elfModule, modulesWithBinary },
        timingContext,
      );
      if (result) {
        if (!rule.private) {
          matchedRules.push(result);
        }
      } else {
        // Stop early for global rules if one fails
        return matchedRules;
      }
    }

    const nonGlobalRules = rules.filter((rule) => !rule.global);
    for (const rule of nonGlobalRules) {
      const result = await this.evaluateRuleCondition(
        ruleMatches,
        rule,
        data,
        ruleMatchStatus,
        { peModule, elfModule, modulesWithBinary },
        timingContext,
      );
      if (result && !rule.private) {
        matchedRules.push(result);
      }
    }

    // Includes non-function module data for downstream evaluations
    for (const [moduleName, moduleInstance] of Object.entries(modulesWithBinary)) {
      // Skip built-in modules that are function-based
      if (["string", "time", "hash", "math"].includes(moduleName)) {
        continue;
      }
      // Copy non-functions only & remove any data arrays (like raw_data or data)
      matchedRules[moduleName] = {};
      for (const [key, value] of Object.entries(moduleInstance)) {
        // Skip functions and constants and _* keys (assume all uppercase keys are constants)
        if (!key.startsWith("_") && typeof value !== "function" && !/[A-Z0-9]+/.test(key)) {
          matchedRules[moduleName][key] = typeof value === "object" ? removeKeyDeep({ ... value }, ["raw_data", "data"]) : value;
        }
      }
    }

    return matchedRules;
  }

  async evaluateRuleCondition(ruleMatches, rule, data, ruleMatchStatus, modules = {}, timingContext = null) {
    const { peModule, elfModule, modulesWithBinary } = modules;
    const tracker = timingContext?.tracker;
    const conditionTiming = timingContext?.condition;
    try {
      // Create scan facts for this rule
      // Use entry point from PE or ELF module, with preference for PE
      // For non-binary files, YARA defaults to 0
      const entrypoint = peModule ? peModule.entry_point : elfModule ? elfModule.entry_point : -1e6;

      // Calculate filesize with cap awareness
      const actualFileSize = data.length;
      const isFileSizeCapped = actualFileSize >= this.maxFileSize;

      const scanFacts = createScanFacts(data, ruleMatches[rule.id], modulesWithBinary, {
        entrypoint,
        filesize: actualFileSize,
        isFileSizeCapped: isFileSizeCapped,
        maxFileSize: this.maxFileSize,
        matchedRules: ruleMatchStatus, // Pass matched rules for dependent rule evaluation
        metadata: {
          ruleName: rule.name,
        },
      });

      // Parse condition to AST
      let conditionAST;
      const parseStart = tracker ? tracker.now() : 0;
      try {
        conditionAST = parseConditionToAST(rule.condition, scanFacts.strings);
      } catch {
        // If parsing fails, try simple evaluation
        conditionAST = this.parseSimpleCondition(rule.condition, scanFacts.strings);
      } finally {
        if (tracker && conditionTiming) {
          tracker.accumulateCondition(conditionTiming, rule.name, tracker.now() - parseStart);
        }
      }

      // Evaluate condition
      const matched = await evaluateCondition(conditionAST, scanFacts);

      // Track this rule's match status for dependent rules
      ruleMatchStatus[rule.name] = matched;

      if (matched) {
        // Filter out anonymous strings (those starting with ".anon_") from output
        const filteredStrings = {};
        for (const [key, value] of Object.entries(ruleMatches[rule.id])) {
          // Only include strings that don't start with "$." (anonymous strings)
          if (!key.startsWith("$.") && !value.private) {
            filteredStrings[key] = value;
          }
        }

        // Return matched rule details
        return {
          rule: rule.name,
          namespace: rule.namespace || "default",
          tags: rule.tags || [],
          metadata: rule.metadata || {},
          strings: filteredStrings,
        };
      }
    } catch (error) {
      console.debug("Failing rule: ", rule);
      console.trace(error);
    }
    return false;
  }

  /**
   * Parse simple conditions (fallback parser)
   * Handles common patterns: $a, any of them, all of them, N of them
   * @param {string} condition - Condition string
   * @param {Object} strings - String match information
   * @returns {Object} AST node
   */
  parseSimpleCondition(condition, strings) {
    condition = condition.trim();

    // Handle "any of them"
    if (condition === "any of them") {
      return { type: "any", items: "them" };
    }

    // Handle "all of them"
    if (condition === "all of them") {
      return { type: "all", items: "them" };
    }

    // Handle "none of them"
    if (condition === "none of them") {
      return { type: "none", items: "them" };
    }

    // Handle "N of them"
    const nOfThemMatch = condition.match(/^(\d+)\s+of\s+them$/);
    if (nOfThemMatch) {
      return {
        type: "quantified",
        quantifier: { type: "number", value: parseInt(nOfThemMatch[1]) },
        items: "them",
      };
    }

    // Handle single string identifier "$a"
    const singleStringMatch = condition.match(/^\$(\w+)$/);
    if (singleStringMatch) {
      return {
        type: "stringIdentifier",
        identifier: `$${singleStringMatch[1]}`,
      };
    }

    // Handle "($a and $b)"
    const andMatch = condition.match(/^\(?(\$\w+)\s+and\s+(\$\w+)\)?$/);
    if (andMatch) {
      return {
        type: "and",
        left: { type: "stringIdentifier", identifier: andMatch[1] },
        right: { type: "stringIdentifier", identifier: andMatch[2] },
      };
    }

    // Handle "($a or $b)"
    const orMatch = condition.match(/^\(?(\$\w+)\s+or\s+(\$\w+)\)?$/);
    if (orMatch) {
      return {
        type: "or",
        left: { type: "stringIdentifier", identifier: orMatch[1] },
        right: { type: "stringIdentifier", identifier: orMatch[2] },
      };
    }

    // Default: if any string in condition is matched, return true
    // This is a very simple fallback
    // const stringIds = Object.keys(strings);
    // for (const id of stringIds) {
    //   if (condition.includes(id) && strings[id].matched) {
    //     return { type: "boolean", value: true };
    //   }
    // }

    return { type: "boolean", value: false };
  }

  filterStringResults(ruleMatches) {
    if (!Array.isArray(ruleMatches)) return;
    ruleMatches.forEach((ruleMatch) => {
      if (Object.keys(ruleMatch.strings).length > 0) {
        for (const [strId, strInfo] of Object.entries(ruleMatch.strings)) {
          if (!strInfo.matched) {
            delete ruleMatch.strings[strId];
          }
        }
      }
    });
  }

  /**
   * Scan binary data with all loaded rules
   * @param {Uint8Array|string} data - Data to scan
   * @returns {Promise<Array>} Matched rules with details
   */
  async scan(data, metadata = {}) {
    const tracker = this.timingTracker;
    const timingEnabled = tracker?.isEnabled();
    const totalStart = timingEnabled ? tracker.now() : 0;
    const scanTiming = timingEnabled ? tracker.createScanTiming() : null;

    // Convert string to Uint8Array if needed
    if (typeof data === "string") {
      const encoder = new TextEncoder();
      data = encoder.encode(data);
    }

    this.resetFilterScanState();

    if (!this.compiledRules || this.compiledRules.length === 0) {
      if (timingEnabled && scanTiming) {
        scanTiming.total = tracker.now() - totalStart;
        scanTiming.matchCount = 0;
        tracker.finalizeScan(scanTiming);
      } else if (tracker) {
        tracker.clearScan();
      }
      return this.attachResultDiagnostics([]);
    }

    // Phase 1: Fast candidate detection with Aho-Corasick
    if (!this.ac) {
      if (timingEnabled && scanTiming) {
        const start = tracker.now();
        this.ac = new AhoCorasick(this.compiledRules);
        tracker.accumulateStep(scanTiming.steps, "buildAutomaton", tracker.now() - start);
      } else {
        this.ac = new AhoCorasick(this.compiledRules);
      }
    }

    const acSearchStart = timingEnabled ? tracker.now() : 0;
    const candidates = this.ac.search(data);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "acSearch", tracker.now() - acSearchStart);
    }

    const dedupeStart = timingEnabled ? tracker.now() : 0;
    const unique = this.deduplicateCandidates(candidates);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "deduplicate", tracker.now() - dedupeStart);
    }

    const verifyStart = timingEnabled ? tracker.now() : 0;
    const verified = this.verifyCandidates(unique, data, this.compiledRules);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "verifyCandidates", tracker.now() - verifyStart);
    }

    const buildStart = timingEnabled ? tracker.now() : 0;
    const ruleMatches = await this.buildStringMatches(verified, this.compiledRules, data, metadata);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "buildMatches", tracker.now() - buildStart);
    }

    let evaluationContext = null;
    let evaluateStart = 0;
    if (timingEnabled && scanTiming) {
      evaluationContext = {
        tracker,
        modules: scanTiming.modules,
        condition: scanTiming.conditionParsing,
      };
      evaluateStart = tracker.now();
    }

    const results = await this.evaluateConditions(ruleMatches, this.compiledRules, data, metadata, evaluationContext);

    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "evaluateConditions", tracker.now() - evaluateStart);
    }

    const filterStart = timingEnabled ? tracker.now() : 0;
    this.filterStringResults(results);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "filterStrings", tracker.now() - filterStart);
      scanTiming.total = tracker.now() - totalStart;
      scanTiming.matchCount = results.length;
      tracker.finalizeScan(scanTiming);
    } else if (tracker) {
      tracker.clearScan();
    }

    return this.attachResultDiagnostics(results);
  }

  /**
   * Set maximum file size limit for filesize operator
   * @param {number} size - Maximum file size in bytes
   */
  setMaxFileSize(size) {
    this.maxFileSize = size;
  }

  // Backed by `matchLimits`, the object shared with compiled string matchers, so changing the
  // cap takes effect for rules that were already compiled.
  get maxMatches() {
    return this.matchLimits.maxMatches;
  }

  set maxMatches(value) {
    this.matchLimits.maxMatches = value;
  }

  /**
   * Get statistics about loaded rules
   * @returns {Object} Rule statistics
   */
  getStats() {
    return {
      totalRules: this.compiledRules.length,
      totalFilterRules: this.compiledFilterRules.length,
      ruleNames: this.compiledRules.map((r) => r.name),
      rulesWithStrings: this.compiledRules.filter((r) => Object.keys(r.strings).length > 0).length,
      totalStrings: this.compiledRules.reduce((sum, r) => sum + Object.keys(r.strings).length, 0),
      totalPatterns: this.compiledRules.reduce((sum, r) => {
        return (
          sum +
          Object.values(r.strings).reduce((s, str) => {
            return s + (str.patterns ? str.patterns.length : 0);
          }, 0)
        );
      }, 0),
      acBuilt: this.ac !== null,
      maxFileSize: this.maxFileSize,
    };
  }

  /**
   * Clear all loaded rules
   */
  clear() {
    this.clearRules();
    // Reset existing modules
    this.setModules(this.customModules);
  }
}


function removeKeyDeep(value, keysToRemove) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(v => removeKeyDeep(v, keysToRemove));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([k]) => !keysToRemove.includes(k))
        .map(([k, v]) => [k, removeKeyDeep(v, keysToRemove)])
    );
  }

  return value;
}

// Remove large arrays from object recursively (Prevent huge outputs to backend)
function removeArrays(value, size = 20) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.length > size ? [] : value.map(v => removeArrays(v, size));
  }

  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (v !== null && (typeof v === "object" || Array.isArray(v))) {
        value[k] = removeArrays(v, size);
      }
    }
  }

  return value;
}

export { InterceptScanner as YaraScanner };
