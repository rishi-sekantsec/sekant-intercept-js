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
import { parseYaraRuleGroup } from "./yaraRuleCompiler.mjs";
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
 * @property {Object} modules - Available YARA modules (string, time, pe, elf, math, hash)
 */
export class InterceptScanner {
  constructor(options = {}) {
    this.compiledRules = [];
    this.ac = null;
    this.autoParsePE = true; // Automatically parse PE files
    this.autoParseELF = true; // Automatically parse ELF files
    this.maxFileSize = 1024 * 1024; // 1MB default limit for filesize operator
    this.setModules(options.modules);
    this.customModules = options.modules || {};
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
    this.compiledRules = parseYaraRuleGroup(rulesText, this.compiledRules || []);
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

      // For text and regex with literal prefix, verify at the candidate offset
      if (strDef.type === "text" || (strDef.type === "regex" && strDef.literalPrefix)) {
        const matches = strDef.matcher(data, candidate.offset);
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
   * Build string match results per rule
   * @param {Array} verifiedCandidates - Verified matches
   * @param {Array} rules - Compiled rules
   * @param {Uint8Array} data - File data
   * @returns {Object} String matches organized by rule
   */
  buildStringMatches(verifiedCandidates, rules, data) {
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

      if (candidate.matches && candidate.matches.length > 0) {
        // Has detailed match information
        const prunedList = candidate.matches.length > MAX_MATCHES ? candidate.matches.slice(0, MAX_MATCHES) : candidate.matches;
        matchInfo.matched = true;
        matchInfo.count += prunedList.length;
        matchInfo.matches.push(...prunedList);
        matchInfo.offsets.push(...candidate.matches.map((m) => m.offset));
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
        if (matches && matches.length > 0) {
          const prunedList = matches.length > MAX_MATCHES ? matches.slice(0, MAX_MATCHES) : matches;
          matchInfo.matched = true;
          matchInfo.count += prunedList.length;
          if (matchInfo.matches.length === 0) {
            matchInfo.matches = prunedList; // Replace if empty
          } else {
            matchInfo.matches.push(...prunedList);
          }
          matchInfo.offsets.push(...matches.map((m) => m.offset));
          // if (prunedList[0].length) {
          //   matchInfo.length = prunedList[0].length;
          // }
        }
      }
    }

    return ruleMatches;
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
      console.log("Failing rule: ", rule);
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

    if (!this.compiledRules || this.compiledRules.length === 0) {
      if (timingEnabled && scanTiming) {
        scanTiming.total = tracker.now() - totalStart;
        scanTiming.matchCount = 0;
        tracker.finalizeScan(scanTiming);
      } else if (tracker) {
        tracker.clearScan();
      }
      return [];
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
    const ruleMatches = this.buildStringMatches(verified, this.compiledRules, data);
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

    return results;
  }

  /**
   * Set maximum file size limit for filesize operator
   * @param {number} size - Maximum file size in bytes
   */
  setMaxFileSize(size) {
    this.maxFileSize = size;
  }

  /**
   * Get statistics about loaded rules
   * @returns {Object} Rule statistics
   */
  getStats() {
    return {
      totalRules: this.compiledRules.length,
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
    this.compiledRules = [];
    this.ac = null;
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
