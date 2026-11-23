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

import { compileYaraLike } from './yaraStringMatch.mjs';
import { parseConditionToAST } from './yaraConditionParser.mjs';

const RULE_START_RE = /^\s*(?:\s*(?:private|global)\s+)*rule\b/i;
const FILTER_RULE_START_RE = /^\s*(?:\s*(?:private|global)\s+)*filter\s+rule\b/i;
const BUILTIN_MODULE_NAMES = new Set(['pe', 'elf', 'math', 'hash', 'string', 'time']);

/**
 * List of supported YARA modules
 * All modules are automatically available, but imports are validated
 */
const SUPPORTED_MODULES = [
  'pe',      // Windows PE file format module
  'elf',     // Linux/Unix ELF file format module
  'math',    // Mathematical and statistical functions
  'hash',    // Cryptographic hash functions (MD5, SHA1, SHA256, CRC32)
  'time',    // Time-related functions
  'string',  // String manipulation functions
];

/**
 * Parse import statements from YARA rule text
 * Validates that all imported modules are supported
 * @param {string} text - The YARA rule text (before comment stripping)
 * @returns {string[]} Array of imported module names
 * @throws {Error} If an unsupported module is imported
 */
function parseImports(text) {
  const imports = [];
  const importRegex = /^\s*import\s+"(\w+)"\s*$/gm;
  let match;
  
  while ((match = importRegex.exec(text)) !== null) {
    const moduleName = match[1];
    
    // Validate that the module is supported
    if (!SUPPORTED_MODULES.includes(moduleName)) {
      throw new Error(
        `Unsupported module import: "${moduleName}". ` +
        `Supported modules are: ${SUPPORTED_MODULES.join(', ')}. ` +
        `Note: All supported modules are automatically available; ` +
        `the import statement is only for validation.`
      );
    }
    
    imports.push(moduleName);
  }
  
  return imports;
}

/**
 * A regex literal only starts where YARA allows one: after the `=` of a string definition, or
 * after the `matches` operator. Everywhere else `/` is just a character.
 */
function isRegexStart(text, index) {
  let p = index - 1;
  while (p >= 0 && (text[p] === ' ' || text[p] === '\t')) p--;
  if (p < 0) return false;
  if (text[p] === '=') return true;

  let wordStart = p;
  while (wordStart >= 0 && /[A-Za-z_]/.test(text[wordStart])) wordStart--;
  return text.slice(wordStart + 1, p + 1) === 'matches';
}

/** Index of the closing slash of the regex literal starting at `start`, or -1 if it never closes. */
function findRegexEnd(text, start) {
  for (let i = start + 1; i < text.length; i++) {
    if (text[i] === '\\') {
      i += 1; // escaped character, including \/
    } else if (text[i] === '/') {
      return i;
    } else if (text[i] === '\n') {
      return -1; // regex literals cannot span lines
    }
  }
  return -1;
}

/**
 * Remove comments from YARA rule text
 * Handles both single-line (//) and multi-line C-style comments
 * Preserves string and regex literals to avoid removing comment-like patterns inside them
 * @param {string} text - The text to strip comments from
 * @returns {string} Text with comments removed
 */
function stripComments(text) {
  let result = '';
  let i = 0;
  const len = text.length;
  
  while (i < len) {
    // Check for string literals (preserve them as-is)
    if (text[i] === '"' || text[i] === "'") {
      const quote = text[i];
      result += text[i++];
      
      // Copy the entire string literal, including escaped quotes
      while (i < len) {
        if (text[i] === '\\' && i + 1 < len) {
          result += text[i++]; // backslash
          result += text[i++]; // escaped character
        } else if (text[i] === quote) {
          result += text[i++]; // closing quote
          break;
        } else {
          result += text[i++];
        }
      }
    }
    // Check for a regex literal (preserve it as-is). Without this, an escaped `\/` right before
    // the closing `/` reads as the start of a `//` comment and truncates the definition. `//` and
    // `/*` are always comments, never empty regexes.
    else if (text[i] === '/' && text[i + 1] !== '/' && text[i + 1] !== '*' && isRegexStart(text, i)) {
      const end = findRegexEnd(text, i);
      if (end < 0) {
        // Unterminated: leave the slash as ordinary text so the rest is still comment-stripped.
        result += text[i++];
      } else {
        result += text.slice(i, end + 1);
        i = end + 1;
      }
    }
    // Check for single-line comment
    else if (text[i] === '/' && i + 1 < len && text[i + 1] === '/') {
      // Skip until end of line
      i += 2;
      while (i < len && text[i] !== '\n') {
        i++;
      }
      // Keep the newline for line integrity
      if (i < len && text[i] === '\n') {
        result += text[i++];
      }
    }
    // Check for multi-line comment
    else if (text[i] === '/' && i + 1 < len && text[i + 1] === '*') {
      // Skip until closing */
      i += 2;
      while (i < len - 1) {
        if (text[i] === '*' && text[i + 1] === '/') {
          i += 2;
          break;
        }
        // Preserve newlines to maintain line numbers for error reporting
        if (text[i] === '\n') {
          result += '\n';
        }
        i++;
      }
    }
    // Regular character
    else {
      result += text[i++];
    }
  }
  
  return result;
}

/**
 * Count braces in a line while ignoring those inside string literals
 * @param {string} line - The line to count braces in
 * @returns {Object} Object with openCount and closeCount
 */
function countBracesOutsideStrings(line) {
  let openCount = 0;
  let closeCount = 0;
  let inString = false;
  let stringChar = null;
  let i = 0;
  
  while (i < line.length) {
    const char = line[i];
    
    // Handle escape sequences in strings
    if (inString && char === '\\' && i + 1 < line.length) {
      i += 2; // Skip the backslash and the next character
      continue;
    }
    
    // Check for string start/end
    if ((char === '"' || char === "'") && !inString) {
      inString = true;
      stringChar = char;
    } else if (char === stringChar && inString) {
      inString = false;
      stringChar = null;
    }
    // Count braces only when not inside a string
    else if (!inString) {
      if (char === '{') {
        openCount++;
      } else if (char === '}') {
        closeCount++;
      }
    }
    
    i++;
  }
  
  return { openCount, closeCount };
}

export function parseYaraRuleGroup(multiRuleText, existingRules = [], options = {}) {
  // Parse and validate import statements before processing rules
  // This will throw an error if an unsupported module is imported
  parseImports(multiRuleText);
  
  // Strip import statements from the text after validation
  // This prevents them from interfering with rule parsing
  multiRuleText = multiRuleText.replace(/^\s*import\s+"[^"]+"\s*$/gm, '');
  
  const rules = existingRules ?? [];
  let currentRuleText = '';
  let braceDepth = 0;
  let inRule = false;
  let skipFilterDepth = 0;

  const lines = multiRuleText.split('\n');
  for (let line of lines) {
    // Filter rules are owned by parseInterceptFilterRuleGroup. Skip their blocks entirely instead
    // of relying on the rule-start pattern failing to match, so rule-like text inside a filter
    // body cannot open a bogus rule.
    if (skipFilterDepth > 0) {
      const braceCounts = countBracesOutsideStrings(line);
      skipFilterDepth += braceCounts.openCount - braceCounts.closeCount;
      continue;
    }

    if (!inRule && FILTER_RULE_START_RE.test(line)) {
      const braceCounts = countBracesOutsideStrings(line);
      const depth = braceCounts.openCount - braceCounts.closeCount;
      skipFilterDepth = depth > 0 ? depth : 0;
      continue;
    }

    // Check for the start of a rule (with or without private modifier)
    if (!inRule && RULE_START_RE.test(line)) {
      inRule = true;
      currentRuleText = line + '\n';
      // Count braces while ignoring those inside strings
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth = braceCounts.openCount - braceCounts.closeCount;
      const atleastOneBrace = (braceCounts.openCount > 0);

      // Handle single-line rules where braces balance immediately
      if (braceDepth === 0 && atleastOneBrace) {
        rules.push(parseYaraRule(currentRuleText, options));
        inRule = false;
        currentRuleText = '';
      }
    } else if (inRule) {
      currentRuleText += line + '\n';
      // Update brace depth while ignoring braces inside strings
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth += braceCounts.openCount - braceCounts.closeCount;

      // Check for end of rule
      if (braceDepth === 0) {
        // Complete rule found
        rules.push(parseYaraRule(currentRuleText, options));
        inRule = false;
        currentRuleText = '';
        // console.log("Pushed rule: ", rules[rules.length - 1].name);
      }
    } else {
      // Not in a rule, ignore the line
      // console.log('Ignoring line outside of rule:', line);
    }
    // Lines outside of rules are ignored
  }

  // Ensure each rule has a unique ID
  rules.forEach((rule, index) => {
    rule.id = index + 1;
  });

  return rules;
}

/**
 * Parse Intercept filter rules from a rule group.
 *
 * Filter rules are kept in their own registry: `parseYaraRuleGroup` skips their blocks, so the two
 * sets never mix. Each returned rule carries a cached condition AST and the module roots its
 * condition references, both reused for every candidate evaluation.
 *
 * @param {string} multiRuleText - Rule text that may contain `filter rule` declarations
 * @param {Array} existingFilterRules - Previously parsed filter rules (appended to / replaced)
 * @param {Object} options - `{ limits, availableModules }`
 * @returns {{ rules: Array, diagnostics: Array }}
 */
export function parseInterceptFilterRuleGroup(multiRuleText, existingFilterRules = [], options = {}) {
  parseImports(multiRuleText);

  multiRuleText = multiRuleText.replace(/^\s*import\s+"[^"]+"\s*$/gm, '');

  const rules = [...(existingFilterRules ?? [])];
  const diagnostics = [];
  let currentRuleText = '';
  let braceDepth = 0;
  let inFilterRule = false;
  let skipRuleDepth = 0;

  const addFilterRule = (ruleText) => {
    const { rule, diagnostics: ruleDiagnostics } = parseFilterRule(ruleText, options);
    diagnostics.push(...ruleDiagnostics);

    const existingIndex = rules.findIndex((existing) => existing.name === rule.name);
    if (existingIndex >= 0) {
      diagnostics.push({
        code: 'duplicate-filter-rule',
        severity: 'warning',
        message: `Filter rule "${rule.name}" redefined; the later definition replaces the earlier one`,
        filter: rule.name,
      });
      rules[existingIndex] = rule;
    } else {
      rules.push(rule);
    }
  };

  for (const line of multiRuleText.split('\n')) {
    // Skip normal rule bodies so rule-like text inside them cannot be mistaken for a filter rule.
    if (skipRuleDepth > 0) {
      const braceCounts = countBracesOutsideStrings(line);
      skipRuleDepth += braceCounts.openCount - braceCounts.closeCount;
      continue;
    }

    if (!inFilterRule && FILTER_RULE_START_RE.test(line)) {
      inFilterRule = true;
      currentRuleText = line + '\n';
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth = braceCounts.openCount - braceCounts.closeCount;
      if (braceDepth === 0 && braceCounts.openCount > 0) {
        addFilterRule(currentRuleText);
        inFilterRule = false;
        currentRuleText = '';
      }
      continue;
    }

    if (!inFilterRule && RULE_START_RE.test(line)) {
      const braceCounts = countBracesOutsideStrings(line);
      const depth = braceCounts.openCount - braceCounts.closeCount;
      skipRuleDepth = depth > 0 ? depth : 0;
      continue;
    }

    if (inFilterRule) {
      currentRuleText += line + '\n';
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth += braceCounts.openCount - braceCounts.closeCount;
      if (braceDepth === 0) {
        addFilterRule(currentRuleText);
        inFilterRule = false;
        currentRuleText = '';
      }
    }
  }

  rules.forEach((rule) => {
    rule.id = `filter:${rule.name}`;
  });

  return { rules, diagnostics };
}

/**
 * Parse a single `filter rule` declaration.
 * @param {string} ruleText - Complete filter rule text
 * @param {Object} options - `{ limits, availableModules }`
 * @returns {{ rule: Object, diagnostics: Array }}
 */
function parseFilterRule(ruleText, options = {}) {
  const text = stripComments(ruleText).trim();
  const diagnostics = [];

  const ruleKeywordIndex = text.search(/\brule\b/i);
  const prefix = ruleKeywordIndex >= 0 ? text.slice(0, ruleKeywordIndex) : '';
  if (/\bglobal\b/i.test(prefix)) {
    throw new Error('Invalid Intercept filter rule: global filter rules are not supported');
  }

  const ruleMatch = text.match(/^(?:.*)?rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{/);
  if (!ruleMatch) {
    throw new Error('Invalid Intercept filter rule: missing rule declaration');
  }

  const name = ruleMatch[1];
  const tags = ruleMatch[2] ? ruleMatch[2].trim().split(/\s+/) : [];

  const bodyMatch = text.match(/\{([\s\S]*)\}/);
  if (!bodyMatch) {
    throw new Error('Invalid Intercept filter rule: missing rule body');
  }

  const ruleBody = bodyMatch[1];
  const metadata = parseMetadata(ruleBody);
  const strings = parseStrings(ruleBody, options);

  for (const [varName, strDef] of Object.entries(strings)) {
    if (strDef.reject?.length || strDef.rejectCapture?.length) {
      throw new Error(
        `Invalid Intercept filter rule "${name}": reject(...) and rejectRECapture(...) are not allowed on string ${varName}`
      );
    }
  }

  const condition = parseCondition(ruleBody);

  let conditionAST = null;
  try {
    conditionAST = parseConditionToAST(condition, strings);
  } catch (error) {
    diagnostics.push({
      code: 'invalid-filter-condition',
      severity: 'warning',
      message: `Filter rule "${name}" condition could not be parsed: ${error.message}`,
      filter: name,
    });
  }

  const usedModules = collectUsedModules(conditionAST, {
    availableModules: options.availableModules ?? [],
    filterName: name,
    diagnostics,
  });

  return {
    rule: {
      name,
      tags,
      metadata,
      strings,
      condition,
      conditionAST,
      usedModules,
      filter: true,
      private: true,
    },
    diagnostics,
  };
}

/**
 * Collect the module roots a filter condition references.
 *
 * Qualified roots (`pe.foo`, `hash.md5(...)`) are the only candidates; loop variables are excluded
 * so `for any s in pe.sections : (s.name == ...)` doesn't treat `s` as a module. Unknown roots are
 * kept (a custom module may be registered later) but produce a diagnostic.
 */
function collectUsedModules(ast, { availableModules = [], filterName, diagnostics }) {
  if (!ast) return [];

  const loopVariables = new Set();
  const qualifiedRoots = new Set();

  walkAst(ast, (node) => {
    if (node.type === 'ruleIdentifier') {
      throw new Error(
        `Invalid Intercept filter rule "${filterName}": conditions cannot reference rules ("${node.name}")`
      );
    }

    if (node.type === 'for') {
      const variable = node.variable;
      if (typeof variable === 'string') loopVariables.add(variable);
      else if (variable?.name) loopVariables.add(variable.name);
    }

    if (node.type === 'moduleFunction' && typeof node.module === 'string') {
      qualifiedRoots.add(node.module);
    }

    if (
      node.type === 'memberAccess' &&
      node.object?.type === 'identifier' &&
      typeof node.object.name === 'string'
    ) {
      qualifiedRoots.add(node.object.name.split('.')[0]);
    }

    if (node.type === 'identifier' && typeof node.name === 'string' && node.name.includes('.')) {
      qualifiedRoots.add(node.name.split('.')[0]);
    }
  });

  const knownModules = new Set([...BUILTIN_MODULE_NAMES, ...availableModules]);
  const usedModules = [];

  for (const root of qualifiedRoots) {
    if (loopVariables.has(root)) continue;

    if (root === 'pe' || root === 'elf') {
      throw new Error(
        `Invalid Intercept filter rule "${filterName}": the "${root}" module is not available for candidate buffers`
      );
    }

    usedModules.push(root);

    if (!knownModules.has(root)) {
      diagnostics.push({
        code: 'unknown-module',
        severity: 'warning',
        message: `Filter rule "${filterName}" references unknown module "${root}"`,
        filter: filterName,
      });
    }
  }

  return usedModules;
}

function walkAst(node, visit) {
  if (!node || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    for (const item of node) walkAst(item, visit);
    return;
  }

  visit(node);

  for (const value of Object.values(node)) {
    if (value && typeof value === 'object') walkAst(value, visit);
  }
}

/**
 * Parse a YARA rule and return an object representation
 * @param {string} ruleText - The complete YARA rule text
 * @returns {Object} Parsed rule object with metadata, strings, and condition
 */
export function parseYaraRule(ruleText, options = {}) {
  // Strip comments before parsing
  ruleText = stripComments(ruleText).trim();

  // Check for private modifier
  const isPrivate = /^.*\bprivate\b.*rule\s+/i.test(ruleText);

    // Check for global modifier
  const isGlobal = /^.*\bglobal\b.*rule\s+/i.test(ruleText);
  
  // Extract rule name and tags (with or without private modifier)
  const ruleMatch = ruleText.match(/^(?:.*)?rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{/);
  if (!ruleMatch) {
    throw new Error('Invalid YARA rule: missing rule declaration');
  }
  
  const ruleName = ruleMatch[1];
  const tags = ruleMatch[2] ? ruleMatch[2].trim().split(/\s+/) : [];
  
  // Extract the rule body (everything between the outer braces)
  const bodyMatch = ruleText.match(/\{([\s\S]*)\}/);
  if (!bodyMatch) {
    throw new Error('Invalid YARA rule: missing rule body');
  }
  
  const ruleBody = bodyMatch[1];
  
  // Parse metadata section
  const metadata = parseMetadata(ruleBody);
  
  // Parse strings section
  const strings = parseStrings(ruleBody, options);
  
  // Parse condition section
  const condition = parseCondition(ruleBody);
  
  return {
    name: ruleName,
    tags,
    metadata,
    strings,
    condition,
    private: isPrivate,
    global: isGlobal
  };
}

/**
 * Parse the metadata section of a YARA rule
 * @param {string} ruleBody - The rule body text
 * @returns {Object} Metadata key-value pairs
 */
function parseMetadata(ruleBody) {
  const metaMatch = ruleBody.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/);
  if (!metaMatch) return {};
  
  const metaText = metaMatch[1];
  const metadata = {};
  
  // Match key = value pairs (handles strings and numbers)
  const metaLines = metaText.match(/(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(-)?\d+(\.\d+)?|true|false)/g);
  
  if (metaLines) {
    for (const line of metaLines) {
      const [, key, value] = line.match(/(\w+)\s*=\s*(.+)/);
      // Remove quotes from string values
      if (value.startsWith('"') || value.startsWith("'")) {
        metadata[key] = value.slice(1, -1);
      } else if (value === 'true' || value === 'false') {
        metadata[key] = value === 'true';
      } else if (!isNaN(value)) {
        metadata[key] = Number(value);
      } else {
        metadata[key] = value;
      }
    }
  }
  
  return metadata;
}

/**
 * Parse the strings section of a YARA rule
 * Supports both named strings ($var = "pattern") and anonymous strings ($ = "pattern")
 * Anonymous strings are automatically assigned internal names like .anon_0, .anon_1, etc.
 * @param {string} ruleBody - The rule body text
 * @returns {Object} String definitions with their compiled matchers
 */
function parseStrings(ruleBody, options = {}) {
  const stringsMatch = ruleBody.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
  if (!stringsMatch) return {};
  
  const stringsText = stringsMatch[1];
  const strings = {};
  
  // Match string definitions: $var = "text" modifiers or $ = "text" or $var = /regex/ or $var = { hex }
  const stringLines = stringsText.match(/\$\w*\s*=\s*(.*)?/g);

  if (stringLines) {
    let anonCounter = 0; // Counter for anonymous strings
    
    for (const line of stringLines) {
      const match = line.match(/\$(\w*)\s*=\s*(.+)/);
      if (!match) continue;
      
      let [, varName, definition] = match;
      
      // Handle anonymous strings ($ = "pattern")
      if (!varName || varName === '') {
        varName = `.anon_${anonCounter++}`;
      } else {
        // Add proper $ prefix to string identifier if not present -- NEED TO VERIFY THIS LOGIC
        if (!varName.startsWith('$')) {
          varName = '$' + varName;
        }
      }
      
      try {
        // Compile the string definition into a matcher function
        const compiledRule = compileYaraLike(definition.trim(), options.limits, {
          includeCaptures: options.includeCaptures,
        });
        
        strings[varName] = {
          definition: definition.trim(),
          ...compiledRule
        };
      } catch (error) {
        console.warn(`Warning: Failed to compile string $${varName}: ${error.message}`);
        console.warn(`Definition: ${definition.trim()}`);
        console.warn(line);
        console.warn(stringsMatch);
        console.warn(ruleBody);
        strings[varName] = {
          definition: definition.trim(),
          type: null,
          matcher: null,
          error: error.message,
        };
      }
    }
  }
  
  return strings;
}

/**
 * Parse the condition section of a YARA rule
 * @param {string} ruleBody - The rule body text
 * @returns {string} The condition expression as a string (to be evaluated later)
 */
function parseCondition(ruleBody) {
  const conditionMatch = ruleBody.match(/condition:\s*([\s\S]*?)$/);
  if (!conditionMatch) {
    throw new Error('Invalid YARA rule: missing condition');
  }
  
  // Return the condition as a trimmed string, removing any trailing braces
  return conditionMatch[1].trim().replace(/\}\s*$/, '').trim();
}

/**
 * Compile a complete YARA rule into an executable form
 * @param {string} ruleText - The complete YARA rule text
 * @returns {Object} Compiled rule object ready for evaluation
 */
export function compileYaraRule(ruleText) {
  const parsed = parseYaraRule(ruleText);
  
  return {
    name: parsed.name,
    tags: parsed.tags,
    metadata: parsed.metadata,
    strings: parsed.strings,
    condition: parsed.condition,
    
    /**
     * Match this rule against binary data
     * @param {Uint8Array} data - The data to scan
     * @returns {Object} Match results with string matches and overall result
     */
    match(data) {
      // Execute all string matchers
      const stringMatches = {};
      
      for (const [varName, stringDef] of Object.entries(parsed.strings)) {
        if (stringDef.matcher) {
          try {
            const matches = stringDef.matcher(data);
            stringMatches[varName] = matches;
          } catch (error) {
            console.warn(`Warning: Error matching $${varName}: ${error.message}`);
            stringMatches[varName] = [];
          }
        } else {
          stringMatches[varName] = [];
        }
      }
      
      // TODO: Evaluate the condition expression against stringMatches
      // For now, return the matches without evaluating the condition
      return {
        ruleName: parsed.name,
        matched: null, // Will be true/false once condition evaluation is implemented
        stringMatches,
        condition: parsed.condition,
      };
    },
  };
}

