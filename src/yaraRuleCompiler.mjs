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
 * Remove comments from YARA rule text
 * Handles both single-line (//) and multi-line C-style comments
 * Preserves strings to avoid removing comment-like patterns inside them
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

export function parseYaraRuleGroup(multiRuleText, existingRules = []) {
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

  const lines = multiRuleText.split('\n');
  for (let line of lines) {
    // Check for the start of a rule (with or without private modifier)
    if (!inRule && line.match(/^\s*(?:\s*(?:private|global)\s+)*rule\b/i)) {
      inRule = true;
      currentRuleText = line + '\n';
      // Count braces while ignoring those inside strings
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth = braceCounts.openCount - braceCounts.closeCount;
      const atleastOneBrace = (braceCounts.openCount > 0);

      // Handle single-line rules where braces balance immediately
      if (braceDepth === 0 && atleastOneBrace) {
        rules.push(parseYaraRule(currentRuleText));
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
        rules.push(parseYaraRule(currentRuleText));
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
 * Parse a YARA rule and return an object representation
 * @param {string} ruleText - The complete YARA rule text
 * @returns {Object} Parsed rule object with metadata, strings, and condition
 */
export function parseYaraRule(ruleText) {
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
  const strings = parseStrings(ruleBody);
  
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
function parseStrings(ruleBody) {
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
      }
      
      try {
        // Compile the string definition into a matcher function
        const compiledRule = compileYaraLike(definition.trim());
        
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

