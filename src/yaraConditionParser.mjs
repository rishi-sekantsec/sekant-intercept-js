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
 * YARA Condition Parser
 * 
 * Parses YARA condition strings into AST format for evaluation.
 * This is a simplified parser that handles common YARA condition patterns.
 * 
 * Supported patterns:
 * - String identifiers: $a, $b, $c
 * - Rule identifiers: RuleA, RuleB (dependent rules)
 * - Quantifiers: any of them, all of them, N of them, X% of them
 * - For loops: for all/any of them : (condition), for i in (range) : (condition)
 * - Logical operators: and, or, not
 * - Comparison: ==, !=, <, >, <=, >=
 * - Arithmetic operators: +, -, *, /, %
 * - Bitwise operators: &, |, ^, ~, <<, >>
 * - Proximity operators: $a at offset, $a in (range), $a within N of $b
 * - Identifiers: filesize, entrypoint
 * - Boolean literals: true, false
 * - Numbers and basic arithmetic
 */

// Constants
const PLACEHOLDER_PREFIX = '__LITERAL_';
const REGEX_PLACEHOLDER_PREFIX = '__REGEX_';
const PLACEHOLDER_SUFFIX = '__';

// Data access type definitions
const DATA_ACCESS_TYPES = [
  { name: 'uint8', bits: 8, signed: false, endian: 'little' },
  { name: 'uint16', bits: 16, signed: false, endian: 'little' },
  { name: 'uint32', bits: 32, signed: false, endian: 'little' },
  { name: 'int8', bits: 8, signed: true, endian: 'little' },
  { name: 'int16', bits: 16, signed: true, endian: 'little' },
  { name: 'int32', bits: 32, signed: true, endian: 'little' },
  { name: 'uint16be', bits: 16, signed: false, endian: 'big' },
  { name: 'uint32be', bits: 32, signed: false, endian: 'big' },
  { name: 'int16be', bits: 16, signed: true, endian: 'big' },
  { name: 'int32be', bits: 32, signed: true, endian: 'big' }
];

/**
 * Utility: Skip whitespace in a string starting from a given index
 * @param {string} str - String to process
 * @param {number} startIndex - Starting position
 * @returns {number} Index after whitespace
 */
function skipWhitespace(str, startIndex) {
  let index = startIndex;
  while (index < str.length && /\s/.test(str[index])) index++;
  return index;
}


/**
 * Utility: Check if parentheses wrap the entire expression
 * @param {string} expr - Expression to check
 * @returns {boolean} True if outer parens wrap everything
 */
function wrapsEntireExpression(expr) {
  if (!expr.startsWith('(') || !expr.endsWith(')')) return false;
  let depth = 0;
  for (let i = 0; i < expr.length; i++) {
    if (expr[i] === '(') depth++;
    if (expr[i] === ')') depth--;
    if (depth === 0 && i < expr.length - 1) return false;
  }
  return true;
}

/**
 * Find the closing quote of a string literal, honouring backslash escapes.
 *
 * @param {string} text
 * @param {number} start - index of the opening quote
 * @param {string} quoteChar - `"` or `'`
 * @returns {number} index of the closing quote, or -1 when unterminated
 */
function findClosingQuote(text, start, quoteChar) {
  let escaped = false;
  for (let i = start + 1; i < text.length; i++) {
    const char = text[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === quoteChar) return i;
  }
  return -1;
}

/**
 * Scan a regex literal starting at `start` (a `/`).
 * Returns null when the text is not a regex literal — an unterminated slash, an empty `//`, or a
 * newline before the closing slash (which in a rule means the author wrote prose, not a pattern).
 *
 * @param {string} text
 * @param {number} start - index of the opening `/`
 * @returns {{pattern: string, flags: string, end: number}|null}
 */
function scanRegexLiteral(text, start) {
  let body = '';
  let inClass = false;
  let escaped = false;

  for (let i = start + 1; i < text.length; i++) {
    const char = text[i];
    if (escaped) {
      body += char;
      escaped = false;
      continue;
    }
    if (char === '\\') {
      body += char;
      escaped = true;
      continue;
    }
    if (char === '\n') return null;
    if (char === '[') inClass = true;
    else if (char === ']') inClass = false;
    else if (char === '/' && !inClass) {
      if (!body) return null; // `//` is not a pattern
      let end = i + 1;
      let flags = '';
      while (end < text.length && /[a-z]/.test(text[end])) {
        flags += text[end];
        end += 1;
      }
      return { pattern: body, flags, end };
    }
    body += char;
  }

  return null;
}

/**
 * Replace string and regex literals with identifiers before the structure is parsed.
 * Phase 1 of parsing: without this, `^`, `/` and ` and ` inside a pattern would be read as
 * operators (`/` is divide and `^` is bitwise-XOR in this grammar).
 *
 * String literals go first in the walk, so a `/` inside `"http://host/path"` never starts a
 * regex, and a quote inside `/[a-z"]+/` never starts a string.
 *
 * @param {string} condition - Raw condition string
 * @returns {Object} { processed, literals } — literals carry { id, type: 'string'|'regex', … }
 */
function extractLiterals(condition) {
  const literals = [];
  let processed = '';
  let stringCount = 0;
  let regexCount = 0;
  let i = 0;

  while (i < condition.length) {
    const char = condition[i];

    if (char === '"' || char === "'") {
      const end = findClosingQuote(condition, i, char);
      if (end !== -1) {
        const id = `${PLACEHOLDER_PREFIX}${stringCount}${PLACEHOLDER_SUFFIX}`;
        literals.push({ id, type: 'string', value: condition.slice(i + 1, end) });
        stringCount += 1;
        processed += id;
        i = end + 1;
        continue;
      }
      processed += char; // Unterminated quote: leave the text alone and let the parser cope.
      i += 1;
      continue;
    }

    if (char === '/') {
      const regex = scanRegexLiteral(condition, i);
      if (regex) {
        const id = `${REGEX_PLACEHOLDER_PREFIX}${regexCount}${PLACEHOLDER_SUFFIX}`;
        literals.push({ id, type: 'regex', pattern: regex.pattern, flags: regex.flags });
        regexCount += 1;
        processed += id;
        i = regex.end;
        continue;
      }
      processed += char;
      i += 1;
      continue;
    }

    processed += char;
    i += 1;
  }

  return { processed, literals };
}

/** True for either placeholder family (`__LITERAL_n__` / `__REGEX_n__`). */
function isPlaceholderId(name) {
  return typeof name === 'string' && (name.startsWith(PLACEHOLDER_PREFIX) || name.startsWith(REGEX_PLACEHOLDER_PREFIX));
}

/**
 * Restore string and regex literals in AST by replacing placeholder identifiers
 * Phase 3 of parsing: replaces placeholders with actual string literal nodes
 * 
 * @param {Object} ast - AST node to process
 * @param {Array} literals - Array of literal info from extraction phase
 * @returns {Object} AST with literals restored
 */
function restoreStringLiterals(ast, literals) {
  if (!ast || typeof ast !== 'object') {
    return ast;
  }
  
  // Check if this is a placeholder identifier (string or regex literal)
  if (ast.type === 'identifier' && ast.name && isPlaceholderId(ast.name)) {
    const literal = literals.find(lit => lit.id === ast.name);
    if (literal) {
      if (literal.type === 'regex') {
        return { type: 'regex', pattern: literal.pattern, flags: literal.flags ?? '' };
      }
      return { type: 'string', value: literal.value };
    }
  }
  
  // Recursively process all properties
  const result = { ...ast };
  for (const key in result) {
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      if (Array.isArray(result[key])) {
        result[key] = result[key].map(item => {
          // Handle plain string items (like in 'items' arrays)
          if (typeof item === 'string' && isPlaceholderId(item)) {
            const literal = literals.find(lit => lit.id === item);
            if (!literal) return item;
            return literal.type === 'regex' ? { type: 'regex', pattern: literal.pattern, flags: literal.flags ?? '' } : literal.value;
          }
          // Handle object items
          return typeof item === 'object' ? restoreStringLiterals(item, literals) : item;
        });
      } else if (typeof result[key] === 'object') {
        result[key] = restoreStringLiterals(result[key], literals);
      }
    }
  }
  
  return result;
}

/**
 * Parse YARA condition to AST
 * @param {string} condition - Condition string
 * @param {Object} strings - Available string identifiers
 * @returns {Object} AST node
 */
export function parseConditionToAST(condition, strings = {}) {
  condition = condition.trim();
  
  // Phase 1: extract string and regex literals so `^`, `/` and ` and ` inside them are not
  // mistaken for operators
  const { processed, literals } = extractLiterals(condition);
  
  // Phase 2: Parse structure with placeholders
  const ast = parseStructure(processed, strings);
  
  // Phase 3: restore both kinds of literal in the AST
  return restoreStringLiterals(ast, literals);
}

/**
 * Parse quantifier expressions (any/all/none of them, N of them, etc.)
 * Consolidates all quantifier parsing patterns into one function
 * 
 * @param {string} condition - Condition string
 * @returns {Object|null} AST node for quantifier, or null if not a quantifier
 */
function parseQuantifier(condition) {
  // Pattern: <quantifier> of <items>
  // quantifier can be: any, all, none, N (number), X% (percentage), N..M (range)
  // items can be: them, or ($a, $b, $c)
  
  const quantifierPattern = /^(any|all|none|\d+|\d+%|\d+\.\.\d+)\s+of\s+(them|\([^)]+\))$/;
  const match = condition.match(quantifierPattern);
  
  if (!match) return null;
  
  const [, quantPart, itemsPart] = match;
  
  // Parse quantifier part
  let quantifier;
  let type;
  
  if (quantPart === 'any') {
    type = 'any';
  } else if (quantPart === 'all') {
    type = 'all';
  } else if (quantPart === 'none') {
    type = 'none';
  } else if (quantPart.includes('..')) {
    // Range: N..M
    const [min, max] = quantPart.split('..').map(n => parseInt(n));
    type = 'quantified';
    quantifier = { type: 'range', min, max };
  } else if (quantPart.endsWith('%')) {
    // Percentage: X%
    type = 'quantified';
    quantifier = { type: 'percentage', value: parseInt(quantPart) };
  } else {
    // Number: N
    type = 'quantified';
    quantifier = { type: 'number', value: parseInt(quantPart) };
  }
  
  // Parse items part
  let items;
  if (itemsPart === 'them') {
    items = 'them';
  } else {
    // Extract items from parentheses: ($a, $b, $c)
    const itemsStr = itemsPart.slice(1, -1); // Remove outer parens
    items = itemsStr.split(',').map(s => s.trim());
  }
  
  return { type, ...(quantifier && { quantifier }), items };
}

/**
 * Parse condition structure (Phase 2)
 * This is the main parsing logic, now working with string literals replaced by placeholders
 * @param {string} condition - Condition string with placeholders
 * @param {Object} strings - Available string identifiers
 * @returns {Object} AST node
 */
function parseStructure(condition, strings = {}) {
  condition = condition.trim();

  // Remove outer parentheses if they wrap the entire expression
  while (wrapsEntireExpression(condition)) {
    condition = condition.slice(1, -1).trim();
  }

  // Try parsing as quantifier first
  const quantifierNode = parseQuantifier(condition);
  if (quantifierNode) {
    return quantifierNode;
  }

  /**
   * Helper: Parse binary operator (or, and)
   * @param {string} operator - Operator name ('or', 'and')
   * @param {number} operatorLength - Length of operator string
   * @returns {Object|null} AST node or null
   */
  const parseBinaryOperator = (operator, operatorLength) => {
    const opIndex = findOperatorOutsideParens(condition, ` ${operator} `);
    if (opIndex === -1) return null;
    
    // Find where operator ends (skip whitespace before, operator, and whitespace after)
    let endIndex = skipWhitespace(condition, opIndex);
    endIndex += operatorLength; // skip operator
    endIndex = skipWhitespace(condition, endIndex);
    
    return {
      type: operator,
      left: parseStructure(condition.substring(0, opIndex), strings),
      right: parseStructure(condition.substring(endIndex), strings)
    };
  };

  // Handle "or" operator (lowest precedence - check first)
  const orNode = parseBinaryOperator('or', 2);
  if (orNode) return orNode;

  // Handle "and" operator (higher precedence than OR - check after OR)
  const andNode = parseBinaryOperator('and', 3);
  if (andNode) return andNode;


  // Handle "for" loops (higher precedence than AND/OR - check after them)
  // Patterns:
  // - for all of them : ( condition )
  // - for any of them : ( condition )
  // - for none of them : ( condition )
  // - for 2 of them : ( condition )
  // - for 50% of them : ( condition )
  // - for all of ($a*, $b*) : ( condition )
  // - for all i in (1..10) : ( condition )
  // - for all i in (0..#a) : ( condition )
  
  // Use a smarter approach: find "for", then find the matching parentheses for the body
  if (condition.trim().startsWith('for ')) {
    // Find the colon that separates iterator from body
    const colonIndex = condition.indexOf(':');
    if (colonIndex !== -1) {
      // Find the opening paren after the colon
      let openParenIndex = colonIndex + 1;
      while (openParenIndex < condition.length && condition[openParenIndex] !== '(') {
        openParenIndex++;
      }
      
      if (openParenIndex < condition.length) {
        // Find the matching closing paren
        let depth = 1;
        let closeParenIndex = openParenIndex + 1;
        while (closeParenIndex < condition.length && depth > 0) {
          if (condition[closeParenIndex] === '(') depth++;
          if (condition[closeParenIndex] === ')') depth--;
          closeParenIndex++;
        }
        
        if (depth === 0) {
          // Successfully found matching parens
          const forHeader = condition.substring(0, colonIndex).trim();
          const bodyCondition = condition.substring(openParenIndex + 1, closeParenIndex - 1).trim();
          
          /**
           * Helper: Parse for-loop quantifier
           * @param {string} quantifierStr - Quantifier string (all, any, none, N, N%)
           * @returns {string|Object} Parsed quantifier
           */
          const parseForQuantifier = (quantifierStr) => {
            if (['all', 'any', 'none'].includes(quantifierStr)) return quantifierStr;
            if (quantifierStr.endsWith('%')) {
              return { type: 'percentage', value: parseInt(quantifierStr) };
            }
            return { type: 'number', value: parseInt(quantifierStr) };
          };
          
          /**
           * Helper: Parse for-loop iterator
           * @param {string} iteratorPart - Iterator part of for-loop
           * @returns {Object} { variable, set }
           */
          const parseForIterator = (iteratorPart) => {
            // Check for "i in (range)" pattern
            const iteratorInRangeMatch = iteratorPart.match(/^(\w+)\s+in\s+\((.+?)\.\.(.+?)\)$/);
            if (iteratorInRangeMatch) {
              return {
                variable: iteratorInRangeMatch[1],
                set: {
                  type: 'range',
                  start: parseExpression(iteratorInRangeMatch[2].trim()),
                  end: parseExpression(iteratorInRangeMatch[3].trim())
                }
              };
            }
            
            // Check for "of them" or "of (set)" pattern
            const ofMatch = iteratorPart.match(/^of\s+(.+)$/);
            if (ofMatch) {
              const setStr = ofMatch[1].trim();
              let items;
              
              if (setStr === 'them') {
                items = 'them';
              } else if (setStr.startsWith('(') && setStr.endsWith(')')) {
                items = setStr.slice(1, -1).split(',').map(s => s.trim());
              } else {
                items = setStr; // wildcard pattern like $api*
              }
              
              return {
                variable: '$', // implicit variable for strings
                set: { type: 'stringSet', items }
              };
            }
            
            return { variable: null, set: null };
          };
          
          // Parse the "for quantifier iterator" part
          const forMatch = forHeader.match(/^for\s+(all|any|none|\d+|(\d+)%)\s+(.+)$/);
          if (forMatch) {
            const quantifier = parseForQuantifier(forMatch[1]);
            const { variable, set } = parseForIterator(forMatch[3]);
            
            return {
              type: 'for',
              quantifier,
              variable,
              set,
              condition: parseStructure(bodyCondition, strings)
            };
          }
        }
      }
    }
  }

  // Handle "not" operator
  if (condition.startsWith('not ')) {
    return {
      type: 'not',
      operand: parseStructure(condition.substring(4), strings)
    };
  }

  // Handle "defined" operator
  if (condition.startsWith('defined ')) {
    return {
      type: 'defined',
      operand: parseStructure(condition.substring(8), strings)
    };
  }

  // Handle "$a at offset", "$ at offset" (for loops), or "string" at offset (string literals)
  const atMatch = condition.match(/^(\$\w*|\w+)\s+at\s+(.+)$/);
  if (atMatch) {
    const firstPart = atMatch[1];
    // Check if it's a string identifier ($a) or a placeholder (__LITERAL_N__) or other identifier
    if (firstPart.startsWith('$')) {
      return {
        type: 'at',
        identifier: firstPart,
        offset: parseExpression(atMatch[2])
      };
    } else if (firstPart.startsWith(PLACEHOLDER_PREFIX)) {
      // String literal placeholder - parse it as an expression to get the string node
      return {
        type: 'at',
        identifier: parseExpression(firstPart),
        offset: parseExpression(atMatch[2])
      };
    }
  }

  // Handle "$a in (start..end)" or "$ in (start..end)" (for loops)
  const inRangeMatch = condition.match(/^(\$\w*)\s+in\s+\((.+)\.\.(.+)\)$/);
  if (inRangeMatch) {
    return {
      type: 'inRange',
      identifier: inRangeMatch[1],
      range: {
        type: 'range',
        start: parseExpression(inRangeMatch[2]),
        end: parseExpression(inRangeMatch[3])
      }
    };
  }

  // Handle "$a within N of $b" or "$a within N bytes of $b"
  // Proximity operator: checks if any occurrence of $a is within N bytes of any occurrence of $b
  const withinMatch = condition.match(/^(\$\w*)\s+within\s+(.+?)(?:\s+bytes)?\s+of\s+(\$\w*)$/);
  if (withinMatch) {
    return {
      type: 'within',
      identifier: withinMatch[1],
      distance: parseExpression(withinMatch[2]),
      reference: withinMatch[3]
    };
  }

  // Handle string operators (must check before comparison operators)
  // These are word-based operators that require flexible whitespace matching
  const stringOps = [
    { pattern: 'matches', type: 'matches' },
    { pattern: 'iequals', type: 'iequals' },
    { pattern: 'icontains', type: 'icontains' },
    { pattern: 'contains', type: 'contains' },
    { pattern: 'istartswith', type: 'istartswith' },
    { pattern: 'startswith', type: 'startswith' },
    { pattern: 'iendswith', type: 'iendswith' },
    { pattern: 'endswith', type: 'endswith' }
  ];

  for (const op of stringOps) {
    const opIndex = findOperatorOutsideParens(condition, ` ${op.pattern} `);
    if (opIndex !== -1) {
      // Find where the operator ends (skip whitespace before, operator, and whitespace after)
      let endIndex = opIndex;
      while (endIndex < condition.length && /\s/.test(condition[endIndex])) endIndex++;
      endIndex += op.pattern.length;
      while (endIndex < condition.length && /\s/.test(condition[endIndex])) endIndex++;
      
      return {
        type: op.type,
        left: parseExpression(condition.substring(0, opIndex)),
        right: parseExpression(condition.substring(endIndex))
      };
    }
  }

  // Handle comparison operators
  const comparisonOps = [
    { pattern: '==', type: 'equal' },
    { pattern: '!=', type: 'notEqual' },
    { pattern: '<=', type: 'lessThanOrEqual' },
    { pattern: '>=', type: 'greaterThanOrEqual' },
    { pattern: '<', type: 'lessThan' },
    { pattern: '>', type: 'greaterThan' }
  ];

  for (const op of comparisonOps) {
    const opIndex = findOperatorOutsideParens(condition, op.pattern);
    if (opIndex !== -1) {
      return {
        type: op.type,
        left: parseExpression(condition.substring(0, opIndex)),
        right: parseExpression(condition.substring(opIndex + op.pattern.length))
      };
    }
  }

  // Handle single expression
  return parseExpression(condition);
}

/**
 * Parse an expression (identifier, number, string identifier, etc.)
 * @param {string} expr - Expression string
 * @returns {Object} AST node
 */
function parseExpression(expr) {
  expr = expr.trim();

  // Boolean literals - must check before identifiers
  if (expr === 'true') {
    return { type: 'boolean', value: true };
  }
  if (expr === 'false') {
    return { type: 'boolean', value: false };
  }

  // Size units (KB, MB, GB) - must check before plain numbers
  const sizeUnitMatch = expr.match(/^(\d+)(KB|MB|GB)$/i);
  if (sizeUnitMatch) {
    const value = parseInt(sizeUnitMatch[1]);
    const unit = sizeUnitMatch[2].toUpperCase();
    const multipliers = { KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };
    return { type: 'number', value: value * multipliers[unit] };
  }

  // Note: string and regex literals are masked in Phase 1 (extractLiterals)
  // and restored as `string` / `regex` nodes in Phase 3 (restoreStringLiterals).
  // By this point, they are placeholders like __LITERAL_0__

  // Floating point number (must be checked before member access)
  if (/^-?\d+\.\d+$/.test(expr)) {
    return { type: 'number', value: parseFloat(expr) };
  }

  // Number (integer)
  if (/^-?\d+$/.test(expr)) {
    return { type: 'number', value: parseInt(expr) };
  }

  // Hex number
  if (/^0x[0-9a-fA-F]+$/.test(expr)) {
    return { type: 'number', value: parseInt(expr, 16) };
  }

  // String identifier $a or just $ (for loops)
  if (/^\$\w*$/.test(expr)) {
    return { type: 'stringIdentifier', identifier: expr };
  }

  // String count #a or just # (for loops)
  if (/^#\w*$/.test(expr)) {
    return { type: 'stringCount', identifier: expr.replace('#', '$') };
  }

  // String offset @a or just @ (for loops)
  if (/^@\w*$/.test(expr)) {
    return { type: 'stringOffset', identifier: expr.replace('@', '$'), index: 0 };
  }

  /**
   * Helper: Parse indexed string operations (@a[n] or !a[n])
   * @param {string} expr - Expression to parse
   * @param {string} prefix - Prefix character (@ or !)
   * @param {string} type - Type name ('stringOffset' or 'stringLength')
   * @returns {Object|null} AST node or null
   */
  const parseIndexedStringOp = (expr, prefix, type) => {
    const pattern = new RegExp(`^\\${prefix}([\\w$]+)\\[([^\\]]+)\\]$`);
    const match = expr.match(pattern);
    if (!match) return null;
    
    const identifierPart = match[1];
    const indexExpr = match[2].trim();
    const identifier = identifierPart.startsWith('$') ? identifierPart : `$${identifierPart}`;
    
    // Parse index as number or expression
    const index = /^\d+$/.test(indexExpr) ? parseInt(indexExpr) : parseExpression(indexExpr);
    
    return { type, identifier, index };
  };

  // String offset @a[expr] - supports @a[n], @a[i], @a[i+1], etc.
  const offsetIndexed = parseIndexedStringOp(expr, '@', 'stringOffset');
  if (offsetIndexed) return offsetIndexed;

  // String length !a or !$
  if (/^![\w$]+$/.test(expr)) {
    const id = expr.slice(1); // Remove '!'
    return { type: 'stringLength', identifier: id.startsWith('$') ? id : `$${id}`, index: 0 };
  }

  // String length !a[expr] - supports !a[n], !a[i], !a[i+1], etc.
  const lengthIndexed = parseIndexedStringOp(expr, '!', 'stringLength');
  if (lengthIndexed) return lengthIndexed;


  // filesize
  if (expr === 'filesize') {
    return { type: 'identifier', name: 'filesize' };
  }

  // entrypoint
  if (expr === 'entrypoint') {
    return { type: 'identifier', name: 'entrypoint' };
  }

  // Data access functions: uint8, uint16, uint32, int8, int16, int32, uint16be, uint32be, int16be, int32be
  for (const dataAccessType of DATA_ACCESS_TYPES) {
    const pattern = new RegExp(`^${dataAccessType.name}\\((.+)\\)$`);
    const match = expr.match(pattern);
    if (match) {
      return {
        type: 'dataAccess',
        dataType: dataAccessType.name.replace('be', ''), // Remove 'be' suffix for storage
        offset: parseExpression(match[1]),
        endian: dataAccessType.endian
      };
    }
  }


  // Module function calls (e.g., math.entropy(...), string.to_int(...), time.now())
  const moduleFuncMatch = expr.match(/^(\w+)\.(\w+)\((.*)\)$/);
  if (moduleFuncMatch) {
    const [, moduleName, functionName, argsStr] = moduleFuncMatch;
    
    // Parse arguments (simple comma-separated for now)
    let args = [];
    if (argsStr.trim()) {
      // Split by comma, but respect nested parentheses
      let depth = 0;
      let currentArg = '';
      for (let i = 0; i < argsStr.length; i++) {
        const ch = argsStr[i];
        if (ch === '(') depth++;
        if (ch === ')') depth--;
        if (ch === ',' && depth === 0) {
          args.push(parseExpression(currentArg.trim()));
          currentArg = '';
        } else {
          currentArg += ch;
        }
      }
      if (currentArg.trim()) {
        args.push(parseExpression(currentArg.trim()));
      }
    }
    
    return {
      type: 'moduleFunction',
      module: moduleName,
      function: functionName,
      args
    };
  }

  // Module property with array indexing and optional chained access
  // Examples: pe.sections[0], pe.sections[0].name, elf.sections[i].virtual_address
  const moduleArrayChainMatch = expr.match(/^(\w+)\.(\w+)\[([^\]]+)\]\.?(\w*)$/);
  if (moduleArrayChainMatch) {
    const [, moduleName, propertyName, indexExpr, rest] = moduleArrayChainMatch;
    
    // Base array access node
    let node = {
      type: 'arrayAccess',
      object: {
        type: 'memberAccess',
        object: { type: 'identifier', name: moduleName },
        property: propertyName
      },
      index: parseExpression(indexExpr.trim())
    };
    
    // If there's chained access (e.g., .name after [0]), parse it
    if (rest) {
      const chainedProperties = rest.split('.');
      for (const prop of chainedProperties) {
        if (prop) {
          node = {
            type: 'memberAccess',
            object: node,
            property: prop
          };
        }
      }
    }
    
    return node;
  }

  // Module property access (e.g., pe.entry_point, elf.is_64bit)
  const modulePropMatch = expr.match(/^(\w+)\.(\w+)$/);
  if (modulePropMatch) {
    const [, moduleName, propertyName] = modulePropMatch;
    return {
      type: 'memberAccess',
      object: { type: 'identifier', name: moduleName },
      property: propertyName
    };
  }

  // Bitwise NOT operator (unary, highest precedence)
  // Only consume a primary expression (number, identifier, or parenthesized)
  if (expr.startsWith('~')) {
    const rest = expr.substring(1).trim();
    let operandEnd; // assigned in each branch below
    
    // If starts with paren, find matching close paren
    if (rest.startsWith('(')) {
      let depth = 1;
      operandEnd = 1;
      while (operandEnd < rest.length && depth > 0) {
        if (rest[operandEnd] === '(') depth++;
        if (rest[operandEnd] === ')') depth--;
        operandEnd++;
      }
    }
    // If starts with another ~, recursively count tildes and then parse primary
    else if (rest.startsWith('~')) {
      // Count consecutive tildes (for potential future multi-NOT support)
      let idx = 0;
      while (idx < rest.length && rest[idx] === '~') {
        idx++;
      }
      const afterTildes = rest.substring(idx).trim();
      
      // Now find the primary expression after all the tildes
      let primaryEnd = 0;
      if (afterTildes.startsWith('(')) {
        let depth = 1;
        primaryEnd = 1;
        while (primaryEnd < afterTildes.length && depth > 0) {
          if (afterTildes[primaryEnd] === '(') depth++;
          if (afterTildes[primaryEnd] === ')') depth--;
          primaryEnd++;
        }
      } else {
        // Check if it's a function call like uint8(4), int16be(10), etc.
        const funcMatch = afterTildes.match(/^([a-zA-Z_$]\w*)\s*\(/);
        if (funcMatch) {
          // Find the matching closing parenthesis for the function call
          let depth = 1;
          primaryEnd = funcMatch[0].length; // Start after the opening '('
          while (primaryEnd < afterTildes.length && depth > 0) {
            if (afterTildes[primaryEnd] === '(') depth++;
            if (afterTildes[primaryEnd] === ')') depth--;
            primaryEnd++;
          }
        } else {
          // Simple identifier or number
          const match = afterTildes.match(/^(0x[0-9a-fA-F]+|\d+|[a-zA-Z_$]\w*)/);
          if (match) {
            primaryEnd = match[0].length;
          }
        }
      }
      
      // Total operand is all the tildes + the primary
      operandEnd = idx + primaryEnd;
    }
    // Otherwise, consume hex number, decimal number, identifier, or function call
    else {
      // Check if it's a function call like uint8(4), int16be(10), etc.
      const funcMatch = rest.match(/^([a-zA-Z_$]\w*)\s*\(/);
      if (funcMatch) {
        // Find the matching closing parenthesis for the function call
        let depth = 1;
        operandEnd = funcMatch[0].length; // Start after the opening '('
        while (operandEnd < rest.length && depth > 0) {
          if (rest[operandEnd] === '(') depth++;
          if (rest[operandEnd] === ')') depth--;
          operandEnd++;
        }
      } else {
        // Match: hex (0x...), decimal number, or identifier
        const match = rest.match(/^(0x[0-9a-fA-F]+|\d+|[a-zA-Z_$]\w*)/);
        if (match) {
          operandEnd = match[0].length;
        } else {
          // Fallback: parse entire rest as operand (shouldn't happen)
          return {
            type: 'bitwiseNot',
            operand: parseExpression(rest)
          };
        }
      }
    }
    
    const operand = parseExpression(rest.substring(0, operandEnd));
    const remaining = rest.substring(operandEnd).trim();
    
    // If there's more after the operand, we need to continue parsing the full expression
    if (remaining) {
      // The ~ is part of a larger expression, wrap the NOT and remaining in parens to reparse
      const fullExpr = '(' + expr.substring(0, operandEnd + 1) + ')' + remaining;
      return parseExpression(fullExpr);
    }
    
    return {
      type: 'bitwiseNot',
      operand
    };
  }

  // Bitwise OR operator (lowest precedence among bitwise)
  const bitwiseOrIndex = findOperatorOutsideParens(expr, '|');
  if (bitwiseOrIndex !== -1) {
    return {
      type: 'bitwiseOr',
      left: parseExpression(expr.substring(0, bitwiseOrIndex)),
      right: parseExpression(expr.substring(bitwiseOrIndex + 1))
    };
  }

  // Bitwise XOR operator
  const bitwiseXorIndex = findOperatorOutsideParens(expr, '^');
  if (bitwiseXorIndex !== -1) {
    return {
      type: 'bitwiseXor',
      left: parseExpression(expr.substring(0, bitwiseXorIndex)),
      right: parseExpression(expr.substring(bitwiseXorIndex + 1))
    };
  }

  // Bitwise AND operator
  const bitwiseAndIndex = findOperatorOutsideParens(expr, '&');
  if (bitwiseAndIndex !== -1) {
    return {
      type: 'bitwiseAnd',
      left: parseExpression(expr.substring(0, bitwiseAndIndex)),
      right: parseExpression(expr.substring(bitwiseAndIndex + 1))
    };
  }

  // Shift operators
  const shiftLeftIndex = findOperatorOutsideParens(expr, '<<');
  if (shiftLeftIndex !== -1) {
    return {
      type: 'shiftLeft',
      left: parseExpression(expr.substring(0, shiftLeftIndex)),
      right: parseExpression(expr.substring(shiftLeftIndex + 2))
    };
  }

  const shiftRightIndex = findOperatorOutsideParens(expr, '>>');
  if (shiftRightIndex !== -1) {
    return {
      type: 'shiftRight',
      left: parseExpression(expr.substring(0, shiftRightIndex)),
      right: parseExpression(expr.substring(shiftRightIndex + 2))
    };
  }

  // Arithmetic operators
  const arithmeticOps = [
    { pattern: '+', type: 'add' },
    { pattern: '-', type: 'subtract' },
    { pattern: '*', type: 'multiply' },
    { pattern: '\\', type: 'divide' },
    { pattern: '%', type: 'modulo' }
  ];

  for (const op of arithmeticOps) {
    const opIndex = findOperatorOutsideParens(expr, op.pattern);
    if (opIndex !== -1) {
      return {
        type: op.type,
        left: parseExpression(expr.substring(0, opIndex)),
        right: parseExpression(expr.substring(opIndex + op.pattern.length))
      };
    }
  }

  // Parenthesized expression - only remove if parentheses wrap the entire expression
  if (expr.startsWith('(') && expr.endsWith(')')) {
    let depth = 0;
    let wrapsEntireExpression = true;
    for (let i = 0; i < expr.length; i++) {
      if (expr[i] === '(') depth++;
      if (expr[i] === ')') depth--;
      // If depth hits 0 before the end, the outer parens don't wrap everything
      if (depth === 0 && i < expr.length - 1) {
        wrapsEntireExpression = false;
        break;
      }
    }
    if (wrapsEntireExpression) {
      return parseExpression(expr.slice(1, -1));
    }
  }

  // Rule identifier (uppercase names like RuleA, MyRule, etc.)
  // YARA rule names must start with a letter and contain only alphanumeric characters and underscores
  if (/^[A-Z][a-zA-Z0-9_]*$/.test(expr)) {
    return { type: 'ruleIdentifier', name: expr };
  }

  // Default: treat as unknown identifier
  return { type: 'identifier', name: expr };
}

/**
 * Find operator outside of parentheses and brackets
 * For word operators (and, or, not), matches with flexible whitespace
 * @param {string} str - String to search
 * @param {string} op - Operator to find (e.g., ' and ', ' or ', '>', '==')
 * @returns {number} Index of operator, or -1 if not found
 */
function findOperatorOutsideParens(str, op) {
  const opTrimmed = op.trim();
  const isWordOp = /^(and|or|not)$/.test(opTrimmed);
  
  let parenDepth = 0;
  let bracketDepth = 0;
  
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '(') parenDepth++;
    if (str[i] === ')') parenDepth--;
    if (str[i] === '[') bracketDepth++;
    if (str[i] === ']') bracketDepth--;
    
    // Only look for operators when outside all brackets and parens
    if (parenDepth === 0 && bracketDepth === 0) {
      if (isWordOp) {
        // For word operators, match the word with flexible surrounding whitespace
        // Must have whitespace before (or be at start)
        const hasWhitespaceBefore = i === 0 || /\s/.test(str[i - 1]);
        if (!hasWhitespaceBefore) continue;
        
        // Skip leading whitespace
        let j = i;
        while (j < str.length && /\s/.test(str[j])) j++;
        
        // Check if operator word matches
        if (str.substring(j, j + opTrimmed.length) === opTrimmed) {
          // Check what comes after the operator
          const afterOp = j + opTrimmed.length;
          const hasWhitespaceAfter = afterOp >= str.length || /\s/.test(str[afterOp]);
          
          if (hasWhitespaceAfter) {
            return i; // Return the position where whitespace before operator starts
          }
        }
      } else {
        // For symbol operators, exact match
        if (str.substring(i, i + op.length) === op) {
          return i;
        }
      }
    }
  }
  return -1;
}

export default {
  parseConditionToAST
};
