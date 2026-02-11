# Conditions Matching Engine

## Architecture

The Conditions Matching Engine (`yaraConditionsMatch.mjs`) is an asynchronous evaluator that determines if a rule applies to a file. It takes two inputs:
1.  **Condition AST**: A JSON tree representing the logic of the rule's `condition:` section.
2.  **ScanFacts**: The structured data from the scanning phase.

The evaluator traverses the AST recursively. Async/await is used throughout to support potentially async operations (though most checks are sync, this design allows for async module functions or I/O in the future).

## AST Format

The AST (Abstract Syntax Tree) is a JSON-serializable format produced by the `yaraConditionParser.mjs`.

### Node Types

#### Atoms
```javascript
{ type: 'boolean', value: true }
{ type: 'number', value: 123 }
{ type: 'string', value: "literal" }
{ type: 'identifier', name: "filesize" } // filesize, entrypoint
```

#### String References
```javascript
{ type: 'stringIdentifier', identifier: "$a" } // Condition: $a
{ type: 'stringCount', identifier: "$a" }      // Condition: #a
{ type: 'stringOffset', identifier: "$a", index: ... } // Condition: @a
{ type: 'stringLength', identifier: "$a", index: ... } // Condition: !a
```

#### Operations
```javascript
{ 
  type: 'and', // or 'or', 'add', 'subtract', 'equal', 'lessThan', etc.
  left: { ... }, 
  right: { ... } 
}
{ type: 'not', operand: { ... } }
```

#### Loops & Quantifiers
```javascript
{ 
  type: 'for', 
  quantifier: 'all', // 'any', 'none', number, percentage
  variable: 'i',     // Loop variable
  set: { type: 'range', start: ..., end: ... }, 
  condition: { ... } // Body expression
}
```

## Supported Operators

### Logical & Arithmetic
-   **Logic**: `and`, `or`, `not`
-   **Math**: `+`, `-`, `*`, `\`, `%`
-   **Bitwise**: `&`, `|`, `^`, `~`, `<<`, `>>`
    -   *Note*: Bitwise operators have **higher precedence** than comparisons in this engine (`$a | $b == 0` -> `($a | $b) == 0`).

### Comparison
-   `==`, `!=`, `<`, `>`, `<=`, `>=`
-   `contains`, `icontains` (case-insensitive)
-   `startswith`, `istartswith`
-   `endswith`, `iendswith`
-   `matches` (Regex match)

### Scope & Strings
-   `in` (Set membership or range)
-   `at` (Fixed offset check)
-   `within` (Proximity check)

### Quantifiers
-   `any of them`, `all of them`, `none of them`
-   `X of them` (count), `X% of them` (percentage)

## Unsupported Operators / Limitations

1.  **External Variables**: The engine does not support injected variables (`-d var=val`).
2.  **Include Directive**: `include` is not supported (handled at the compiler/pre-processor level only or logic manual merge).
3.  **Iteration Constraints**:
    -   Cannot iterate over arbitrary integer sets (e.g., `for i in (1,5,9)`).
    -   Cannot iterate over module arrays directly (e.g., `for s in pe.sections`).

## Module Integration

Modules are accessed via the `ScanFacts.modules` object.
-   **Property Access**: `pe.number_of_sections` -> resolves to `scanFacts.modules.pe.number_of_sections`.
-   **Function Calls**: `math.min(1, 2)` -> executes the function on the module instance.

## Error Handling

-   **Undefined Operands**: In line with YARA spec, many operations involving `undefined` (e.g., failed module field access) propagate `undefined` rather than throwing, eventually evaluating to `false` in boolean contexts.
-   **Missing Modules**: Accessing a module that wasn't loaded (e.g., `pe` on a non-PE file) safely returns `undefined`.

---
**Last Updated:** 2026-02-11
