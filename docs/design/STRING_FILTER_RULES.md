# String Filter Rules

**Status:** Implemented.

For the user-facing summary of every Intercept-only construct, see
[INTERCEPT_EXTENSIONS.md](../general/INTERCEPT_EXTENSIONS.md).

## 1. Summary

An Intercept-only extension that discards verified string matches before rule conditions are
evaluated. Filtering logic lives in `filter rule` declarations, which are compiled separately and
never participate in normal scanning, and is applied through `reject(...)` and
`rejectRECapture(...)` string modifiers.

Compatibility is one-way: every existing YARA rule continues to work unchanged, while rules using
`filter rule`, `reject(...)`, or `rejectRECapture(...)` are compile errors in libyara.

## 2. Syntax

```yara
filter rule short_pe_match {
  condition:
    filesize < 8 and uint16(0) == 0x5A4D
}

filter rule is_high_entropy {
  strings:
    $mz = { 4D 5A }
  condition:
    $mz and math.entropy(0, filesize) > 7.0
}

rule Demo {
  strings:
    $a = "malware" ascii nocase reject(short_pe_match, is_high_entropy)
    $b = { 4D 5A ?? ?? } reject(short_pe_match)
    $c = /dropper[0-9]+/ reject(short_pe_match)
    $d = /download\/([A-Za-z0-9_.-]+)/ rejectRECapture(is_high_entropy)
  condition:
    any of them
}
```

- Filter names are unquoted identifiers, parenthesized, and **case-sensitive** (matching YARA's
  identifier rules).
- `reject(...)` and `rejectRECapture(...)` are supported on text, hex, and regex strings, and may
  appear together on one string.
- Repeated modifiers of either form are allowed and union their own lists.
- An empty `reject()` or `rejectRECapture()` is a no-op.
- `meta:` and `tags:` on filter rules are parsed and ignored.
- Filter rules are always private: they never appear in scan results, `matchedRules`, or rule
  statistics.

## 3. Semantics

- **Input:** the exact bytes of the verified match (`data[offset .. offset + length]`), or of
  capture group 1 for `rejectRECapture(...)` (see below). Nothing before or after the buffer is
  visible.
- **Verdict:** `reject(a, b, ...)` and `rejectRECapture(a, b, ...)` are each an OR — if any listed
  filter returns `true`, the candidate is discarded. Evaluation short-circuits on the first `true`,
  in list order (`reject` first, then `rejectRECapture`).
- **Size bound:** candidates longer than `MAX_FILTER_RULE_BUFFER_SIZE` (4096, exported from
  `interceptScanner.mjs`) are kept without running any filter (reject is treated as `false`). No
  truncation.
- **Errors:** a filter that throws or rejects at runtime contributes `false` (fail-open); the
  remaining filters still run. Record one diagnostic per `(filter, error)` per scan.
- **Buffer-relative facts:** `filesize` is the buffer length, offsets are 0-based within the
  buffer, and `entrypoint` is `0`.
- **Modules:** `string`, `time`, `math`, `hash`, and registered custom modules are available.
  `pe` and `elf` are rejected at compile time because a fragment cannot be parsed meaningfully.
- **Nesting:** filter rules cannot use `reject(...)` or `rejectRECapture(...)`; a filter rule
  cannot reference another filter rule or a regular rule in its condition.

### Capture-based filters

`rejectRECapture(names...)` behaves exactly like `reject(names...)` except for the buffer handed to
the filter:

| String type | Filter receives |
|---|---|
| Regex, group 1 exists and is non-empty | the bytes of **capture group 1** |
| Regex with no capture group | the full match |
| Regex where group 1 did not participate (e.g. `/a|(b)/` matching `a`) | the full match |
| Regex where group 1 is empty (e.g. `/a(.*)b/` matching `ab`) | the full match |
| Text, hex, wide, xor, base64 | the full match |

Only group 1 is used; additional and named groups are ignored. The 4096-byte cap applies to the
match length, so a capture is always within the cap. All other semantics — OR across names,
short-circuiting, fail-open, caching, diagnostics, buffer-relative facts — are unchanged, and the
capture buffer is cached separately from a full-match buffer.

```yara
filter rule no_extension {
  strings:
    $dot = "."
  condition:
    not $dot
}

rule Download {
  strings:
    $url = /download\/([A-Za-z0-9_-]+)/ rejectRECapture(no_extension)
  condition:
    $url
}
```

Here the filter sees only the captured file name, so `$dot` tests the name rather than the URL.

The capture value is derived from the decoded match text using the same conversion the matcher
already uses for reported match lengths.

**Output:** the same group 1 can be surfaced in results with the scanner's
`includeCaptures: true` option, as `captures: [{ index: 1, name?, value, offset, length }]` on each
regex match — absolute byte positions, so downstream can slice the buffer without re-running the
regex. Only group 1 is kept, so other groups' substrings are collectable immediately. Positions use
the ES2022 `d` flag, applied internally; it is off by default to keep output YARA-shaped.

### Accessing the buffer from a condition

An undeclared `$_` refers to the whole buffer passed to the filter, as decoded text:

```yara
filter rule luhn_valid {
  condition:
    validators.isLuhn($_)
}

rule Card {
  strings:
    $c = /card[ =:]+([0-9]{13,19})/ rejectRECapture(luhn_valid)
  condition:
    $c
}
```

| Context | Value of `$_` |
|---|---|
| `reject(...)` filter | the candidate bytes, decoded |
| `rejectRECapture(...)` filter | capture group 1, or the full match on fallback, decoded |
| normal rule | the whole file, decoded |

`$_` is resolved at parse time by rewriting the identifier to a buffer node, so it never enters the
string set: `any of them` and friends are unaffected, and no phantom match is created.

Declaring a string named `$_` overrides the placeholder everywhere. While `$_` is undeclared, the
length/offset/count forms use YARA's spelling (`#_`, `@_`, `!_`) and keep their ordinary
undeclared-identifier behavior:

| Form | Value when `$_` is undeclared |
|---|---|
| `$_` | buffer text; truthy when non-empty |
| `#_` | `0` |
| `@_` | `undefined` |
| `!_` | `undefined` |

`undefined` propagates through every comparison, so `!_ == 0` evaluates to `undefined` rather than
`true`; the rule does not match and a filter rule fails open, keeping the candidate. Use
`filesize` for the buffer length when `$_` is not declared.

Decoding is lossy for invalid UTF-8; use `(0, filesize)` arguments for byte-exact work.

## 4. Compilation

- **Two parsers over the same text, called in order:**
  1. `parseInterceptFilterRuleGroup(text, existingFilterRules, options)` extracts `filter rule`
     blocks and returns `{ rules, diagnostics }`.
  2. `parseYaraRuleGroup(text, existingRules, options)` is unchanged in signature and return type;
     it parses only normal rules and skips each `filter rule` block by tracking brace depth, not
     by relying on the rule-start pattern failing to match.
- `InterceptScanner.compile()` calls the filter parser first, assigns `compiledFilterRules`, then
  calls the normal parser, then performs cross-registry validation.
- Both parsers share identifier and brace handling, so a filter body containing the word `rule`
  cannot be mistaken for a rule start.
- The two registries use independent rule-id spaces so ids cannot collide.
- `parseInterceptFilterRuleGroup` receives the scanner's shared `matchLimits` object, so filter
  string matchers honor the same live `maxMatches` setting as normal strings.
- The filter parser owns duplicate resolution (last one wins) and its diagnostic, since it merges
  new declarations into `existingFilterRules` and renumbers the registry.
- Each compiled string definition gains `reject: string[]` alongside the existing matcher metadata.
- For each filter rule, compilation caches the parsed condition AST and the set of module roots it
  references, so neither is recomputed per candidate.
- Filter references resolve lazily at scan time against the current filter registry, which allows
  forward references within a group and across incremental `compile()` calls.

**Hard errors:** `reject(...)` inside a filter rule, `global filter rule`, and `pe`/`elf`
references inside a filter condition (all detected by the filter parser), plus a filter name
colliding with a regular rule name (detected by `compile()` after both parsers run).

**Accepted modifiers:** `private filter rule` is accepted; the `private` flag is ignored because
filter rules are always private.

**Condition parsing:** each filter condition is parsed at compile time. If parsing fails it falls
back to `parseSimpleCondition`; if that also fails, a diagnostic is recorded and the filter never
rejects.

**Diagnostics:** unknown module roots and invalid filter conditions come from the filter parser;
unknown filter names in a `reject(...)` list are resolved by `compile()` once both registries are
current. All are reported on the scan result rather than the console.

**Duplicates:** a repeated `filter rule` declaration replaces the earlier one (last one wins) and
records a diagnostic.

## 5. Evaluation

Filters run after candidate verification and before string-match facts are built:

```
AC candidates ─┐
full-scan matches ─┴→ verify → reject gate → buildStringMatches → ruleMatches → evaluateConditions
```

Applying the gate before `ruleMatches` keeps `#a`, `@a`, and `$a at N` consistent with only the
surviving matches. The gate must cover both acceptance paths — Aho-Corasick verified candidates and
the full-scan fallback used for hex and non-literal-prefix regex strings.

- **No Aho-Corasick for filters.** Filter strings are evaluated with their normal matchers against
  the candidate buffer (`matcher(buffer, -1)`). With a 4 kB bound this is cheap and removes atom
  nondeterminism from filter verdicts.
- **Verdict cache:** decisions are memoized per `(filter, buffer hash)` for the duration of a scan.
- **Module strategy:** `math`/`hash` closures are built eagerly (construction is nearly free, and
  a missing built-in resolves to `undefined`, which can invert `not` conditions into wrongful
  rejections). Custom modules are initialized lazily, only for filters whose extracted module set
  includes them, with a retry-on-miss fallback if evaluation reports an uninitialized custom
  module.

## 6. Direct invocation API

`scanFilterRules(data, metadata, ruleNames[])` evaluates the named rules from
`compiledFilterRules` against the supplied buffer. It is the observability surface for filter
rules, since normal scans exclude them.

- **Result shape matches `scan()`:** an array of matched-rule objects
  (`{ rule, namespace, tags, metadata, strings }`).
- Requested names that are not registered are skipped silently.
- Uses the same verify → facts → condition path, without the Aho-Corasick automaton.
- `filesize` is the supplied buffer length, so conditions are naturally buffer-relative.
- Must not touch or replace the automaton or rule-match state used by `scan()`.
- `string`/`time`/`math`/`hash` and custom modules are available; `pe`/`elf` remain excluded.
- Custom modules are initialized exactly as they are for normal rules, using the metadata supplied
  to the call: when `scanFilterRules` is invoked from `scan()`, that is the metadata `scan()`
  received. Direct callers pass their own. No candidate-specific fields (offset, length,
  identifier) are exposed.

## 7. Diagnostics

Diagnostics travel on the returned result rather than through console output. `scan()` and
`scanFilterRules()` keep their array-of-matches shape; a non-enumerable `diagnostics` property is
attached to the returned array so iteration and serialization are unchanged.

Diagnostics include:

- A duplicate `filter rule` declaration replacing an earlier definition, recorded at compile time
  and attached to subsequent scan results until the registry changes.
- Unknown filter names and unknown module roots in filter rules.
- A single entry per scan when a candidate exceeds `MAX_FILTER_RULE_BUFFER_SIZE` and its filters
  are skipped.
- Per-filter rejection counts for the scan.

Each entry is structured:

```js
{
  code,      // duplicate-filter-rule | unknown-filter-rule | unknown-module |
             // invalid-filter-condition | filter-buffer-too-large | filter-error
  severity,  // "warning" | "error" | "info"
  message,
  rule,      // owning rule name, when applicable
  filter,    // filter rule name, when applicable
  string,    // string identifier, when applicable
}
```

An opt-in debug listing of rejected `(rule, string, offset)` tuples may be added to the same
property.

## 8. YARA compatibility

| Construct | libyara | Intercept |
|---|---|---|
| Existing rules | Valid | Valid, behavior unchanged |
| `filter rule ...` | Syntax error | Valid |
| `reject(...)` modifier | Syntax error | Valid |

The only compatibility risk is parser regression for valid YARA. Because `reject(...)` contains no
quotes, the existing string-definition split remains valid for text strings; regex parsing needs an
explicit split between the flag token and trailing modifiers.

## 9. Implementation touch points

- `src/yaraRuleCompiler.mjs` — new `parseInterceptFilterRuleGroup`, filter-block skipping in
  `parseYaraRuleGroup`, filter validation, cached AST/module extraction.
- `src/yaraStringMatch.mjs` — `reject` extraction for text, hex, and regex; regex flag/modifier
  split fix.
- `src/interceptScanner.mjs` — `compiledFilterRules`, reject gate ahead of `buildStringMatches`,
  `scanFilterRules`, stats, cache invalidation.
- `src/yaraConditionsMatch.mjs` — unchanged; filter evaluation reuses `createScanFacts` and
  `evaluateCondition`.

## 10. Resolved decisions

| Question | Decision |
|---|---|
| Filter rule parsing | Separate `parseInterceptFilterRuleGroup`, called before `parseYaraRuleGroup` |
| Unknown name in `scanFilterRules` | Silent skip |
| `scanFilterRules` result shape | Same as `scan()` |
| Duplicate filter declaration | Report in `diagnostics`, not on the console |
| Metadata for custom modules | Same metadata `scan()` received; `scan()` passes it to `scanFilterRules()` |
| Filter condition parse failure | `parseSimpleCondition` fallback, else never reject + diagnostic |
| `private filter rule` | Accepted, `private` ignored |
| Diagnostics entry shape | Structured `{ code, severity, message, rule, filter, string }` |
| Candidate cap constant | `MAX_FILTER_RULE_BUFFER_SIZE` in `interceptScanner.mjs` |
| `rejectRECapture` group selection | Group 1 only; named and later groups ignored |
| Missing/empty/non-participating group | Fall back to the full match |
| String types for `rejectRECapture` | All three; text and hex always fall back |
| Buffer placeholder | Undeclared `$_`, rewritten at parse time; a declared `$_` wins |
| Placeholder type | Decoded text; `(0, filesize)` for byte-exact work |
| `#_` / `@_` / `!_` when `$_` is undeclared | `0` / `undefined` / `undefined` (fail-open in filters) |
| Capture output | Opt-in `includeCaptures`; group 1 only, with `value` plus byte `offset`/`length` via internal `d` |

## 11. Assumptions

Unless revised, these follow from the decisions above:

1. `entrypoint` evaluates to `0` inside filter rules, since there is no file-level entry point for a
   fragment.
2. Compile-time diagnostics persist on the scanner and are attached to each returned result until
   the next `compile()`/`clearRules()`, including scans with no matched rules.
3. Rejection counts are per scan, not cumulative.
4. Custom-module metadata for filter evaluation reports `filesize` as the buffer length and
   `hasPE`/`hasELF` as `false`, matching the buffer's limited scope.
