# String Filter Rules

**Status:** Draft — not implemented.

## 1. Summary

An Intercept-only extension that discards verified string matches before rule conditions are
evaluated. Filtering logic lives in `filter rule` declarations, which are compiled separately and
never participate in normal scanning, and is applied through a `reject(...)` string modifier.

Compatibility is one-way: every existing YARA rule continues to work unchanged, while rules using
`filter rule` or `reject(...)` are compile errors in libyara.

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
  condition:
    $a or $b or $c
}
```

- Filter names are unquoted identifiers, parenthesized, and **case-sensitive** (matching YARA's
  identifier rules).
- `reject(...)` is supported on text, hex, and regex strings.
- Repeated `reject(...)` modifiers are allowed and union their lists.
- An empty `reject()` is a no-op.
- `meta:` and `tags:` on filter rules are parsed and ignored.
- Filter rules are always private: they never appear in scan results, `matchedRules`, or rule
  statistics.

## 3. Semantics

- **Input:** the exact bytes of the verified match (`data[offset .. offset + length]`). Nothing
  before or after the match is visible.
- **Verdict:** `reject(a, b, ...)` is an OR — if any listed filter returns `true`, the candidate is
  discarded. Evaluation short-circuits on the first `true`.
- **Size bound:** candidates longer than `MAX_FILTER_RULE_BUFFER_SIZE` (4096, exported from
  `interceptScanner.mjs`) are kept without running any filter (reject is treated as `false`). No
  truncation.
- **Errors:** a filter that throws or rejects at runtime contributes `false` (fail-open); the
  remaining filters still run. Record one diagnostic per `(filter, error)` per scan.
- **Buffer-relative facts:** `filesize` is the buffer length, offsets are 0-based within the
  buffer, and `entrypoint` is `0`.
- **Modules:** `string`, `time`, `math`, `hash`, and registered custom modules are available.
  `pe` and `elf` are rejected at compile time because a fragment cannot be parsed meaningfully.
- **Nesting:** filter rules cannot use `reject(...)`; a filter rule cannot reference another
  filter rule or a regular rule in its condition.

## 4. Compilation

- `parseYaraRuleGroup` recognizes a `filter` prefix before `rule` and routes declarations into a
  separate registry (`compiledFilterRules`), keeping `compiledRules` unchanged.
- The two registries use independent rule-id spaces so ids cannot collide.
- Each compiled string definition gains `reject: string[]` alongside the existing matcher metadata.
- For each filter rule, compilation caches the parsed condition AST and the set of module roots it
  references, so neither is recomputed per candidate.
- Filter references resolve lazily at scan time against the current filter registry, which allows
  forward references within a group and across incremental `compile()` calls.

**Hard errors:** `reject(...)` inside a filter rule, `global filter rule`, a filter name colliding
with a regular rule name, and `pe`/`elf` references inside a filter condition.

**Diagnostics:** unknown filter names in a `reject(...)` list, and unknown module roots in a filter
condition. Both are reported on the scan result rather than the console.

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
- Custom modules receive only the candidate buffer and the **scanner's global metadata** — never
  per-call metadata or candidate-specific fields (offset, length, identifier).

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

- `src/yaraRuleCompiler.mjs` — `filter` rule prefix, registry split, validation, cached AST/module
  extraction.
- `src/yaraStringMatch.mjs` — `reject` extraction for text, hex, and regex; regex flag/modifier
  split fix.
- `src/interceptScanner.mjs` — `compiledFilterRules`, reject gate ahead of `buildStringMatches`,
  `scanFilterRules`, stats, cache invalidation.
- `src/yaraConditionsMatch.mjs` — unchanged; filter evaluation reuses `createScanFacts` and
  `evaluateCondition`.

## 10. Resolved decisions

| Question | Decision |
|---|---|
| Unknown name in `scanFilterRules` | Silent skip |
| `scanFilterRules` result shape | Same as `scan()` |
| Duplicate filter declaration | Report in `diagnostics`, not on the console |
| Custom module inputs | Candidate buffer + scanner global metadata only |
| Candidate cap constant | `MAX_FILTER_RULE_BUFFER_SIZE` in `interceptScanner.mjs` |

## 11. Assumptions

Unless revised, these follow from the decisions above:

1. `entrypoint` evaluates to `0` inside filter rules, since there is no file-level entry point for a
   fragment.
2. Compile-time diagnostics persist on the scanner and are attached to each returned result until
   the next `compile()`/`clearRules()`.
3. Rejection counts are per scan, not cumulative.
