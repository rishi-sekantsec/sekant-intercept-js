# Intercept Extensions to Standard YARA

This document describes the constructs Intercept accepts beyond standard YARA. Compatibility is
one-way: **every valid YARA rule runs unchanged in Intercept, but rules using these extensions do
not run in libyara.**

| Construct | Kind | Purpose |
|---|---|---|
| `filter rule <name> { ... }` | Rule declaration | Reusable predicate, compiled separately from normal rules |
| `reject(...)` | String modifier | Discard a match when a filter rule returns `true` |
| `rejectRECapture(...)` | String modifier | Same, but the filter sees capture group 1 |
| `$_` | Condition placeholder | The whole buffer as text |

Implementation notes live in [STRING_FILTER_RULES.md](../design/STRING_FILTER_RULES.md) and
[STRING_MATCHING_ENGINE.md](../developer/STRING_MATCHING_ENGINE.md).

---

## 1. Filter rules

```yara
filter rule short_match {
  condition:
    filesize < 8 and uint16(0) == 0x5A4D
}

filter rule no_digits {
  strings:
    $d = /[0-9]/
  condition:
    $d
}
```

A `filter rule` is a predicate that is never scanned on its own:

- It is compiled into a separate registry (`InterceptScanner.compiledFilterRules`) and never
  participates in Aho-Corasick matching, rule conditions, or scan results.
- It is always private; `private filter rule` is accepted and the flag is ignored.
- It may contain `strings:` and `meta:`/`tags:` (parsed, tags/metadata ignored by `scan()`).
- It may not use `reject(...)` or `rejectRECapture(...)` (no nesting), may not be `global`, and may
  not reference another rule in its condition.
- `pe` and `elf` are unavailable, since a filter sees a fragment rather than a parsed binary.
- `string`, `time`, `math`, `hash`, and custom modules are available.
- A repeated declaration replaces the earlier one (last one wins) and reports a diagnostic.

### What a filter sees

A filter rule is evaluated against **one buffer and nothing else**. `filesize` is that buffer's
length, offsets start at 0, and `entrypoint` is `0`. This bounds the cost of filtering and makes it
independent of file size.

## 2. `reject(...)`

```yara
rule Demo {
  strings:
    $a = "malware" reject(short_match, no_digits)
  condition:
    $a
}
```

- Supported on text, hex, and regex strings.
- The filter receives the full verified match (`data[offset .. offset + length]`), capped at
  `MAX_FILTER_RULE_BUFFER_SIZE` (4096 bytes). Longer matches keep the candidate and skip filtering,
  with a diagnostic.
- Names are case-sensitive; repeated `reject(...)` modifiers union their lists; `reject()` is a
  no-op; unknown names are ignored and reported in `diagnostics`.
- Any listed filter returning `true` discards the match **before** string facts are built, so `#a`,
  `@a`, and `$a at N` reflect surviving matches only.
- A filter that throws contributes `false` (fail-open).

## 3. `rejectRECapture(...)`

```yara
rule Card {
  strings:
    $c = /card[ =:]+([0-9]{13,19})/ rejectRECapture(luhn_valid)
  condition:
    $c
}
```

Identical to `reject(...)` except for the buffer handed to the filter:

| String type | Filter receives |
|---|---|
| Regex, group 1 exists and is non-empty | capture group 1 |
| Regex with no capture group | the full match |
| Regex where group 1 did not participate | the full match |
| Regex where group 1 is empty | the full match |
| Text, hex, wide, xor, base64 | the full match |

Only group 1 is used; named and later groups are ignored. `reject(...)` and `rejectRECapture(...)`
may appear together on one string, and each filter name keeps the buffer its own modifier implies.

## 4. The `$_` placeholder

Inside a condition, an **undeclared** `$_` refers to the whole buffer being evaluated, as decoded
text:

```yara
filter rule luhn_valid {
  condition:
    validators.isLuhn($_)
}
```

| Context | Value of `$_` |
|---|---|
| `reject(...)` filter | candidate bytes, decoded |
| `rejectRECapture(...)` filter | capture group 1, or the full match on fallback, decoded |
| normal rule | the whole file, decoded |

Because it yields text, it drops straight into module functions that accept a string:
`string.length($_)`, `hash.md5($_)`, `math.entropy($_)`.

### Declaring `$_` overrides it

`$_` is a legal YARA string identifier. If the rule declares one, the placeholder does not apply
and `$_` behaves exactly as a normal string — identical to libyara:

```yara
rule UsesOwnString {
  strings:
    $_ = "abc"
  condition:
    $_
}
```

### Undefined behavior when `$_` is not declared

The length/offset/count forms use YARA's spelling, built from the bare name — `#_`, `@_`, `!_`, not
`#$_`. While `$_` is undeclared they keep ordinary undeclared-identifier behavior:

| Form | Value when `$_` is undeclared |
|---|---|
| `$_` | the buffer, as text (truthy when non-empty) |
| `#_` | `0` |
| `@_` | `undefined` |
| `!_` | `undefined` |

`undefined` propagates through every comparison, so `!_ == 0` evaluates to `undefined`, not `true`:
the rule does not match, and a filter rule fails open (the candidate is kept). Use `filesize` when
the buffer length is required and `$_` is not declared.

The placeholder is resolved at parse time and never enters the string set, so `them` — and therefore
`any of them`, `all of them`, `N of them` — is unaffected and no phantom match is created.

### Text, not bytes

`$_` is decoded with `TextDecoder`, so it is lossy for invalid UTF-8. Use `(0, filesize)` arguments
(`hash.md5(0, filesize)`, `math.entropy(0, filesize)`) when byte-exact access is required.

---

## 5. Other Intercept-only details

Minor extensions that are documented where they are implemented:

- `$a[i]` — the i-th matched substring, built from `@a[i]` and `!a[i]`. Standard YARA has no
  indexed form of `$a`.
- `@a[0]` and `!a[0]` — treated as the first match. Standard YARA leaves index 0 undefined.
- Modules are available without `import`; `import` statements are validated but optional. See
  [ENGINE_DIFFERENCES.md](ENGINE_DIFFERENCES.md).

## 6. Compatibility summary

| Construct | libyara | Intercept |
|---|---|---|
| Existing rules | Valid | Valid, unchanged |
| `filter rule ...` | Syntax error | Valid |
| `reject(...)` | Syntax error | Valid |
| `rejectRECapture(...)` | Syntax error | Valid |
| Undeclared `$_` | Compile error | Whole buffer, as text |
| Declared `$_ = "..."` | Valid | Valid, identical |

---
**Last Updated:** 2026-11-22
