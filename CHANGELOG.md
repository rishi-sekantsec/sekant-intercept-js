# Changelog

## Unreleased

- Added support for the `nocase` modifier on regular expressions (`/foo/ nocase`), which YARA
  accepts as an alias for the `i` flag
- Reworked the literal matching pipeline: the Aho-Corasick automaton is byte-keyed, case/XOR
  variants of a pattern report a single candidate per occurrence, and candidates are verified by an
  exact-position compare instead of a forward window scan
- Fixed non-ASCII text strings never matching raw byte data, literal prefixes extracted from
  optional, alternated, or anchored regex tails (`/https?:/`, `/foo|bar/`, `/^foo/`, `/foo$/`)
  producing wrong matches, and regex match offsets shifting on buffers that are not valid UTF-8
- Added Intercept-only `filter rule` declarations and the `reject(...)` string modifier, which
  discard candidate matches before conditions are evaluated
- Added `rejectRECapture(...)`, which hands the filter capture group 1 of a regex match (falling
  back to the full match) instead of the whole match
- Added the `includeCaptures` scanner option, which attaches capture group 1 to regex matches as
  `{ index, name?, value, offset, length }` — value plus absolute byte position — for downstream use
  without re-running regexes
- Added the `$_` condition placeholder: an undeclared `$_` is the whole buffer as text (the file in
  normal rules, the candidate or capture in filter rules), while a declared `$_` keeps ordinary
  string semantics
- Added `InterceptScanner.scanFilterRules()` for evaluating filter rules directly
- Scan results now expose a non-enumerable `diagnostics` property

## v1.0.1

- Changed default behavior for unknown strings to return false
- Added byte offset to ahocorasick return result
- Added support for nested identifiers in custom modules
- Minor clean up of console log statements
- Updated dependencies to latest versions

## v1.0.0

- Initial Version (Taken from Sekant Security's internal repo)
- Reorganized repo to be open-source friendly
- Renamed source files to align with tool branding
- Updated documentation for open-source consumption
- Added LICENSE and NOTICE for open-source usage
- Added module build command
- 