# Changelog

## Unreleased

- Added Intercept-only `filter rule` declarations and the `reject(...)` string modifier, which
  discard candidate matches before conditions are evaluated
- Added `rejectRECapture(...)`, which hands the filter capture group 1 of a regex match (falling
  back to the full match) instead of the whole match
- Added the `includeCaptures` scanner option, which attaches capture-group offsets to regex
  matches (1-based indices, absolute byte offsets, names on numbered entries) for downstream
  use without re-running regexes
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