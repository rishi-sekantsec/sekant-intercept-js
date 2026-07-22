# Contribution Guidelines

## Getting Started

1.  **Repository**: Clone repository.
2.  **Language**: Pure JavaScript (ES Modules). No transpilation (TypeScript/Babel) is currently used, preserving drop-in compatibility.
3.  **Dependencies**: Zero runtime dependencies. devDependencies are allowed for testing only.

## Development Workflow

### 1. Code Style
-   **Files**: `.mjs` extension for ES modules.
-   **Imports**: Relative imports (e.g., `import { X } from './utils.mjs'`).
-   **Formatting**: Standard JS formatting.
-   **Documentation**: JSDoc comments are required for all public classes and complex methods.

### 2. Adding Features
-   **New Modules**: See [CUSTOM_MODULE_OVERVIEW.md](CUSTOM_MODULE_OVERVIEW.md).
-   **Grammar Changes**:
    1.  Update `yaraConditionParser.mjs` (Recursive Descent Parser).
    2.  Update `yaraConditionsMatch.mjs` (Evaluator).
    3.  Add tests in `tests/` covering the new syntax.
    4.  Update [CONDITIONS_MATCHING_ENGINE.md](CONDITIONS_MATCHING_ENGINE.md).

### 3. Pull Requests
-   Run the full test suite (`npm run test`) before submitting.
-   Ensure no performance regressions.

## Release Checklist

-   [ ] Verify `docs/` are up to date with code changes.
-   [ ] Check `TODO.md` for blocking issues.

## Roadmap & Priorities

See `TODO.md` for the current backlog. 

---
**Last Updated:** 2026-02-21
