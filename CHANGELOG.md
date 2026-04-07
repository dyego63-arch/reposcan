# Changelog

All notable changes to RepoScan are documented here.

This project follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-04-07

### Added

- **Core scanning engine** — recursive directory walk with SHA-256 hashing, hidden-file detection, symlink loop guards, and configurable skip lists.
- **Four-tier detection** — CRITICAL_MALWARE → HIGH_RISK_LURE → ADVISORY_IP_RISK → INFO severity classification.
- **Signature-based matching** — SHA-256 hash match and filename/path glob patterns loaded from `signatures/malware.json` and `signatures/ip_leak_risk.json`.
- **Heuristic matching** — four built-in rules (HEUR-001 through HEUR-004) for lure-keyword filenames, executable-in-release paths, oversized source maps, and large JS/WASM in AI-themed directories.
- **Interactive cleanup menu** — five post-scan options: manual paths, auto-delete (with per-file confirmation), quarantine, export report, or ignore.
- **CLI subcommands** — `reposcan start` (scan CWD), `reposcan scan <path>`, `reposcan version`, `reposcan signatures`, `reposcan init-hook`.
- **Git hook integration** — `reposcan init-hook --pre-commit` and `--pre-push` to block suspicious commits.
- **Branded TUI** — massive block-letter banner, four-color brand bar, in-place loading screen with progress bar and running counters.
- **JSON output** — `--json` flag for machine-readable scan results.
- **Zero dependencies** — Python standard library only, no network calls, no telemetry.
- **CI pipeline** — GitHub Actions running pytest on Python 3.10, 3.11, 3.12, and 3.13.
- **Comprehensive test suite** — 122 unit tests covering all modules.

### Security

- Strict local-first design: zero network calls, zero data exfiltration.
- All destructive actions (delete, quarantine) require explicit user confirmation.
- Scan root boundary enforcement prevents operating on files outside the target directory.

[1.0.0]: https://github.com/KanavvGupta/reposcan/releases/tag/v1.0.0
