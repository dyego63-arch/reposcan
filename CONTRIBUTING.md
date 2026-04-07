# Contributing to reposcan

Thank you for your interest in contributing to **reposcan**! This project is maintained by [THE ABOVE MINDSET](https://github.com/KanavvGupta) and thrives on community contributions.

## How to Contribute

### 🐛 Reporting Bugs

Open a [GitHub Issue](https://github.com/KanavvGupta/reposcan/issues/new) with:

- **What happened** — clear description of the bug.
- **What you expected** — what should have happened.
- **Steps to reproduce** — minimal commands to trigger the bug.
- **Environment** — OS, Python version (`python --version`), reposcan version (`reposcan version`).

### 🚨 Reporting False Positives / Negatives

If reposcan flags a legitimate file (false positive) or misses a known threat (false negative):

1. Open a GitHub Issue with the label `false-positive` or `false-negative`.
2. Include:
   - The file name and approximate size (do **NOT** upload malware samples).
   - The signature ID that matched (or should have matched).
   - Any public references (VirusTotal links, threat intel reports, etc.).

### 📝 Proposing New Signatures

Signatures are the heart of reposcan. We welcome community contributions! To propose new signatures:

1. **Fork the repo** and create a branch: `git checkout -b sigs/add-<name>`.
2. **Edit the appropriate JSON file** in `signatures/`:
   - `malware.json` for malware indicators.
   - `ip_leak_risk.json` for IP/leak-risk indicators.
3. **Follow the existing schema** — each entry must include:
   - A unique `id` (e.g., `MAL-005`, `IPR-003`).
   - A descriptive `name` and `description`.
   - `severity` (`CRITICAL`, `HIGH`, `ADVISORY`, `WARNING`).
   - At least one indicator (hash, filename pattern, path pattern, etc.).
   - At least one `references` URL pointing to **public** threat intelligence.
4. **Open a Pull Request** with a clear description.

#### Signature Requirements

> ⚠️ **Critical rules for signature submissions:**
>
> - **Public sources only** — Signatures must be based on publicly available IOCs, threat reports, or blog posts. Do not submit indicators derived from proprietary or classified intelligence.
> - **No proprietary code** — Do not include vendor source code, proprietary strings, or any content that could reconstruct copyrighted material.
> - **Keep it lawful** — Do not submit malware samples, stolen credentials, or any illegal content.
> - **False positive awareness** — Overly broad patterns that generate excessive false positives will be rejected.

### 💻 Contributing Code

1. **Fork and clone** the repo.
2. **Create a feature branch**: `git checkout -b feature/<name>`.
3. **Install in dev mode**: `pip install -e ".[test]"`
4. **Run tests**: `python -m pytest tests/ -vv`
5. **Follow the code style**:
   - Python 3.10+ type hints.
   - Docstrings on all public functions.
   - Zero external dependencies (stdlib only).
   - Keep it simple — this is an MVP.
6. **Open a Pull Request** targeting `main`.

### Code Style

- **Formatter**: We recommend `black` but don't enforce it.
- **Linter**: `ruff` or `flake8` for basic checks.
- **Type hints**: Use `from __future__ import annotations` and standard library types.
- **Tests**: Add tests for new logic. Use `pytest` (installed via `pip install -e ".[test]"`).

## Pull Request Checklist

- [ ] Code runs without errors on Python 3.10+.
- [ ] Existing tests pass: `python -m pytest tests/ -vv`.
- [ ] New tests added for new functionality.
- [ ] No external dependencies introduced.
- [ ] Signature changes include public references.
- [ ] No proprietary, classified, or illegal content.

## Code of Conduct

Be respectful, constructive, and security-minded. We're building a tool to protect developers — let's model the behaviour we want to see.

---

*Maintained by [THE ABOVE MINDSET](https://github.com/KanavvGupta)*
