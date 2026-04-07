# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in RepoScan, **please report it privately**.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

### How to Report

Email: **kanavgoyalok@gmail.com**

Include in your report:

- Description of the vulnerability.
- Steps to reproduce.
- Potential impact.
- Suggested fix (if any).

We will acknowledge your report within **48 hours** and aim to release a fix within **7 days** for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Current |
| 0.x.x   | ❌ Unsupported |

## Policies

### Malicious Signature Submissions

We take the integrity of our signature database seriously. We will:

- **Review all signature PRs** for accuracy, sourcing, and potential for false positives.
- **Reject** any PR that:
  - Contains malware samples or links to active malware distribution.
  - Includes proprietary vendor source code or content.
  - Introduces intentionally misleading signatures designed to cause false positives.
  - Lacks public references for claimed indicators.
- **Ban contributors** who repeatedly submit malicious or misleading content.

### Proprietary Code Policy

This project does **not** accept contributions that include:

- Proprietary source code from any vendor.
- Content that could reconstruct copyrighted or trade-secret material.
- Leaked credentials, API keys, or access tokens.

Signatures must use **structural patterns only** (file names, sizes, directory layouts) — never proprietary code content.

### Responsible Disclosure

If you find that a RepoScan signature inadvertently matches legitimate, non-malicious software and causes widespread false positives, please report it as a security issue so we can address it quickly.

---

*Maintained by [THE ABOVE MINDSET](https://github.com/KanavvGupta) · [https://github.com/KanavvGupta/reposcan](https://github.com/KanavvGupta/reposcan)*
