<p align="center">
  <img src="assets/logo-above-mindset.png" alt="THE ABOVE MINDSET" width="120" />
</p>

<h1 align="center">REPOSCAN</h1>

<p align="center">
  <strong>One-command security scanner that finds fake Claude Code leak malware droppers<br/>and other suspicious artifacts in your repositories.</strong><br /><br />
  Zero extra dependencies. Zero network calls. Just answers.<br /><br />
  <em>by <a href="https://github.com/KanavvGupta">THE ABOVE MINDSET</a></em>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#quick-guide">Quick Guide</a> •
  <a href="#what-you-see">What You See</a> •
  <a href="#features">Features</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#interactive-menu">Interactive Menu</a> •
  <a href="#limitations">Limitations</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <em>If reposcan helps you stay safe when cloning sketchy repos, consider dropping a ⭐ — it's how other developers find tools like this.</em>
</p>

---

## The Problem

"Leaked" AI source code is the new honeypot.

When Anthropic's Claude Code source was [accidentally exposed via npm](https://www.bleepingcomputer.com/news/security/anthropic-claude-code-source-accidentally-exposed-via-npm/) in March 2026, threat actors flooded GitHub with **fake "leaked" repos** that actually dropped **Vidar info-stealers** and **GhostSocks proxy malware** via trojanised executables — within hours.

This pattern keeps repeating. AI-themed fake repos are now a top vector for infecting developers, and there's no simple, local-only tool to answer the most basic question:

> **"I just cloned this repo. Is it obviously dangerous?"**

**RepoScan** exists to answer that question — fast, offline, and honestly.

## Quickstart

### Install

```bash
git clone https://github.com/KanavvGupta/reposcan.git
cd reposcan
pip install -e .
```

### Run (one command)

```bash
reposcan start
```

That's it. RepoScan scans the current folder, shows you a branded banner, a plain-English summary, and — if anything suspicious is found — an interactive menu to help you clean up.

## Quick Guide

**Scan this folder**
Use **`reposcan start`** to scan the folder you are currently in.

**Scan a specific folder**
Use **`reposcan scan "<path>"`** to scan a folder you choose.
Example: **`reposcan scan "C:\Users\YourName\Downloads"`**

**Scan an entire drive** *(advanced)*
Use **`reposcan scan C:\`** to scan an entire drive.
This is an advanced option and may take longer on large drives.

> [!NOTE]
> RepoScan never scans your whole PC by default. The `start` command always scans only the current folder. Drive-level scanning only happens when you explicitly pass a drive root as the path.

## What You See

### Clean run

```
  ██████████████████████████████████████████████████████████████████████████████

  ██████╗ ███████╗██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝█████╗  ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║  ██║███████╗██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

                      by  THE  [ ABOVE ]  MINDSET

  ──────────────────────────────────────────────────────────────────────────
              v1.0.0  ·  Local-First Repo Safety Scanner
  ██████████████████████████████████████████████████████████████████████████████

  Good news: RepoScan did not find anything obviously dangerous in this folder.

  Scan Summary
  ────────────────
  Target:             /home/user/my-project
  Files scanned:      42
  Files skipped:      3
  Critical findings:  0
  Advisory findings:  0
  Scan time:          0.012s
```

### Run with a critical detection

```
  ██████████████████████████████████████████████████████████████████████████████

  ██████╗ ███████╗██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ...
                      by  THE  [ ABOVE ]  MINDSET
  ──────────────────────────────────────────────────────────────────────────
  ██████████████████████████████████████████████████████████████████████████████

  Warning: RepoScan found suspicious files in this folder. Read the summary below.

  Scan Summary
  ────────────────
  Target:             /home/user/fake-claude-repo
  Files scanned:      15
  Critical findings:  1
  Advisory findings:  0
  Scan time:          0.008s

  🚨 CRITICAL FINDINGS
  ────────────────────────

  [CRITICAL]  [MAL-001] Vidar Dropper — ClaudeCode Lure (primary)
    File:    releases/ClaudeCode_x64.exe
    SHA-256: a1b2c3d4...
    Size:    2,450,000 bytes
    Matched: Filename pattern match: ClaudeCode_x64.exe
    Info:    Rust-based dropper delivering Vidar infostealer via fake Claude Code repos.

  What do you want to do next?
  ────────────────────────────────

  [1]  Show locations so I can clean things manually
  [2]  Let RepoScan remove dangerous files for me (recommended for confirmed malware)
  [3]  Move suspicious files into a quarantine folder
  [4]  Export a report and exit
  [5]  Ignore and exit (not recommended)

  › Choose an option [1-5]:
```

## Features

- 🔒 **100 % local** — zero network calls, zero telemetry, zero cloud dependencies
- ⚡ **Fast** — streams SHA-256 hashes; scans thousands of files in seconds
- 🎯 **Four-tier detection** — CRITICAL → HIGH RISK → ADVISORY → INFO
- 🧹 **Interactive cleanup** — manual, auto-delete, or quarantine
- 🪝 **Git hook integration** — block commits or pushes that contain threats
- 📦 **Zero dependencies** — Python standard library only
- 🖥️ **God-tier banner** — massive REPOSCAN block letters with branded color bars
- 🔓 **MIT licensed** — use it anywhere, fork it, improve it

## Interactive Menu

When RepoScan finds suspicious files, it shows a 5-option menu:

### Option 1 — Manual cleanup
Shows copy-paste-ready absolute file paths. For each file, you get a one-line recommendation: "Delete this file if you do not trust this repository." Optionally saves text + JSON reports.

### Option 2 — Automatic removal (critical only)
Walks through each `CRITICAL_MALWARE` file with a per-file confirmation prompt. If you decline, RepoScan asks once more with a stronger warning. Non-critical files are offered for quarantine instead.

### Option 3 — Quarantine
Moves all actionable files into `./reposcan_quarantine/<timestamp>/`, preserving relative paths. Original and new paths are printed. Files are marked as "QUARANTINED" in reports.

### Option 4 — Export report and exit
Writes `reposcan-findings-YYYYMMDD-HHMM.json` and `.txt` reports without deleting anything. Exits with non-zero if there were findings.

### Option 5 — Ignore and exit
Prints a strong warning that the folder may still be dangerous. Exits with non-zero if there were findings.

## CLI Reference

```
reposcan start                  One-command quickstart: scan CWD interactively
reposcan scan <path> [options]  Scan a directory
reposcan version                Show version and branding
reposcan signatures             Show loaded signature database details
reposcan init-hook              Install a git hook

scan options:
  --json                Output as JSON (no colors/art)
  --no-color            Disable colored output
  --auto                Show interactive menu after scan
  --follow-symlinks     Follow symbolic links
  --no-ip-checks        Skip IP/leak-risk checks
  --fail-on-ip-risk     Exit 1 on advisory findings
  --no-heuristics       Disable built-in heuristic detection
  --signatures-dir DIR  Custom signatures directory
  --exclude PATTERN     Glob pattern to exclude (repeatable)
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no suspicious findings |
| `1` | **Findings** — malware or high-risk files detected |
| `2` | **Error** — bad path, missing signatures, etc. |

### Color control

RepoScan respects:
- `--no-color` flag
- `NO_COLOR` environment variable (any value)

## Git Hook Integration

```bash
cd /path/to/your/project
reposcan init-hook --pre-commit
```

Blocks commits if threats are found. To bypass: `git commit --no-verify`

For pushes: `reposcan init-hook --pre-push`

## Signatures

Signatures live as JSON files in the `signatures/` directory:

- **`malware.json`** — SHA-256 hashes and filename patterns for known malware
- **`ip_leak_risk.json`** — structural patterns for IP/leak-risk indicators

### Updating

```bash
cd reposcan && git pull origin main
```

### Adding Signatures

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose new signatures.

## Limitations

> [!WARNING]
> **RepoScan is a lightweight first-pass tool, not a comprehensive security solution.**

- ❌ Does **not** perform deep static analysis, behavioural analysis, or sandboxing
- ❌ Does **not** scan container images or network traffic
- ❌ Does **not** replace professional endpoint protection
- ❌ Does **not** detect zero-day threats or novel malware
- ❌ Signature coverage is limited — community contributions are essential

> [!IMPORTANT]
> **This tool is not legal advice.** It cannot guarantee that a repository is safe, free of malware, or free of intellectual property issues. Always exercise caution with code from untrusted sources.

## Project Structure

```
reposcan/
├── src/reposcan/        # Core Python package
│   ├── cli.py           # CLI entry point, subcommands, interactive menus
│   ├── scanner.py       # Recursive file discovery, hidden file detection, SHA-256 hashing
│   ├── signatures.py    # Signature definitions + JSON loader
│   ├── matcher.py       # File classification logic (4-tier severity)
│   ├── actions.py       # Delete, quarantine, confirmation helpers
│   ├── reporter.py      # Summary/detailed report builders (text + JSON)
│   ├── theme.py         # ANSI colors, banner rendering, styled print helpers
│   └── hooks.py         # Git hook installer
├── signatures/          # Signature databases (JSON)
│   ├── malware.json
│   └── ip_leak_risk.json
├── tests/               # Unit tests
├── docs/                # Documentation + branding
└── pyproject.toml       # Package configuration
```

## Contributing

Contributions are welcome — whether it's a new signature, a bug fix, or better docs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability or a false-negative signature? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <em>Stars are how security tools get discovered.<br />If you think reposcan should exist, a quick ⭐ makes a real difference.</em>
</p>

<p align="center">
  <strong>Created by <a href="https://github.com/KanavvGupta">THE ABOVE MINDSET</a></strong><br />
  <em>Stay above the noise.</em>
</p>
