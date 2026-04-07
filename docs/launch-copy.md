# reposcan — Launch Copy

> All launch-ready text for GitHub, Hacker News, and X/Twitter.

---

## 1. GitHub Repo Description (≤160 chars)

```
Local-first CLI to scan cloned repos for known malware & IP-leak-risk. Zero deps, zero uploads. — by THE ABOVE MINDSET
```

---

## 2. Hacker News Submission

**Title** (< 80 chars):

```
Show HN: Reposcan – local-only CLI that scans cloned repos for fake-leak malware
```

**Body:**

Last week, Anthropic accidentally leaked Claude Code's source via npm. Within 48 hours, threat actors created dozens of fake "Claude Code leak" repos on GitHub that actually delivered Vidar info-stealers and GhostSocks proxy malware via trojanized executables.

This is part of a bigger pattern: AI-themed fake repos are becoming a top attack vector targeting developers who clone trending or "leaked" repos without a second thought.

I built **reposcan** — a small, local-only, zero-dependency Python CLI that scans a directory against known malware signatures (SHA-256 hashes + filename patterns) and optionally flags IP/leak-risk indicators. It runs entirely on your machine — no files or hashes are uploaded anywhere. It also ships with a git pre-commit hook that blocks suspicious commits.

This is v1.0 — the signature database is small and community contributions are essential. It won't catch zero-days or do deep static analysis. But it answers a question that no existing lightweight tool does: "Is this repo I just cloned obviously dangerous?"

GitHub: https://github.com/KanavvGupta/reposcan

Built under THE ABOVE MINDSET — because developers deserve better defaults.

---

## 3. X / Twitter Launch Thread

**Tweet 1 — Hook:**
```
🚨 Devs are getting infected by cloning "leaked Claude Code" repos on GitHub.

Those repos? Fake. The payloads? Real — Vidar info-stealers and GhostSocks proxy malware.

Here's what's happening and what I built to help. 🧵
```

**Tweet 2 — Context:**
```
Last week, Anthropic accidentally exposed Claude Code source via npm.

Within 48 hours, attackers flooded GitHub with fake "leak" repos — SEO-optimized, convincing READMEs, promising "unlocked enterprise features."

Inside: ClaudeCode_x64.exe → Rust-based dropper → Vidar + GhostSocks.
```

**Tweet 3 — The problem:**
```
This isn't new. AI-themed fake repos have impersonated 25+ brands in 2026 alone.

And there's NO simple tool for an individual dev to run:

"I just cloned this repo. Is it obviously dangerous?"

Enterprise SCA tools exist. But they're overkill for a developer on a Saturday.
```

**Tweet 4 — The solution:**
```
So I built reposcan — a local-first CLI that:

✅ Scans every file against known malware signatures (SHA-256 + filename patterns)
✅ Flags IP/leak-risk indicators (optional)
✅ Runs 100% locally — zero uploads, zero telemetry
✅ Zero Python dependencies (stdlib only)
✅ Ships with a git pre-commit hook
```

**Tweet 5 — Demo:**
```
Install + scan in 30 seconds:

$ pip install -e .
$ reposcan scan ./suspicious-repo

🚨 CRITICAL: [MAL-001] Vidar Dropper — ClaudeCode Lure
   File: releases/ClaudeCode_x64.exe
   Matched: filename pattern + hash

[Screenshot: CLI catching a fake Claude leak archive]
```

**Tweet 6 — Git hook:**
```
Don't trust yourself to remember to scan?

$ reposcan init-hook --pre-commit

Now every commit runs through the scanner first. 🪝

Blocked commit = clear message + instructions.
Bypass for emergencies: git commit --no-verify
```

**Tweet 7 — Honest limitations:**
```
Let me be honest about v1.0:

❌ Won't catch zero-day malware
❌ No deep static analysis
❌ Signature DB is small (4 malware + 2 IP-risk)
❌ Not a replacement for endpoint protection

This is a first-pass tool. Community contributions make it better.
```

**Tweet 8 — Call to contribute:**
```
The signature database is the most important part.

If you work in threat intel, security research, or just found a sketchy repo — you can add signatures via PR.

Rules: public IOCs only, no proprietary code, include references.

Details: CONTRIBUTING.md
```

**Tweet 9 — Brand + CTA:**
```
Built under THE ABOVE MINDSET — my project to help devs stay above the noise.

If this helps you or someone you know:
⭐ Star it: github.com/KanavvGupta/reposcan
🔄 RT this thread
🗣️ Tell a dev friend

Security should be accessible, not enterprise-gated.
```

**Tweet 10 — Close:**
```
"Is this repo safe?"

It's a question every dev should be able to answer in 10 seconds.

reposcan won't give you certainty. But it gives you a fighting chance.

github.com/KanavvGupta/reposcan

— THE ABOVE MINDSET
```

---

## 4. Pinned Tweet

```
🔍 reposcan — local-first CLI that scans cloned repos for known malware and IP-leak-risk indicators. Zero deps. Zero uploads. 100% local.

Built for devs who clone first and ask questions later.

⭐ github.com/KanavvGupta/reposcan

— THE ABOVE MINDSET
```

---

## 5. GitHub Topics (for the repo settings)

```
security, malware-detection, cli, python, local-first, developer-tools,
github-security, threat-intelligence, open-source, devtools
```
