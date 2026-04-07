"""
Matching logic for RepoScan.

Four-tier classification:
    CRITICAL_MALWARE  — SHA-256 hash match or very tight pattern match.
    HIGH_RISK_LURE    — strong heuristic combo (name + ext + size + path).
    ADVISORY_IP_RISK  — Claude-Code-like source maps, internal naming.
    INFO              — unusual but not clearly malicious.

Matching strategy:
    Signature-based:
        • Hash match alone → definitive CRITICAL_MALWARE.
        • Filename-pattern match → finding at the signature's severity.
    Heuristic-based:
        • "premium / leak / cracked" keywords + suspicious extension → HIGH_RISK_LURE.
        • Suspicious path context (releases/, dist/, bin/) → INFO.
        • Large .js/.wasm in "claude/code/premium/leak" paths → HIGH_RISK_LURE.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from reposcan.signatures import MalwareSignature, IPLeakRiskIndicator


# ── Severity mapping ──────────────────────────────────────────────────────
# Translate JSON severity values (CRITICAL, HIGH, ADVISORY, WARNING)
# into the 4-tier names used throughout the CLI / reporter / actions.

_SEVERITY_MAP_MALWARE: dict[str, str] = {
    "CRITICAL": "CRITICAL_MALWARE",
    "HIGH":     "HIGH_RISK_LURE",
}

_SEVERITY_MAP_IP: dict[str, str] = {
    "ADVISORY": "ADVISORY_IP_RISK",
    "WARNING":  "INFO",
}

def _map_severity(raw: str, category: str) -> str:
    if category == "malware":
        return _SEVERITY_MAP_MALWARE.get(raw, raw)
    if category == "ip_leak_risk":
        return _SEVERITY_MAP_IP.get(raw, raw)
    return raw


# ── Heuristic keywords ───────────────────────────────────────────────────

_LURE_KEYWORDS = re.compile(
    r"(premium|leaked?|crack(?:ed)?|keygen|patch(?:ed)?|exploit|"
    r"bypass|unlock(?:ed)?|activat|pirat|warez|free[-_ ]?pro)",
    re.IGNORECASE,
)

_CLAUDE_PATH_KEYWORDS = re.compile(
    r"(claude|anthropic|copilot|openai|gemini)",
    re.IGNORECASE,
)

_SUSPICIOUS_EXTS = frozenset({
    ".exe", ".scr", ".dll", ".bin", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js",  ".7z", ".rar", ".zip", ".tar",
    ".gz",  ".so",  ".dylib",
})

_SUSPICIOUS_PATH_SEGMENTS = frozenset({
    "releases", "dist", "build", "bin", "output", "out",
})


# ── Finding data class ───────────────────────────────────────────────────

@dataclass
class Finding:
    """A single scan finding."""
    file_path: str                        # relative path from scan root
    file_size: int
    file_sha256: str
    signature_id: str
    signature_name: str
    severity: str                         # CRITICAL_MALWARE | HIGH_RISK_LURE | …
    category: str                         # "malware" | "ip_leak_risk" | "heuristic"
    match_reasons: list[str] = field(default_factory=list)
    description: str = ""
    confidence: Optional[str] = None      # ip_leak_risk only
    legal_note: Optional[str] = None      # ip_leak_risk only
    mtime: Optional[float] = None         # last-modified timestamp


# ── Malware matching ─────────────────────────────────────────────────────

def match_malware(
    rel_path: str,
    filename: str,
    sha256: str,
    size: int,
    signatures: list[MalwareSignature],
    *,
    mtime: float | None = None,
) -> list[Finding]:
    """Check a file against all malware signatures.

    Matching strategy:
      • Hash match alone → definitive CRITICAL_MALWARE.
      • Filename-pattern match → finding (with extra context from ext/size).
      • Extension + size alone (no filename, no hash) → NOT flagged (too noisy).
    """
    findings: list[Finding] = []

    for sig in signatures:
        reasons: list[str] = []

        # --- SHA-256 hash ---
        hash_hit = sha256 in sig.sha256_hashes
        if hash_hit:
            reasons.append(f"SHA-256 hash match: {sha256}")

        # --- Filename glob ---
        fn_hit = any(
            fnmatch.fnmatch(filename.lower(), pat.lower())
            for pat in sig.filename_patterns
        )
        if fn_hit:
            reasons.append(f"Filename pattern match: {filename}")

        # --- Extension ---
        ext_hit = False
        if sig.extensions:
            ext_hit = any(
                filename.lower().endswith(ext.lower()) for ext in sig.extensions
            )
            if ext_hit:
                reasons.append(f"Suspicious extension: .{filename.rsplit('.', 1)[-1]}")

        # --- Size range ---
        size_hit = False
        if sig.min_size_bytes is not None and size >= sig.min_size_bytes:
            upper_ok = sig.max_size_bytes is None or size <= sig.max_size_bytes
            if upper_ok:
                size_hit = True
                reasons.append(f"File size in suspicious range: {size:,} bytes")

        # Decide if this is a real finding
        is_finding = hash_hit or fn_hit
        if is_finding and reasons:
            findings.append(Finding(
                file_path=rel_path,
                file_size=size,
                file_sha256=sha256,
                signature_id=sig.id,
                signature_name=sig.name,
                severity=_map_severity(sig.severity, "malware"),
                category="malware",
                match_reasons=reasons,
                description=sig.description,
                mtime=mtime,
            ))

    return findings


# ── IP / leak-risk matching ──────────────────────────────────────────────

def match_ip_leak_risk(
    rel_path: str,
    filename: str,
    sha256: str,
    size: int,
    indicators: list[IPLeakRiskIndicator],
    *,
    mtime: float | None = None,
) -> list[Finding]:
    """Check a file against all IP/leak-risk indicators.

    A finding requires at least one pattern match (filename or path).
    If a size threshold is defined, it must also be satisfied.
    """
    findings: list[Finding] = []

    for ind in indicators:
        reasons: list[str] = []

        # --- Filename glob ---
        fn_hit = any(
            fnmatch.fnmatch(filename.lower(), pat.lower())
            for pat in ind.filename_patterns
        )
        if fn_hit:
            reasons.append(f"Filename pattern match: {filename}")

        # --- Path glob (forward slashes for cross-platform consistency) ---
        normed = rel_path.replace("\\", "/").lower()
        path_hit = any(
            fnmatch.fnmatch(normed, pat.lower())
            for pat in ind.path_patterns
        )
        if path_hit:
            reasons.append(f"Path pattern match: {rel_path}")

        # --- Size threshold ---
        size_ok = True
        if ind.min_size_bytes is not None:
            if size >= ind.min_size_bytes:
                reasons.append(
                    f"File size exceeds threshold: {size:,} bytes "
                    f"(min: {ind.min_size_bytes:,})"
                )
            else:
                size_ok = False

        has_pattern = fn_hit or path_hit
        if has_pattern and size_ok and reasons:
            findings.append(Finding(
                file_path=rel_path,
                file_size=size,
                file_sha256=sha256,
                signature_id=ind.id,
                signature_name=ind.name,
                severity=_map_severity(ind.severity, "ip_leak_risk"),
                category="ip_leak_risk",
                match_reasons=reasons,
                description=ind.description,
                confidence=ind.confidence,
                legal_note=ind.legal_note,
                mtime=mtime,
            ))

    return findings


# ── Heuristic matching (no signatures needed) ────────────────────────────

def match_heuristics(
    rel_path: str,
    filename: str,
    sha256: str,
    size: int,
    *,
    mtime: float | None = None,
) -> list[Finding]:
    """Apply built-in heuristic rules that don't require an explicit signature.

    These catch "premium/leak/cracked" naming combined with suspicious
    extensions, large-binary anomalies in CI-like paths, and suspicious
    large .js/.wasm in AI-themed directories.
    """
    findings: list[Finding] = []
    fn_lower = filename.lower()
    _, ext = os.path.splitext(fn_lower)

    # ── HEUR-001: Lure-keyword + suspicious extension ──
    if ext in _SUSPICIOUS_EXTS and _LURE_KEYWORDS.search(fn_lower):
        findings.append(Finding(
            file_path=rel_path,
            file_size=size,
            file_sha256=sha256,
            signature_id="HEUR-001",
            signature_name="Lure-keyword filename with suspicious extension",
            severity="HIGH_RISK_LURE",
            category="heuristic",
            match_reasons=[
                f"Filename contains lure keyword: {filename}",
                f"Suspicious extension: {ext}",
            ],
            description=(
                "Files with 'premium', 'leaked', 'cracked' etc. in the name "
                "and an executable/archive extension are a common social-"
                "engineering vector for malware distribution."
            ),
            mtime=mtime,
        ))

    # ── HEUR-002: Suspicious path segment + executable ──
    path_parts = set(rel_path.replace("\\", "/").lower().split("/"))
    in_suspicious_dir = bool(path_parts & _SUSPICIOUS_PATH_SEGMENTS)
    if in_suspicious_dir and ext in (".exe", ".scr", ".dll", ".msi", ".bat", ".ps1"):
        findings.append(Finding(
            file_path=rel_path,
            file_size=size,
            file_sha256=sha256,
            signature_id="HEUR-002",
            signature_name="Executable in release/build path",
            severity="INFO",
            category="heuristic",
            match_reasons=[
                f"Found in suspicious directory segment: {rel_path}",
                f"Executable extension: {ext}",
            ],
            description=(
                "Executables placed in releases/, dist/, or build/ folders "
                "of cloned repos may be pre-compiled droppers."
            ),
            mtime=mtime,
        ))

    # ── HEUR-003: Oversized .js.map ──
    if fn_lower.endswith(".js.map") and size > 5_000_000:
        findings.append(Finding(
            file_path=rel_path,
            file_size=size,
            file_sha256=sha256,
            signature_id="HEUR-003",
            signature_name="Oversized JavaScript source map",
            severity="INFO",
            category="heuristic",
            match_reasons=[
                f"Very large .js.map file: {size:,} bytes",
            ],
            description=(
                "Source maps over 5 MB are unusual and may indicate "
                "mirrored proprietary source code (e.g. Claude Code leak)."
            ),
            mtime=mtime,
        ))

    # ── HEUR-004: Large .js/.wasm in Claude/AI-themed path ──
    rel_lower = rel_path.replace("\\", "/").lower()
    if (
        ext in (".js", ".wasm")
        and size > 2_000_000
        and _CLAUDE_PATH_KEYWORDS.search(rel_lower)
        and _LURE_KEYWORDS.search(rel_lower)
    ):
        findings.append(Finding(
            file_path=rel_path,
            file_size=size,
            file_sha256=sha256,
            signature_id="HEUR-004",
            signature_name="Large JS/WASM in AI-lure path",
            severity="HIGH_RISK_LURE",
            category="heuristic",
            match_reasons=[
                f"Large {ext} file ({size:,} bytes) in suspicious AI-themed path",
                f"Path contains AI vendor + lure keywords: {rel_path}",
            ],
            description=(
                "Very large JavaScript or WebAssembly files in directories "
                "named with 'claude', 'premium', 'leaked' etc. often "
                "indicate trojanised bundles in fake AI tool repos."
            ),
            mtime=mtime,
        ))

    return findings
