"""
Output formatting for RepoScan.

Produces two kinds of output:
    1. Human-readable, colorised text with a beginner-friendly summary
       before any technical detail (the default).
    2. Machine-readable JSON (``--json`` flag).

Uses ``theme.py`` for all styled output.
"""

from __future__ import annotations

import json as json_mod
from datetime import datetime

from reposcan import __version__
from reposcan.scanner import ScanResult
from reposcan.matcher import Finding
from reposcan import theme


# ── Exit-code logic ──────────────────────────────────────────────────────

def compute_exit_code(result: ScanResult, fail_on_ip_risk: bool = False) -> int:
    """Return the process exit code for a scan result.

    0 = clean (no non-INFO findings)
    1 = findings found
    2 = error (handled elsewhere)
    """
    if result.malware_findings:
        return 1
    if result.heuristic_findings:
        non_info = [f for f in result.heuristic_findings if f.severity != "INFO"]
        if non_info:
            return 1
    if fail_on_ip_risk and result.ip_leak_findings:
        return 1
    return 0


# ── Beginner-friendly summary ────────────────────────────────────────────

def format_summary(result: ScanResult) -> str:
    """Build the plain-English summary block shown before any details."""
    lines: list[str] = []

    lines.append(theme.section_header("Scan Summary"))
    lines.append("")
    lines.append(f"  Target:             {result.target_path}")
    lines.append(f"  Files scanned:      {result.files_scanned:,}")
    lines.append(f"  Files skipped:      {result.files_skipped:,}")
    if result.hidden_files_found:
        lines.append(
            f"  Hidden files found: {result.hidden_files_found:,}"
        )
    lines.append(
        f"  Signatures loaded:  "
        f"{result.malware_sigs_loaded} malware, "
        f"{result.ip_leak_sigs_loaded} ip-leak-risk"
    )
    lines.append(f"  Scan time:          {result.scan_duration_secs:.3f}s")
    lines.append("")

    crit = result.critical_count
    advs = result.advisory_count
    info_count = sum(1 for f in result.all_findings if f.severity == "INFO")

    # Counts
    lines.append(
        f"  Critical findings:  "
        f"{theme.error(str(crit)) if crit else theme.success('0')}"
    )
    lines.append(
        f"  Advisory findings:  "
        f"{theme.warning(str(advs)) if advs else theme.success('0')}"
    )
    if info_count:
        lines.append(f"  Informational:      {info_count}")

    lines.append("")
    return "\n".join(lines)


# ── Detailed findings (text) ─────────────────────────────────────────────

def format_findings(result: ScanResult) -> str:
    """Render all findings as themed text blocks."""
    all_f = result.all_findings
    if not all_f:
        return ""

    lines: list[str] = []

    # Group by severity tier
    criticals = [f for f in all_f if f.severity in ("CRITICAL_MALWARE", "CRITICAL")]
    high_risk = [f for f in all_f if f.severity in ("HIGH_RISK_LURE", "HIGH")]
    advisories = [f for f in all_f if f.severity in ("ADVISORY_IP_RISK", "ADVISORY")]
    infos = [f for f in all_f if f.severity == "INFO"]

    if criticals:
        lines.append(theme.section_header(
            f"{theme.red('🚨')} CRITICAL FINDINGS"
        ))
        lines.append("")
        for f in criticals:
            lines += _render_finding(f)

    if high_risk:
        lines.append(theme.section_header(
            f"{theme.amber('⚠')}  HIGH-RISK LURE FINDINGS"
        ))
        lines.append("")
        for f in high_risk:
            lines += _render_finding(f)

    if advisories:
        lines.append(theme.section_header(
            f"{theme.teal('ℹ')}  ADVISORY / IP RISK FINDINGS"
        ))
        lines.append("")
        for f in advisories:
            lines += _render_finding(f)

    if infos:
        lines.append(theme.section_header("INFORMATIONAL"))
        lines.append("")
        for f in infos:
            lines += _render_finding(f)

    # Errors
    if result.errors:
        lines.append("")
        lines.append(
            f"  {theme.warning('⚠')}  "
            f"{len(result.errors)} file(s) could not be processed:"
        )
        for err in result.errors[:10]:
            lines.append(f"    - {err}")
        if len(result.errors) > 10:
            lines.append(f"    ... and {len(result.errors) - 10} more")

    lines.append("")
    return "\n".join(lines)


def _render_finding(f: Finding) -> list[str]:
    """Render a single Finding as indented text lines."""
    badge = theme.severity_badge(f.severity)
    conf = f" ({f.confidence} confidence)" if f.confidence else ""

    block = [
        f"  {badge}  [{f.signature_id}] {f.signature_name}{conf}",
        f"    File:    {f.file_path}",
        f"    SHA-256: {f.file_sha256}",
        f"    Size:    {f.file_size:,} bytes",
        f"    Matched: {', '.join(f.match_reasons)}",
    ]
    if f.mtime:
        try:
            ts = datetime.fromtimestamp(f.mtime).strftime("%Y-%m-%d %H:%M:%S")
            block.append(f"    Modified: {ts}")
        except (OSError, ValueError):
            pass
    if f.description:
        block.append(f"    Info:    {f.description}")
    if f.legal_note:
        block.append(f"    Note:    {f.legal_note}")
    block.append("")
    return block


# ── Full text output (summary + findings) ────────────────────────────────

def format_text(result: ScanResult) -> str:
    """Render the complete text report: summary first, then details."""
    return format_summary(result) + format_findings(result)


# ── JSON formatter ───────────────────────────────────────────────────────

def format_json(result: ScanResult) -> str:
    """Render *result* as pretty-printed JSON (no colors)."""
    payload = {
        "version": __version__,
        "target": result.target_path,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "hidden_files_found": result.hidden_files_found,
        "signatures": {
            "malware": result.malware_sigs_loaded,
            "ip_leak_risk": result.ip_leak_sigs_loaded,
        },
        "scan_duration_secs": result.scan_duration_secs,
        "malware_findings": [_finding_dict(f) for f in result.malware_findings],
        "ip_leak_findings": [_finding_dict(f) for f in result.ip_leak_findings],
        "heuristic_findings": [_finding_dict(f) for f in result.heuristic_findings],
        "errors": result.errors,
        "exit_code": compute_exit_code(result),
    }
    return json_mod.dumps(payload, indent=2)


def _finding_dict(f: Finding) -> dict:
    """Serialise a Finding to a JSON-friendly dict."""
    d: dict = {
        "file_path": f.file_path,
        "file_size": f.file_size,
        "file_sha256": f.file_sha256,
        "signature_id": f.signature_id,
        "signature_name": f.signature_name,
        "severity": f.severity,
        "category": f.category,
        "match_reasons": f.match_reasons,
        "description": f.description,
    }
    if f.confidence:
        d["confidence"] = f.confidence
    if f.legal_note:
        d["legal_note"] = f.legal_note
    if f.mtime:
        d["mtime"] = f.mtime
    return d
