"""
Interactive action handlers for RepoScan.

Provides the post-scan 5-option menu that lets users:
  1. View copy-ready file paths for manual deletion.
  2. Auto-delete confirmed malware (with per-file Y/N prompts).
  3. Quarantine suspicious files into a timestamped folder.
  4. Export findings as .txt / .json reports.
  5. Ignore and exit (with a strong warning).

Safety rules:
  • No file is ever deleted or moved without explicit user confirmation.
  • Destructive operations catch PermissionError and log failures.
  • Will never operate on files outside the original scan root.

This is a *first-layer* helper, NOT a replacement for antivirus or EDR.
"""

from __future__ import annotations

import json as json_mod
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from reposcan import theme

if TYPE_CHECKING:
    from reposcan.matcher import Finding
    from reposcan.scanner import ScanResult


# ── Severity tiers that trigger the interactive menu ──────────────────────

_ACTIONABLE = {"CRITICAL_MALWARE", "HIGH_RISK_LURE", "ADVISORY_IP_RISK"}


def has_actionable_findings(findings: list[Finding]) -> bool:
    """Return True if any finding warrants the interactive menu."""
    return any(f.severity in _ACTIONABLE for f in findings)


# ── 1. Manual path display ────────────────────────────────────────────────

def show_manual_paths(findings: list[Finding], scan_root: str) -> None:
    """Print copy-ready absolute paths so the user can delete files manually."""
    root = Path(scan_root).resolve()

    print(theme.section_header("File locations for manual removal"))
    print()

    for f in findings:
        if f.severity not in _ACTIONABLE:
            continue
        full_path = root / f.file_path
        badge = theme.severity_badge(f.severity)
        print(f"  {badge}  {f.signature_name}")
        print(f"    {theme.bold('Path:')}  {full_path}")
        if f.severity in ("CRITICAL_MALWARE", "CRITICAL"):
            print(f"    {theme.red('→ Delete this file if you do not trust this repository.')}")
        else:
            print(f"    {theme.amber('→ Review this file manually before taking action.')}")
        print()

    # Offer to export
    answer = theme.prompt("Save a report file too? [Y/n]")
    if answer.lower() != "n":
        _export_both(findings, scan_root)


# ── 2. Auto-delete flow ──────────────────────────────────────────────────

def auto_remove_flow(findings: list[Finding], scan_root: str) -> None:
    """Walk through each CRITICAL finding and ask for delete confirmation."""
    root = Path(scan_root).resolve()

    print(theme.section_header("Automatic Removal"))
    print(f"  {theme.dim('Only CRITICAL_MALWARE files are eligible for auto-delete.')}")
    print(f"  {theme.dim('HIGH_RISK and ADVISORY files can be quarantined instead.')}")
    print()

    deleted = 0
    kept = 0
    errors = 0

    for f in findings:
        if f.severity not in ("CRITICAL_MALWARE", "CRITICAL"):
            continue

        full_path = root / f.file_path
        if not full_path.exists():
            print(f"  {theme.dim('[skipped]')} {f.file_path} — file no longer exists")
            continue

        # Safety: refuse to delete outside scan root
        try:
            full_path.resolve().relative_to(root)
        except ValueError:
            print(f"  {theme.warning('[skipped]')} {f.file_path} — outside scan root")
            continue

        # Show RED warning block
        print(f"  {theme.severity_badge(f.severity)}  {f.signature_name}")
        print(f"    File:    {full_path}")
        print(f"    SHA-256: {f.file_sha256}")
        print(f"    Size:    {f.file_size:,} bytes")
        print(f"    Reason:  {', '.join(f.match_reasons)}")

        answer = theme.prompt("Delete this file automatically? [y/N]")
        if answer.lower() == "y":
            if delete_file(full_path):
                deleted += 1
                print(f"    {theme.success('✓ Deleted.')}\n")
            else:
                errors += 1
                print()
        else:
            # Double-check for CRITICAL files
            print()
            print(f"    {theme.red('WARNING: This file matches a known malware signature.')}")
            print(f"    {theme.red('Keeping it is risky.')}")
            answer2 = theme.prompt("Are you absolutely sure you want to keep it? [y/N]")
            if answer2.lower() == "y":
                kept += 1
                print(f"    {theme.dim('Kept by user choice.')}\n")
            else:
                if delete_file(full_path):
                    deleted += 1
                    print(f"    {theme.success('✓ Deleted.')}\n")
                else:
                    errors += 1
                    print()

    # Offer quarantine for non-CRITICAL findings
    non_critical = [f for f in findings if f.severity in ("HIGH_RISK_LURE", "ADVISORY_IP_RISK")]
    if non_critical:
        print(f"  {theme.info(f'{len(non_critical)} non-critical finding(s) remain.')}")
        answer = theme.prompt("Move them to quarantine? [Y/n]")
        if answer.lower() != "n":
            quarantine_files(findings, scan_root, only_non_critical=True)

    print(theme.thin_separator())
    print(f"  Deleted: {deleted}  |  Kept: {kept}  |  Errors: {errors}")
    print()


# ── 3. Quarantine ─────────────────────────────────────────────────────────

def quarantine_files(
    findings: list[Finding],
    scan_root: str,
    *,
    only_non_critical: bool = False,
) -> None:
    """Move actionable files to a timestamped quarantine directory."""
    root = Path(scan_root).resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    q_dir = root / "reposcan_quarantine" / stamp

    print(theme.section_header("Quarantine"))
    print(f"  Target: {theme.teal(str(q_dir))}")
    print()

    moved = 0
    errors = 0

    for f in findings:
        if f.severity not in _ACTIONABLE:
            continue
        if only_non_critical and f.severity in ("CRITICAL_MALWARE", "CRITICAL"):
            continue

        full_path = root / f.file_path
        if not full_path.exists():
            continue

        # Safety check
        try:
            full_path.resolve().relative_to(root)
        except ValueError:
            print(f"  {theme.warning('[skipped]')} {f.file_path} — outside scan root")
            continue

        dest = q_dir / f.file_path
        if _safe_move(full_path, dest):
            moved += 1
            print(f"  {theme.success('✓')} {f.file_path}")
            print(f"    → {dest}")
        else:
            errors += 1

    print()
    print(theme.thin_separator())
    print(f"  Moved: {moved}  |  Errors: {errors}")
    if moved:
        print(f"  Files marked as: QUARANTINED")
        print(f"  To restore, copy files back from: {q_dir}")
    print()


# ── 4. Export reports ─────────────────────────────────────────────────────

def export_report(findings: list[Finding], scan_root: str,
                  fmt: str = "both") -> None:
    """Export findings as text and/or JSON files."""
    _export_both(findings, scan_root, fmt=fmt)


def _export_both(findings: list[Finding], scan_root: str,
                 fmt: str = "both") -> None:
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    root = Path(scan_root).resolve()
    base = f"reposcan-findings-{stamp}"

    if fmt in ("both", "txt"):
        txt_path = Path.cwd() / f"{base}.txt"
        _write_text_report(findings, root, txt_path)
        print(f"  {theme.success('✓')} Text report: {txt_path}")

    if fmt in ("both", "json"):
        json_path = Path.cwd() / f"{base}.json"
        _write_json_report(findings, root, json_path)
        print(f"  {theme.success('✓')} JSON report: {json_path}")

    print()


def _write_text_report(findings: list[Finding], root: Path, path: Path) -> None:
    lines = [
        f"RepoScan Findings Report — {datetime.now().isoformat()}",
        f"Scan root: {root}",
        f"Total findings: {len(findings)}",
        "",
    ]
    for f in findings:
        lines.append(f"[{f.severity}]  {f.signature_name}")
        lines.append(f"  ID:      {f.signature_id}")
        lines.append(f"  File:    {root / f.file_path}")
        lines.append(f"  SHA-256: {f.file_sha256}")
        lines.append(f"  Size:    {f.file_size:,} bytes")
        lines.append(f"  Matched: {', '.join(f.match_reasons)}")
        if f.description:
            lines.append(f"  Info:    {f.description}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_json_report(findings: list[Finding], root: Path, path: Path) -> None:
    payload = {
        "generated": datetime.now().isoformat(),
        "scan_root": str(root),
        "findings": [
            {
                "severity": f.severity,
                "signature_id": f.signature_id,
                "signature_name": f.signature_name,
                "file_path": str(root / f.file_path),
                "file_sha256": f.file_sha256,
                "file_size": f.file_size,
                "match_reasons": f.match_reasons,
                "description": f.description,
                "category": f.category,
            }
            for f in findings
        ],
    }
    path.write_text(json_mod.dumps(payload, indent=2), encoding="utf-8")


# ── Safe file operations ─────────────────────────────────────────────────

def delete_file(path: Path) -> bool:
    """Delete a file, catching errors.  Returns True on success.

    This is the public name referenced by the spec.
    Called ``actions.delete_file(path)`` from the CLI.
    """
    return _safe_delete(path)


def _safe_delete(path: Path) -> bool:
    """Delete a file, catching errors.  Returns True on success."""
    try:
        path.unlink()
        return True
    except PermissionError:
        print(f"    {theme.error('✗ Permission denied:')} {path}")
        return False
    except OSError as exc:
        print(f"    {theme.error(f'✗ Error: {exc}')}")
        return False


def _safe_move(src: Path, dst: Path) -> bool:
    """Move a file to the quarantine, creating parent dirs as needed."""
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return True
    except PermissionError:
        print(f"  {theme.error('✗ Permission denied:')} {src}")
        return False
    except OSError as exc:
        print(f"  {theme.error(f'✗ Error: {exc}')}")
        return False


# ── Interactive menu ──────────────────────────────────────────────────────

def run_action_menu(all_findings: list[Finding], scan_root: str) -> None:
    """
    Display the post-scan 5-option action menu and dispatch the chosen action.

    Only shown when there are actionable (non-INFO) findings.
    """
    if not has_actionable_findings(all_findings):
        return

    # Filter to actionable only for display count
    actionable = [f for f in all_findings if f.severity in _ACTIONABLE]
    critical   = [f for f in actionable if f.severity in ("CRITICAL_MALWARE", "CRITICAL")]

    print(theme.section_header("What do you want to do next?"))
    print()
    print(f"  {theme.bold('[1]')}  Show locations so I can clean things manually")
    print(f"  {theme.bold('[2]')}  Let RepoScan remove dangerous files for me "
          f"{theme.dim('(recommended for confirmed malware)')}")
    print(f"  {theme.bold('[3]')}  Move suspicious files into a quarantine folder")
    print(f"  {theme.bold('[4]')}  Export a report and exit")
    print(f"  {theme.bold('[5]')}  Ignore and exit {theme.red('(not recommended)')}")
    print()

    while True:
        choice = theme.prompt("Choose an option [1-5]:")
        if choice in ("1", "2", "3", "4", "5"):
            break
        if not choice:
            # Ctrl+C or EOF
            print(f"\n  {theme.dim('Exiting.')}")
            return
        print(f"  {theme.dim('Please enter 1, 2, 3, 4, or 5.')}")

    if choice == "1":
        show_manual_paths(all_findings, scan_root)
    elif choice == "2":
        if not critical:
            print(f"\n  {theme.info('No CRITICAL malware files to delete.')}")
            print(f"  {theme.dim('Use option [3] to quarantine HIGH/ADVISORY files.')}\n")
        else:
            auto_remove_flow(all_findings, scan_root)
    elif choice == "3":
        quarantine_files(all_findings, scan_root)
    elif choice == "4":
        export_report(all_findings, scan_root)
    elif choice == "5":
        print()
        print(f"  {theme.red('⚠ You chose to ignore these findings.')}")
        print(f"  {theme.red('  This folder may still contain dangerous files.')}")
        print(f"  {theme.amber('  Consider cleaning it later.')}")
        print()
