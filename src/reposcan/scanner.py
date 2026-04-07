"""
Core scanning engine for RepoScan.

Walks a directory tree, hashes every candidate file with SHA-256, and
runs each file through the matcher against loaded signatures plus
built-in heuristics.

Extended features:
    • Hidden-file detection (Unix dotfiles, Windows attributes).
    • Symlink following (opt-in via --follow-symlinks) with loop guard.
    • Candidate-extension filtering for efficient scanning.
    • Streaming SHA-256 hashing (8 KiB chunks).
    • Configurable skip-directory and skip-file lists.
    • **Incremental progress callbacks** for live loading-screen UI.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
import fnmatch as fnmatch_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from reposcan.signatures import load_signatures, SignatureLoadError
from reposcan.matcher import (
    match_malware, match_ip_leak_risk, match_heuristics, Finding,
)


# ── Defaults ──────────────────────────────────────────────────────────────

# Directories to always skip (unless overridden)
DEFAULT_SKIP_DIRS: set[str] = {
    ".git", ".github", ".svn",
    ".venv", "venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
    "node_modules",
    ".eggs", "dist", "build",
    ".cache", ".npm", ".yarn",
    "reposcan_quarantine",
}

# Max file size to hash (100 MB) — avoids stalling on huge binaries
MAX_HASH_SIZE: int = 100 * 1024 * 1024

# Extensions worth scanning
CANDIDATE_EXTENSIONS: frozenset[str] = frozenset({
    # Executables / libraries
    ".exe", ".dll", ".scr", ".bin", ".so", ".dylib", ".msi",
    # Scripts
    ".bat", ".cmd", ".ps1", ".vbs", ".sh",
    # Archives
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz",
    # Web bundles
    ".js", ".wasm",
    # Source maps (can be huge in "leaked" repos)
    ".map",
})


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class ScanOptions:
    """Options controlling a scan run."""
    no_ip_checks: bool = False
    fail_on_ip_risk: bool = False
    json_output: bool = False
    signatures_dir: Optional[str] = None
    exclude_patterns: list[str] = field(default_factory=list)
    follow_symlinks: bool = False
    interactive: bool = False
    no_heuristics: bool = False


@dataclass
class ScanResult:
    """Aggregate result of a scan run."""
    target_path: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    malware_sigs_loaded: int = 0
    ip_leak_sigs_loaded: int = 0
    malware_findings: list[Finding] = field(default_factory=list)
    ip_leak_findings: list[Finding] = field(default_factory=list)
    heuristic_findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_secs: float = 0.0
    hidden_files_found: int = 0

    @property
    def all_findings(self) -> list[Finding]:
        """Combined view of every finding, sorted by severity."""
        severity_order = {
            "CRITICAL_MALWARE": 0, "CRITICAL": 0,
            "HIGH_RISK_LURE": 1, "HIGH": 1,
            "ADVISORY_IP_RISK": 2, "ADVISORY": 2,
            "WARNING": 3,
            "INFO": 4,
        }
        combined = (
            self.malware_findings
            + self.ip_leak_findings
            + self.heuristic_findings
        )
        return sorted(combined, key=lambda f: severity_order.get(f.severity, 99))

    @property
    def critical_count(self) -> int:
        return sum(
            1 for f in self.all_findings
            if f.severity in ("CRITICAL_MALWARE", "CRITICAL")
        )

    @property
    def advisory_count(self) -> int:
        return sum(
            1 for f in self.all_findings
            if f.severity not in ("CRITICAL_MALWARE", "CRITICAL", "INFO")
        )


@dataclass
class ScanProgress:
    """Snapshot of scan progress, passed to the progress callback.

    Attributes:
        current_path:     Relative path of the file just processed.
        files_processed:  Number of files processed so far.
        total_estimate:   Estimated total file count (0 = unknown yet).
        critical_count:   Running CRITICAL_MALWARE finding count.
        suspicious_count: Running HIGH_RISK_LURE finding count.
        advisory_count:   Running ADVISORY_IP_RISK finding count.
        phase:            'discovering' while walking, 'scanning' while hashing.
    """
    current_path: str = ""
    files_processed: int = 0
    total_estimate: int = 0
    critical_count: int = 0
    suspicious_count: int = 0
    advisory_count: int = 0
    phase: str = "discovering"


# Type alias for the progress callback
ProgressCallback = Callable[[ScanProgress], None]


class ScanError(Exception):
    """Raised when a scan cannot be completed."""


# ── Helpers ───────────────────────────────────────────────────────────────

def hash_file(filepath: str) -> str:
    """Compute SHA-256 of *filepath* using 8 KiB streaming reads."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _is_candidate(filename: str) -> bool:
    """Return True if the file extension is worth scanning."""
    lower = filename.lower()
    # .js.map is a compound extension
    if lower.endswith(".js.map"):
        return True
    _, ext = os.path.splitext(lower)
    return ext in CANDIDATE_EXTENSIONS


def _is_hidden(filepath: str, filename: str) -> bool:
    """Detect hidden files (cross-platform best-effort).

    Unix:    names starting with '.'
    Windows: FILE_ATTRIBUTE_HIDDEN (0x2) via os.stat st_file_attributes
             (only available on Windows; gracefully skipped elsewhere).
    """
    if filename.startswith("."):
        return True
    if sys.platform == "win32":
        try:
            attrs = os.stat(filepath).st_file_attributes  # type: ignore[attr-defined]
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
    return False


def _should_skip_dir(name: str, exclude_patterns: list[str]) -> bool:
    """Return True if a directory should be pruned from the walk."""
    if name in DEFAULT_SKIP_DIRS:
        return True
    return any(fnmatch_mod.fnmatch(name, p) for p in exclude_patterns)


def _should_skip_file(name: str, exclude_patterns: list[str]) -> bool:
    """Return True if a file should be skipped by user-supplied globs."""
    return any(fnmatch_mod.fnmatch(name, p) for p in exclude_patterns)


def _file_mtime(filepath: str) -> float | None:
    """Return file mtime, or None on error."""
    try:
        return os.path.getmtime(filepath)
    except OSError:
        return None


def _count_files_fast(target: Path, options: ScanOptions) -> int:
    """Quick pre-scan to estimate total file count for the progress bar.

    Uses the same skip-dir/skip-file logic as the main walk but avoids
    hashing or matching — just counts filesystem entries.  Typically
    completes in <50ms even for 10k-file repos.
    """
    count = 0
    try:
        for dirpath, dirnames, filenames in os.walk(
            target, followlinks=options.follow_symlinks,
        ):
            dirnames[:] = [
                d for d in dirnames
                if not _should_skip_dir(d, options.exclude_patterns)
            ]
            for fn in filenames:
                if not _should_skip_file(fn, options.exclude_patterns):
                    count += 1
    except OSError:
        pass
    return count


# ── Public API ────────────────────────────────────────────────────────────

def scan(target_path: str, options: ScanOptions) -> ScanResult:
    """Run a full scan on *target_path* and return a ScanResult.

    Backward-compatible wrapper — no progress UI.
    """
    return scan_with_progress(target_path, options, on_progress=None)


def scan_with_progress(
    target_path: str,
    options: ScanOptions,
    *,
    on_progress: ProgressCallback | None = None,
) -> ScanResult:
    """Run a full scan with optional incremental progress callbacks.

    If *on_progress* is provided it will be called after each file is
    processed, receiving a ``ScanProgress`` snapshot the caller can use to
    drive a loading-screen UI.  The callback should return quickly — it
    runs synchronously on the scan thread.
    """
    start = time.time()

    target = Path(target_path).resolve()
    if not target.exists():
        raise ScanError(f"Target path does not exist: {target_path}")
    if not target.is_dir():
        raise ScanError(f"Target path is not a directory: {target_path}")

    # Load signatures
    try:
        sig_db = load_signatures(options.signatures_dir)
    except SignatureLoadError as exc:
        raise ScanError(str(exc))

    result = ScanResult(
        target_path=str(target),
        malware_sigs_loaded=len(sig_db.malware),
        ip_leak_sigs_loaded=len(sig_db.ip_leak_risk),
    )

    # Fast pre-count for progress bar (only when we have a progress callback)
    total_estimate = 0
    if on_progress is not None:
        total_estimate = _count_files_fast(target, options)

    # Running finding counters for progress
    running_critical = 0
    running_suspicious = 0
    running_advisory = 0
    files_processed = 0

    # Symlink loop guard
    seen_real: set[str] = set()

    # Walk directory tree
    for dirpath, dirnames, filenames in os.walk(
        target, followlinks=options.follow_symlinks,
    ):
        # Check for symlink loops
        if options.follow_symlinks:
            real = os.path.realpath(dirpath)
            if real in seen_real:
                continue
            seen_real.add(real)

        # Prune excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if not _should_skip_dir(d, options.exclude_patterns)
        ]

        for filename in filenames:
            if _should_skip_file(filename, options.exclude_patterns):
                result.files_skipped += 1
                continue

            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, target)

            # Track hidden files
            if _is_hidden(filepath, filename):
                result.hidden_files_found += 1

            # File size
            try:
                file_size = os.path.getsize(filepath)
            except OSError:
                result.errors.append(f"Could not stat: {rel_path}")
                result.files_skipped += 1
                continue

            if file_size > MAX_HASH_SIZE:
                result.files_skipped += 1
                continue

            # Only hash candidate files (performance optimisation)
            if not _is_candidate(filename):
                # Still count as scanned for accurate reporting
                result.files_scanned += 1
                files_processed += 1

                # Fire progress callback
                if on_progress is not None:
                    on_progress(ScanProgress(
                        current_path=rel_path,
                        files_processed=files_processed,
                        total_estimate=total_estimate,
                        critical_count=running_critical,
                        suspicious_count=running_suspicious,
                        advisory_count=running_advisory,
                        phase="scanning",
                    ))
                continue

            # Hash
            sha256 = hash_file(filepath)
            if not sha256:
                result.errors.append(f"Could not hash: {rel_path}")
                result.files_skipped += 1
                continue

            result.files_scanned += 1
            files_processed += 1
            mtime = _file_mtime(filepath)

            # Match malware
            new_malware = match_malware(
                rel_path, filename, sha256, file_size,
                sig_db.malware, mtime=mtime,
            )
            result.malware_findings.extend(new_malware)
            for f in new_malware:
                if f.severity in ("CRITICAL_MALWARE", "CRITICAL"):
                    running_critical += 1

            # Match IP/leak-risk (if enabled)
            if not options.no_ip_checks and sig_db.ip_leak_risk:
                new_ip = match_ip_leak_risk(
                    rel_path, filename, sha256, file_size,
                    sig_db.ip_leak_risk, mtime=mtime,
                )
                result.ip_leak_findings.extend(new_ip)
                for f in new_ip:
                    if f.severity in ("ADVISORY_IP_RISK", "ADVISORY"):
                        running_advisory += 1

            # Match heuristics (unless disabled)
            if not options.no_heuristics:
                new_heur = match_heuristics(
                    rel_path, filename, sha256, file_size,
                    mtime=mtime,
                )
                result.heuristic_findings.extend(new_heur)
                for f in new_heur:
                    if f.severity in ("HIGH_RISK_LURE", "HIGH"):
                        running_suspicious += 1
                    elif f.severity in ("ADVISORY_IP_RISK", "ADVISORY"):
                        running_advisory += 1

            # Fire progress callback
            if on_progress is not None:
                on_progress(ScanProgress(
                    current_path=rel_path,
                    files_processed=files_processed,
                    total_estimate=total_estimate,
                    critical_count=running_critical,
                    suspicious_count=running_suspicious,
                    advisory_count=running_advisory,
                    phase="scanning",
                ))

    result.scan_duration_secs = round(time.time() - start, 3)
    return result
