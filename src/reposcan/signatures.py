"""
Signature loading and validation for RepoScan.

Loads malware signatures and IP/leak-risk indicators from JSON files.
All data structures are stdlib dataclasses — zero external dependencies.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MalwareSignature:
    """A single malware signature entry."""
    id: str
    name: str
    description: str
    severity: str                                    # CRITICAL | HIGH
    sha256_hashes: list[str] = field(default_factory=list)
    filename_patterns: list[str] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    min_size_bytes: Optional[int] = None
    max_size_bytes: Optional[int] = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class IPLeakRiskIndicator:
    """A single IP/leak-risk indicator entry."""
    id: str
    name: str
    description: str
    severity: str                                    # ADVISORY | WARNING
    confidence: str                                  # HIGH | MEDIUM | LOW
    filename_patterns: list[str] = field(default_factory=list)
    path_patterns: list[str] = field(default_factory=list)
    min_size_bytes: Optional[int] = None
    content_fingerprints: list[str] = field(default_factory=list)
    legal_note: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class SignatureDatabase:
    """Container for all loaded signatures."""
    malware: list[MalwareSignature] = field(default_factory=list)
    ip_leak_risk: list[IPLeakRiskIndicator] = field(default_factory=list)
    malware_version: str = "unknown"
    ip_leak_risk_version: str = "unknown"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SignatureLoadError(Exception):
    """Raised when signatures cannot be loaded."""


# ---------------------------------------------------------------------------
# Locating the signatures directory
# ---------------------------------------------------------------------------

def find_signatures_dir(custom_dir: Optional[str] = None) -> Optional[Path]:
    """
    Locate the signatures directory.

    Search order:
      1. --signatures-dir flag (explicit override)
      2. Bundled inside the package (works from pip-installed wheel)
      3. Relative to this source file  (works for editable / dev install)
      4. Current working directory      (fallback)
    """
    if custom_dir:
        p = Path(custom_dir)
        if p.is_dir():
            return p
        return None

    pkg_dir = Path(__file__).resolve().parent
    repo_root = pkg_dir.parent.parent          # src/reposcan → src → repo root

    candidates = [
        pkg_dir / "signatures",                # bundled inside package (wheel)
        repo_root / "signatures",              # editable / dev install
        Path.cwd() / "signatures",             # CWD fallback
    ]

    for candidate in candidates:
        if candidate.is_dir() and (candidate / "malware.json").exists():
            return candidate

    return None


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_malware_file(path: Path) -> tuple[list[MalwareSignature], str]:
    """Parse ``malware.json`` into a list of MalwareSignature objects."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise SignatureLoadError(f"Failed to load {path}: {exc}")

    version = data.get("version", "unknown")
    sigs: list[MalwareSignature] = []

    for entry in data.get("signatures", []):
        ind = entry.get("indicators", {})
        sigs.append(MalwareSignature(
            id=entry.get("id", "UNKNOWN"),
            name=entry.get("name", "Unnamed"),
            description=entry.get("description", ""),
            severity=entry.get("severity", "CRITICAL"),
            sha256_hashes=[h.lower() for h in ind.get("sha256", [])],
            filename_patterns=ind.get("filename_patterns", []),
            extensions=ind.get("extensions", []),
            min_size_bytes=ind.get("min_size_bytes"),
            max_size_bytes=ind.get("max_size_bytes"),
            references=entry.get("references", []),
            tags=entry.get("tags", []),
        ))

    return sigs, version


def _load_ip_leak_file(path: Path) -> tuple[list[IPLeakRiskIndicator], str]:
    """Parse ``ip_leak_risk.json`` into a list of IPLeakRiskIndicator objects."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise SignatureLoadError(f"Failed to load {path}: {exc}")

    version = data.get("version", "unknown")
    indicators: list[IPLeakRiskIndicator] = []

    for entry in data.get("indicators", []):
        ind = entry.get("indicators", {})
        indicators.append(IPLeakRiskIndicator(
            id=entry.get("id", "UNKNOWN"),
            name=entry.get("name", "Unnamed"),
            description=entry.get("description", ""),
            severity=entry.get("severity", "ADVISORY"),
            confidence=entry.get("confidence", "LOW"),
            filename_patterns=ind.get("filename_patterns", []),
            path_patterns=ind.get("path_patterns", []),
            min_size_bytes=ind.get("min_size_bytes"),
            content_fingerprints=ind.get("content_fingerprints", []),
            legal_note=entry.get("legal_note", ""),
            references=entry.get("references", []),
            tags=entry.get("tags", []),
        ))

    return indicators, version


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_signatures(custom_dir: Optional[str] = None) -> SignatureDatabase:
    """Load all signature databases and return a SignatureDatabase."""
    sig_dir = find_signatures_dir(custom_dir)
    if sig_dir is None:
        raise SignatureLoadError(
            "Could not find signatures directory. "
            "Use --signatures-dir to specify the path, or ensure "
            "'signatures/' exists in the current directory or repo root."
        )

    db = SignatureDatabase()

    malware_path = sig_dir / "malware.json"
    if malware_path.exists():
        db.malware, db.malware_version = _load_malware_file(malware_path)

    ip_path = sig_dir / "ip_leak_risk.json"
    if ip_path.exists():
        db.ip_leak_risk, db.ip_leak_risk_version = _load_ip_leak_file(ip_path)

    return db
