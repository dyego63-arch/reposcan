"""Tests for the reposcan scanner module."""

import hashlib
import json
import os
import tempfile
import unittest

from reposcan.scanner import hash_file, scan, ScanOptions, ScanError, _is_hidden


class TestHashFile(unittest.TestCase):
    """Tests for SHA-256 file hashing."""

    def test_known_content(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            path = f.name
        try:
            self.assertEqual(
                hash_file(path),
                hashlib.sha256(b"hello world").hexdigest(),
            )
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            self.assertEqual(
                hash_file(path),
                hashlib.sha256(b"").hexdigest(),
            )
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        self.assertEqual(hash_file("/no/such/file.bin"), "")


class TestIsHidden(unittest.TestCase):
    """Tests for hidden-file detection."""

    def test_dotfile_is_hidden(self):
        self.assertTrue(_is_hidden("/some/path/.secret", ".secret"))

    def test_normal_file_not_hidden(self):
        self.assertFalse(_is_hidden("/some/path/readme.md", "readme.md"))


class TestScan(unittest.TestCase):
    """Tests for the main scan() function."""

    def test_nonexistent_path_raises(self):
        with self.assertRaises(ScanError):
            scan("/no/such/path", ScanOptions())

    def test_file_instead_of_dir_raises(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with self.assertRaises(ScanError):
                scan(path, ScanOptions())
        finally:
            os.unlink(path)

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)

            result = scan(target, ScanOptions(signatures_dir=sig_dir))
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(len(result.malware_findings), 0)
            self.assertEqual(len(result.ip_leak_findings), 0)

    def test_clean_file_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "safe.txt"), "w") as f:
                f.write("totally safe content")

            result = scan(target, ScanOptions(signatures_dir=sig_dir))
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(len(result.malware_findings), 0)

    def test_malicious_filename_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_test_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            # Create a file matching the malware filename pattern
            with open(os.path.join(target, "ClaudeCode_x64.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            result = scan(target, ScanOptions(signatures_dir=sig_dir,
                                              no_heuristics=True))
            self.assertGreater(len(result.malware_findings), 0)
            self.assertEqual(result.malware_findings[0].signature_id, "MAL-TEST")

    def test_hash_match_detected(self):
        content = b"this is known malware content for testing"
        known_hash = hashlib.sha256(content).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_hash_sig(sig_dir, known_hash)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "innocent.bin"), "wb") as f:
                f.write(content)

            result = scan(target, ScanOptions(signatures_dir=sig_dir,
                                              no_heuristics=True))
            self.assertEqual(len(result.malware_findings), 1)
            self.assertIn("SHA-256", result.malware_findings[0].match_reasons[0])

    def test_no_ip_checks_skips_advisory(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_ip_leak_sig(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "INTERNAL_ONLY.js"), "w") as f:
                f.write("internal stuff")

            result = scan(target, ScanOptions(
                signatures_dir=sig_dir, no_ip_checks=True,
                no_heuristics=True,
            ))
            self.assertEqual(len(result.ip_leak_findings), 0)

    def test_ip_check_finds_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_ip_leak_sig(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            # Use .js extension so it passes the candidate filter and gets hashed
            with open(os.path.join(target, "INTERNAL_ONLY.js"), "w") as f:
                f.write("internal stuff")

            result = scan(target, ScanOptions(signatures_dir=sig_dir,
                                              no_heuristics=True))
            self.assertGreater(len(result.ip_leak_findings), 0)

    def test_all_findings_property(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_test_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "ClaudeCode_x64.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            result = scan(target, ScanOptions(signatures_dir=sig_dir,
                                              no_heuristics=True))
            self.assertGreater(len(result.all_findings), 0)
            self.assertEqual(result.critical_count, len(result.malware_findings))

    def test_heuristic_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            releases_dir = os.path.join(target, "releases")
            os.makedirs(releases_dir)
            # Create a file that triggers HEUR-002
            with open(os.path.join(releases_dir, "tool.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            result = scan(target, ScanOptions(signatures_dir=sig_dir))
            heur_ids = [h.signature_id for h in result.heuristic_findings]
            self.assertIn("HEUR-002", heur_ids)

    def test_no_heuristics_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            releases_dir = os.path.join(target, "releases")
            os.makedirs(releases_dir)
            with open(os.path.join(releases_dir, "tool.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            result = scan(target, ScanOptions(
                signatures_dir=sig_dir, no_heuristics=True,
            ))
            self.assertEqual(len(result.heuristic_findings), 0)


# -- Helper functions to write test signature files --

def _write_empty_sigs(d: str) -> None:
    _write_json(d, "malware.json", {
        "$schema": "reposcan-malware-v1", "version": "test", "signatures": []
    })
    _write_json(d, "ip_leak_risk.json", {
        "$schema": "reposcan-ip-leak-risk-v1", "version": "test", "indicators": []
    })


def _write_test_sigs(d: str) -> None:
    _write_json(d, "malware.json", {
        "$schema": "reposcan-malware-v1", "version": "test",
        "signatures": [{
            "id": "MAL-TEST",
            "name": "Test ClaudeCode Pattern",
            "description": "Test pattern",
            "severity": "CRITICAL",
            "indicators": {
                "sha256": [],
                "filename_patterns": ["ClaudeCode_*.exe"],
                "extensions": [".exe"],
            },
            "references": [], "tags": [],
        }],
    })
    _write_json(d, "ip_leak_risk.json", {
        "$schema": "reposcan-ip-leak-risk-v1", "version": "test", "indicators": []
    })


def _write_hash_sig(d: str, sha: str) -> None:
    _write_json(d, "malware.json", {
        "$schema": "reposcan-malware-v1", "version": "test",
        "signatures": [{
            "id": "MAL-HASH",
            "name": "Hash-match test",
            "description": "Test hash-based detection",
            "severity": "CRITICAL",
            "indicators": {"sha256": [sha], "filename_patterns": [], "extensions": []},
            "references": [], "tags": [],
        }],
    })
    _write_json(d, "ip_leak_risk.json", {
        "$schema": "reposcan-ip-leak-risk-v1", "version": "test", "indicators": []
    })


def _write_ip_leak_sig(d: str) -> None:
    _write_json(d, "malware.json", {
        "$schema": "reposcan-malware-v1", "version": "test", "signatures": []
    })
    _write_json(d, "ip_leak_risk.json", {
        "$schema": "reposcan-ip-leak-risk-v1", "version": "test",
        "indicators": [{
            "id": "IPR-TEST",
            "name": "Test internal marker",
            "description": "Test IP/leak-risk indicator",
            "severity": "ADVISORY",
            "confidence": "LOW",
            "indicators": {
                "filename_patterns": ["INTERNAL_ONLY*"],
                "path_patterns": [],
            },
            "legal_note": "Test only.",
            "references": [], "tags": [],
        }],
    })


def _write_json(d: str, name: str, data: dict) -> None:
    with open(os.path.join(d, name), "w") as f:
        json.dump(data, f)


if __name__ == "__main__":
    unittest.main()
