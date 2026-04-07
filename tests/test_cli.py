"""Tests for the reposcan CLI module."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from io import StringIO

from reposcan.cli import main


def _write_json(d: str, name: str, data: dict) -> None:
    with open(os.path.join(d, name), "w") as f:
        json.dump(data, f)


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


class TestCLIVersion(unittest.TestCase):
    """Test 'reposcan version'."""

    def test_version_prints_branding(self):
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new_callable=StringIO) as out:
                main(["version"])
        self.assertEqual(cm.exception.code, 0)

    def test_version_output_contains_brand(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            try:
                main(["version"])
            except SystemExit:
                pass
        output = out.getvalue()
        self.assertIn("THE ABOVE MINDSET", output)
        self.assertIn("RepoScan", output)


class TestCLINoSubcommand(unittest.TestCase):
    """Test 'reposcan' with no subcommand."""

    def test_no_command_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new_callable=StringIO):
                main([])
        self.assertEqual(cm.exception.code, 2)


class TestCLIScan(unittest.TestCase):
    """Test 'reposcan scan' subcommand."""

    def test_scan_nonexistent_path_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr", new_callable=StringIO):
                with patch("sys.stdout", new_callable=StringIO):
                    main(["--no-color", "scan", "/no/such/path"])
        self.assertEqual(cm.exception.code, 2)

    def test_scan_clean_directory_exits_0(self):
        """Scanning an empty dir with no findings should exit 0."""
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "readme.txt"), "w") as f:
                f.write("safe content")

            with self.assertRaises(SystemExit) as cm:
                with patch("sys.stdout", new_callable=StringIO):
                    main(["--no-color", "scan", target,
                          "--signatures-dir", sig_dir])
            self.assertEqual(cm.exception.code, 0)

    def test_scan_json_output(self):
        """--json should produce valid JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)

            with patch("sys.stdout", new_callable=StringIO) as out:
                try:
                    main(["--no-color", "scan", target, "--json",
                          "--signatures-dir", sig_dir])
                except SystemExit:
                    pass

            output = out.getvalue()
            data = json.loads(output)
            self.assertIn("version", data)
            self.assertIn("malware_findings", data)
            self.assertEqual(data["exit_code"], 0)

    def test_scan_with_detection(self):
        """Scanning a dir with a malicious filename should exit 1."""
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_test_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "ClaudeCode_x64.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            with self.assertRaises(SystemExit) as cm:
                with patch("sys.stdout", new_callable=StringIO):
                    main(["--no-color", "scan", target,
                          "--signatures-dir", sig_dir,
                          "--no-heuristics"])
            self.assertEqual(cm.exception.code, 1)


class TestCLIStartEquivalence(unittest.TestCase):
    """Verify 'reposcan start' is equivalent to 'reposcan scan . --auto'."""

    def test_start_scans_cwd(self):
        """start should scan '.' (CWD)."""
        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            # We can't easily change CWD in tests, but we verify it
            # calls scan with "." by patching
            with patch("reposcan.cli.scan") as mock_scan:
                mock_scan.return_value = _empty_result()
                with patch("sys.stdout", new_callable=StringIO):
                    try:
                        main(["--no-color", "start"])
                    except SystemExit:
                        pass
                # Verify scan was called with "."
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertEqual(call_args[0][0], ".")


def _empty_result():
    """Create an empty ScanResult for mocking."""
    from reposcan.scanner import ScanResult
    return ScanResult(
        target_path=".",
        files_scanned=0,
        files_skipped=0,
    )


if __name__ == "__main__":
    unittest.main()
