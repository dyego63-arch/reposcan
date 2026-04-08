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


def _empty_result():
    """Create an empty ScanResult for mocking."""
    from reposcan.scanner import ScanResult
    return ScanResult(
        target_path=".",
        files_scanned=0,
        files_skipped=0,
    )


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
    """Test 'reposcan' with no subcommand (non-TTY fallback)."""

    def test_no_command_exits_2_in_non_tty(self):
        """In a non-TTY context (StringIO), should exit 2 (old behaviour)."""
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new_callable=StringIO):
                main([])
        self.assertEqual(cm.exception.code, 2)

    def test_no_command_shows_banner(self):
        """Banner should be printed even in non-TTY fallback."""
        with patch("sys.stdout", new_callable=StringIO) as out:
            try:
                main([])
            except SystemExit:
                pass
        output = out.getvalue()
        self.assertIn("REPOSCAN", output.upper())

    def test_no_command_shows_quick_guide(self):
        """Quick guide section should appear in non-TTY output."""
        with patch("sys.stdout", new_callable=StringIO) as out:
            try:
                main([])
            except SystemExit:
                pass
        output = out.getvalue()
        # Quick guide should mention both main commands
        self.assertIn("reposcan start", output)
        self.assertIn("reposcan scan", output)

    def test_no_command_tty_shows_menu(self):
        """In a TTY context, the startup menu prompt should appear."""
        with patch("sys.stdout", new_callable=StringIO) as out:
            with patch("sys.stdout.isatty", return_value=True):
                # Simulate user pressing Enter immediately (default = 1)
                # but we mock the scan so it exits cleanly
                with patch("reposcan.cli.scan") as mock_scan:
                    mock_scan.return_value = _empty_result()
                    with patch("builtins.input", return_value="3"):  # choose exit
                        try:
                            main([])
                        except SystemExit:
                            pass
        output = out.getvalue()
        # Menu options must appear
        self.assertIn("[1]", output)
        self.assertIn("[2]", output)
        self.assertIn("[3]", output)
        self.assertIn("What would you like to do", output)

    def test_no_command_tty_option1_scans_cwd(self):
        """Choosing option 1 in TTY menu should scan current directory."""
        with patch("sys.stdout", new_callable=StringIO):
            with patch("sys.stdout.isatty", return_value=True):
                with patch("reposcan.cli.scan") as mock_scan:
                    mock_scan.return_value = _empty_result()
                    with patch("builtins.input", return_value="1"):
                        try:
                            main([])
                        except SystemExit:
                            pass
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertEqual(call_args[0][0], ".")

    def test_no_command_tty_option3_exits_0(self):
        """Choosing option 3 (just show commands and exit) should exit 0."""
        with patch("sys.stdout", new_callable=StringIO):
            with patch("sys.stdout.isatty", return_value=True):
                with patch("builtins.input", return_value="3"):
                    with self.assertRaises(SystemExit) as cm:
                        main([])
        self.assertEqual(cm.exception.code, 0)

    def test_no_command_tty_default_enter_scans_cwd(self):
        """Pressing Enter with no input (blank) should default to option 1."""
        with patch("sys.stdout", new_callable=StringIO):
            with patch("sys.stdout.isatty", return_value=True):
                with patch("reposcan.cli.scan") as mock_scan:
                    mock_scan.return_value = _empty_result()
                    with patch("builtins.input", return_value=""):  # blank = default 1
                        try:
                            main([])
                        except SystemExit:
                            pass
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertEqual(call_args[0][0], ".")

    def test_no_command_tty_option2_scans_given_path(self):
        """Choosing option 2 then entering a path should scan that path."""
        with patch("sys.stdout", new_callable=StringIO):
            with patch("sys.stdout.isatty", return_value=True):
                with patch("reposcan.cli.scan") as mock_scan:
                    mock_scan.return_value = _empty_result()
                    # First input = menu choice "2", second = the path
                    with patch("builtins.input", side_effect=["2", "/tmp"]):
                        try:
                            main([])
                        except SystemExit:
                            pass
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertEqual(call_args[0][0], "/tmp")


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
        with patch("reposcan.cli.scan") as mock_scan:
            mock_scan.return_value = _empty_result()
            with patch("sys.stdout", new_callable=StringIO):
                try:
                    main(["--no-color", "start"])
                except SystemExit:
                    pass
            mock_scan.assert_called_once()
            call_args = mock_scan.call_args
            self.assertEqual(call_args[0][0], ".")


class TestCLIStartBannerAndWelcome(unittest.TestCase):
    """Verify 'reposcan start' emits banner + welcome text to stdout."""

    def test_start_emits_banner_and_welcome(self):
        """start should print the REPOSCAN banner and welcome text."""
        with patch("reposcan.cli.scan") as mock_scan:
            mock_scan.return_value = _empty_result()
            with patch("sys.stdout", new_callable=StringIO) as out:
                try:
                    main(["--no-color", "start"])
                except SystemExit:
                    pass
            output = out.getvalue()
            self.assertIn("██", output)
            self.assertIn("ABOVE", output)
            self.assertIn("MINDSET", output)
            self.assertIn("Scanning", output)
            self.assertIn("this folder", output)
            self.assertIn("locally", output)
            self.assertIn("Scan Summary", output)


if __name__ == "__main__":
    unittest.main()
