"""Tests for the reposcan actions module."""

import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from reposcan.actions import (
    has_actionable_findings,
    _safe_delete,
    _safe_move,
    run_action_menu,
)
from reposcan.matcher import Finding


def _finding(severity: str = "CRITICAL_MALWARE", **kw) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    defaults = dict(
        file_path="test.exe",
        file_size=1000,
        file_sha256="abc123",
        signature_id="MAL-T",
        signature_name="Test",
        severity=severity,
        category="malware",
        match_reasons=["test"],
        description="",
    )
    defaults.update(kw)
    return Finding(**defaults)


class TestHasActionableFindings(unittest.TestCase):

    def test_critical_is_actionable(self):
        self.assertTrue(has_actionable_findings([_finding("CRITICAL_MALWARE")]))

    def test_high_risk_is_actionable(self):
        self.assertTrue(has_actionable_findings([_finding("HIGH_RISK_LURE")]))

    def test_advisory_is_actionable(self):
        self.assertTrue(has_actionable_findings([_finding("ADVISORY_IP_RISK")]))

    def test_info_not_actionable(self):
        self.assertFalse(has_actionable_findings([_finding("INFO")]))

    def test_empty_not_actionable(self):
        self.assertFalse(has_actionable_findings([]))


class TestSafeDelete(unittest.TestCase):

    def test_deletes_existing_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        self.assertTrue(_safe_delete(Path(path)))
        self.assertFalse(os.path.exists(path))

    def test_nonexistent_file_fails_gracefully(self):
        # Should return False, not raise
        result = _safe_delete(Path("/no/such/file.bin"))
        self.assertFalse(result)


class TestSafeMove(unittest.TestCase):

    def test_moves_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source.exe")
            with open(src, "wb") as f:
                f.write(b"data")

            dst = os.path.join(tmp, "quarantine", "source.exe")
            self.assertTrue(_safe_move(Path(src), Path(dst)))
            self.assertFalse(os.path.exists(src))
            self.assertTrue(os.path.exists(dst))

    def test_move_nonexistent_fails_gracefully(self):
        result = _safe_move(Path("/no/such/file"), Path("/tmp/dest"))
        self.assertFalse(result)


class TestActionMenu(unittest.TestCase):
    """Test the interactive action menu dispatching."""

    def test_option_5_ignore_and_exit(self):
        """Option 5 should print a warning and return without deleting."""
        findings = [_finding("CRITICAL_MALWARE")]

        with patch("reposcan.theme.prompt", return_value="5"):
            with patch("reposcan.theme.set_no_color"):
                # Should not raise
                run_action_menu(findings, ".")

    def test_option_4_export(self):
        """Option 4 should attempt to export reports."""
        findings = [_finding("CRITICAL_MALWARE")]

        with patch("reposcan.theme.prompt", return_value="4"):
            with patch("reposcan.actions._export_both") as mock_export:
                run_action_menu(findings, ".")
                mock_export.assert_called_once()

    def test_no_actionable_findings_returns_early(self):
        """If no actionable findings, menu should not display."""
        findings = [_finding("INFO")]

        with patch("reposcan.theme.prompt") as mock_prompt:
            run_action_menu(findings, ".")
            mock_prompt.assert_not_called()

    def test_invalid_input_loops(self):
        """Invalid input should loop until valid."""
        findings = [_finding("CRITICAL_MALWARE")]

        # Simulate: first "x" (invalid), then "5" (valid)
        with patch("reposcan.theme.prompt", side_effect=["x", "5"]):
            run_action_menu(findings, ".")


if __name__ == "__main__":
    unittest.main()
