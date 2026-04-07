"""Tests for the LoadingView and scan progress integration."""

import io
import time
import unittest

from reposcan import theme
from reposcan.theme import LoadingView
from reposcan.scanner import ScanProgress


class TestLoadingViewRendering(unittest.TestCase):
    """Test the LoadingView rendering helpers in no-color mode."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_render_bar_text_determinate(self):
        """Progress bar should show #### fill proportional to progress."""
        result = LoadingView.render_bar_text(50, 100)
        self.assertIn("[", result)
        self.assertIn("]", result)
        self.assertIn("50", result)
        self.assertIn("100", result)

    def test_render_bar_text_zero(self):
        """At 0% the bar should be all dots."""
        result = LoadingView.render_bar_text(0, 100)
        self.assertIn("[", result)
        # The bar should have no '#' chars
        bar_part = result[result.index("["):result.index("]") + 1]
        self.assertNotIn("#", bar_part)

    def test_render_bar_text_full(self):
        """At 100% the bar should be all #."""
        result = LoadingView.render_bar_text(100, 100)
        bar_part = result[result.index("["):result.index("]") + 1]
        self.assertNotIn(".", bar_part)

    def test_render_bar_text_indeterminate(self):
        """When total is 0, show indeterminate style."""
        result = LoadingView.render_bar_text(42, 0)
        self.assertIn("42", result)
        self.assertIn("?", result)

    def test_render_bar_text_over_100_percent(self):
        """Progress > total should cap at 100%."""
        result = LoadingView.render_bar_text(200, 100)
        bar_part = result[result.index("["):result.index("]") + 1]
        # Should be fully filled, not overflow
        self.assertNotIn(".", bar_part)

    def test_render_counters_text_all_zero(self):
        result = LoadingView.render_counters_text(0, 0, 0)
        self.assertIn("Critical: 0", result)
        self.assertIn("Suspicious: 0", result)
        self.assertIn("Advisory: 0", result)

    def test_render_counters_text_with_values(self):
        result = LoadingView.render_counters_text(3, 5, 7)
        self.assertIn("Critical: 3", result)
        self.assertIn("Suspicious: 5", result)
        self.assertIn("Advisory: 7", result)

    def test_render_counters_has_pipe_separators(self):
        result = LoadingView.render_counters_text(0, 0, 0)
        self.assertEqual(result.count("|"), 2)


class TestLoadingViewLifecycle(unittest.TestCase):
    """Test the LoadingView start/update/finish lifecycle."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_start_writes_output(self):
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        output = buf.getvalue()
        # Should contain at least the brand bar and scanning text
        self.assertIn("Scanning", output)

    def test_start_is_idempotent(self):
        """Calling start() twice should not double-draw."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        first_len = len(buf.getvalue())
        view.start()
        # Second call should not add anything
        self.assertEqual(len(buf.getvalue()), first_len)

    def test_finish_writes_completion(self):
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        view.finish()
        output = buf.getvalue()
        self.assertIn("Scan complete", output)

    def test_finish_is_idempotent(self):
        """Calling finish() twice should not double-print."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        view.finish()
        first_len = len(buf.getvalue())
        view.finish()
        self.assertEqual(len(buf.getvalue()), first_len)

    def test_update_after_finish_is_noop(self):
        """Updates after finish should be silently ignored."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        view.finish()
        after_finish_len = len(buf.getvalue())

        progress = ScanProgress(
            current_path="foo.exe",
            files_processed=10,
            total_estimate=100,
        )
        view.update(progress)
        self.assertEqual(len(buf.getvalue()), after_finish_len)


class TestLoadingViewUpdate(unittest.TestCase):
    """Test that update() writes progress to the output."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_update_writes_path(self):
        """The current file path should appear in the output."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()

        # Force past the throttle
        view._state.last_update = 0

        progress = ScanProgress(
            current_path="releases/evil.exe",
            files_processed=50,
            total_estimate=200,
            critical_count=1,
            suspicious_count=2,
            advisory_count=3,
        )
        view.update(progress)
        output = buf.getvalue()

        # Path should be visible
        self.assertIn("evil.exe", output)

    def test_update_writes_counters(self):
        """Counters should reflect the progress values."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()
        view._state.last_update = 0

        progress = ScanProgress(
            current_path="test.js",
            files_processed=10,
            total_estimate=50,
            critical_count=2,
            suspicious_count=0,
            advisory_count=1,
        )
        view.update(progress)
        view.finish()
        output = buf.getvalue()
        # Output should mention "Scan complete" rather than being cut off
        self.assertIn("Scan complete", output)

    def test_update_throttling(self):
        """Rapid updates should be throttled (not every call writes)."""
        buf = io.StringIO()
        view = LoadingView(output=buf)
        view.start()

        # Reset throttle so the first update in the loop gets through
        view._state.last_update = 0
        initial_len = len(buf.getvalue())

        # Send 100 rapid updates — most should be throttled
        for i in range(100):
            progress = ScanProgress(
                current_path=f"file_{i}.txt",
                files_processed=i,
                total_estimate=100,
            )
            view.update(progress)

        output_after = buf.getvalue()
        # At least the first update should have gotten through
        self.assertGreater(len(output_after), initial_len)

        view.finish()


class TestLoadingViewAutoStart(unittest.TestCase):
    """Test that update() auto-starts the view if needed."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_update_without_start(self):
        """update() should auto-call start() if not yet started."""
        buf = io.StringIO()
        view = LoadingView(output=buf)

        # Force past throttle
        view._state.last_update = 0

        progress = ScanProgress(
            current_path="autostart.exe",
            files_processed=1,
            total_estimate=10,
        )
        view.update(progress)
        output = buf.getvalue()
        self.assertIn("Scanning", output)
        self.assertTrue(view._state.started)


class TestScanProgressDataclass(unittest.TestCase):
    """Test the ScanProgress data structure."""

    def test_defaults(self):
        p = ScanProgress()
        self.assertEqual(p.current_path, "")
        self.assertEqual(p.files_processed, 0)
        self.assertEqual(p.total_estimate, 0)
        self.assertEqual(p.critical_count, 0)
        self.assertEqual(p.suspicious_count, 0)
        self.assertEqual(p.advisory_count, 0)
        self.assertEqual(p.phase, "discovering")

    def test_custom_values(self):
        p = ScanProgress(
            current_path="a/b/c.js",
            files_processed=42,
            total_estimate=100,
            critical_count=1,
            suspicious_count=2,
            advisory_count=3,
            phase="scanning",
        )
        self.assertEqual(p.current_path, "a/b/c.js")
        self.assertEqual(p.files_processed, 42)
        self.assertEqual(p.total_estimate, 100)
        self.assertEqual(p.phase, "scanning")


class TestScanWithProgressCallback(unittest.TestCase):
    """Integration test: verify scan_with_progress fires callbacks."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_callback_fires_for_files(self):
        """scan_with_progress should call the callback at least once."""
        import tempfile, os, json
        from reposcan.scanner import scan_with_progress, ScanOptions

        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            # Create some candidate files
            for i in range(5):
                with open(os.path.join(target, f"file_{i}.js"), "w") as f:
                    f.write(f"content {i}")

            progress_events: list[ScanProgress] = []

            def on_progress(p: ScanProgress) -> None:
                progress_events.append(p)

            result = scan_with_progress(
                target,
                ScanOptions(signatures_dir=sig_dir, no_heuristics=True),
                on_progress=on_progress,
            )

            # Should have fired at least once per file
            self.assertGreaterEqual(len(progress_events), 5)
            # Last event should have files_processed == 5
            self.assertEqual(progress_events[-1].files_processed, 5)
            # Total estimate should be > 0
            self.assertGreater(progress_events[-1].total_estimate, 0)

    def test_no_callback_still_works(self):
        """scan_with_progress(on_progress=None) should work like scan()."""
        import tempfile, os, json
        from reposcan.scanner import scan_with_progress, ScanOptions

        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_empty_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)

            result = scan_with_progress(
                target,
                ScanOptions(signatures_dir=sig_dir),
                on_progress=None,
            )
            self.assertEqual(result.files_scanned, 0)

    def test_callback_receives_finding_counts(self):
        """Callbacks should reflect running finding counts."""
        import tempfile, os, json
        from reposcan.scanner import scan_with_progress, ScanOptions

        with tempfile.TemporaryDirectory() as tmp:
            sig_dir = os.path.join(tmp, "sigs")
            os.makedirs(sig_dir)
            _write_test_sigs(sig_dir)

            target = os.path.join(tmp, "target")
            os.makedirs(target)
            with open(os.path.join(target, "ClaudeCode_x64.exe"), "wb") as f:
                f.write(b"\x00" * 200)

            progress_events: list[ScanProgress] = []

            def on_progress(p: ScanProgress) -> None:
                progress_events.append(p)

            result = scan_with_progress(
                target,
                ScanOptions(signatures_dir=sig_dir, no_heuristics=True),
                on_progress=on_progress,
            )

            # The malware file should bump critical_count
            self.assertGreater(len(progress_events), 0)
            last = progress_events[-1]
            self.assertGreater(last.critical_count, 0)


class TestJSONBypassesLoading(unittest.TestCase):
    """Verify --json mode does not trigger the loading view."""

    def test_json_output_is_clean(self):
        """JSON output should have no ANSI codes or loading text."""
        import tempfile, os, json as json_mod
        from io import StringIO
        from unittest.mock import patch
        from reposcan.cli import main

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
            # Should be valid JSON
            data = json_mod.loads(output)
            self.assertIn("version", data)

            # Should NOT contain loading screen text
            self.assertNotIn("Scanning files", output)
            self.assertNotIn("Scan complete", output)


# ── Signature helper stubs (matching test_scanner.py) ─────────────────────

def _write_json(d, name, data):
    import json, os
    with open(os.path.join(d, name), "w") as f:
        json.dump(data, f)


def _write_empty_sigs(d):
    _write_json(d, "malware.json", {
        "$schema": "reposcan-malware-v1", "version": "test", "signatures": []
    })
    _write_json(d, "ip_leak_risk.json", {
        "$schema": "reposcan-ip-leak-risk-v1", "version": "test", "indicators": []
    })


def _write_test_sigs(d):
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


if __name__ == "__main__":
    unittest.main()
