"""Tests for the reposcan theme module."""

import os
import unittest

from reposcan import theme


class TestColorsEnabled(unittest.TestCase):
    """Test color-enabled detection logic."""

    def test_no_color_flag_disables(self):
        theme.set_no_color(True)
        self.assertFalse(theme.colors_enabled())
        theme.set_no_color(False)

    def test_no_color_env_disables(self):
        old = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertFalse(theme.colors_enabled())
        finally:
            if old is None:
                del os.environ["NO_COLOR"]
            else:
                os.environ["NO_COLOR"] = old


class TestColorFunctions(unittest.TestCase):
    """Test that color wrappers return strings (content preserved)."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_green_no_color(self):
        self.assertEqual(theme.green("ok"), "ok")

    def test_red_no_color(self):
        self.assertEqual(theme.red("bad"), "bad")

    def test_teal_no_color(self):
        self.assertEqual(theme.teal("info"), "info")

    def test_cyan_alias(self):
        self.assertEqual(theme.cyan("info"), "info")

    def test_amber_no_color(self):
        self.assertEqual(theme.amber("warn"), "warn")

    def test_yellow_alias(self):
        self.assertEqual(theme.yellow("warn"), "warn")

    def test_bold_no_color(self):
        self.assertEqual(theme.bold("title"), "title")

    def test_dim_no_color(self):
        self.assertEqual(theme.dim("faded"), "faded")

    def test_white_no_color(self):
        self.assertEqual(theme.white("text"), "text")


class TestSemanticHelpers(unittest.TestCase):
    """Test semantic color helpers."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_success(self):
        self.assertEqual(theme.success("ok"), "ok")

    def test_info(self):
        self.assertEqual(theme.info("note"), "note")

    def test_warning(self):
        self.assertEqual(theme.warning("warn"), "warn")

    def test_error(self):
        self.assertEqual(theme.error("bad"), "bad")


class TestSeverityBadge(unittest.TestCase):
    """Test severity badge rendering."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_critical_malware(self):
        badge = theme.severity_badge("CRITICAL_MALWARE")
        self.assertIn("CRITICAL", badge)

    def test_high_risk_lure(self):
        badge = theme.severity_badge("HIGH_RISK_LURE")
        self.assertIn("HIGH RISK", badge)

    def test_advisory_ip_risk(self):
        badge = theme.severity_badge("ADVISORY_IP_RISK")
        self.assertIn("ADVISORY", badge)

    def test_info(self):
        badge = theme.severity_badge("INFO")
        self.assertIn("INFO", badge)

    def test_unknown_severity(self):
        badge = theme.severity_badge("MADE_UP")
        self.assertIn("UNKNOWN", badge)


class TestBanner(unittest.TestCase):
    """Test banner rendering."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_banner_contains_version(self):
        b = theme.banner("1.0.0")
        self.assertIn("1.0.0", b)

    def test_banner_contains_brand(self):
        b = theme.banner("1.0.0")
        self.assertIn("ABOVE", b)
        self.assertIn("MINDSET", b)

    def test_banner_contains_reposcan(self):
        b = theme.banner("1.0.0")
        # The block letters contain fragments of REPOSCAN
        self.assertIn("██", b)

    def test_banner_no_color_mode(self):
        b = theme.banner("1.0.0")
        # Should not contain ANSI escape codes
        self.assertNotIn("\033[", b)

    def test_banner_with_empty_version(self):
        b = theme.banner("")
        self.assertIn("ABOVE", b)


class TestSeparators(unittest.TestCase):
    """Test separator helpers."""

    def test_separator_length(self):
        self.assertEqual(len(theme.separator(40)), 40)

    def test_thin_separator_length(self):
        self.assertEqual(len(theme.thin_separator(30)), 30)


class TestSectionHeader(unittest.TestCase):
    """Test section header rendering."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_contains_title(self):
        result = theme.section_header("Test Title")
        self.assertIn("Test Title", result)


class TestQuickGuide(unittest.TestCase):
    """Test render_quick_guide() and quick_guide_plain()."""

    def setUp(self):
        theme.set_no_color(True)

    def tearDown(self):
        theme.set_no_color(False)

    def test_render_contains_three_patterns(self):
        guide = theme.render_quick_guide()
        self.assertIn("Scan this folder", guide)
        self.assertIn("Scan a specific folder", guide)
        self.assertIn("Scan an entire drive", guide)

    def test_render_contains_commands(self):
        guide = theme.render_quick_guide()
        self.assertIn("reposcan start", guide)
        self.assertIn('reposcan scan', guide)

    def test_render_contains_advanced_label(self):
        guide = theme.render_quick_guide()
        self.assertIn("advanced", guide)

    def test_render_no_ansi_in_no_color_mode(self):
        guide = theme.render_quick_guide()
        self.assertNotIn("\033[", guide)

    def test_plain_contains_three_patterns(self):
        guide = theme.quick_guide_plain()
        self.assertIn("Scan this folder", guide)
        self.assertIn("Scan a specific folder", guide)
        self.assertIn("Scan an entire drive", guide)

    def test_plain_contains_commands(self):
        guide = theme.quick_guide_plain()
        self.assertIn("reposcan start", guide)
        self.assertIn("reposcan scan", guide)

    def test_plain_no_ansi(self):
        """Plain guide should never contain ANSI codes regardless of mode."""
        theme.set_no_color(False)  # Even with colors "enabled"
        guide = theme.quick_guide_plain()
        self.assertNotIn("\033[", guide)

    def test_plain_contains_example_path(self):
        guide = theme.quick_guide_plain()
        self.assertIn("Downloads", guide)


if __name__ == "__main__":
    unittest.main()
