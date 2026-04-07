"""Tests for the reposcan matcher module."""

import unittest

from reposcan.matcher import match_malware, match_ip_leak_risk, match_heuristics
from reposcan.signatures import MalwareSignature, IPLeakRiskIndicator


def _mal(**kw) -> MalwareSignature:
    """Helper to create a MalwareSignature with sensible defaults."""
    defaults = dict(
        id="MAL-T", name="Test", description="", severity="CRITICAL",
        sha256_hashes=[], filename_patterns=[], extensions=[],
        min_size_bytes=None, max_size_bytes=None, references=[], tags=[],
    )
    defaults.update(kw)
    return MalwareSignature(**defaults)


def _ipr(**kw) -> IPLeakRiskIndicator:
    """Helper to create an IPLeakRiskIndicator with sensible defaults."""
    defaults = dict(
        id="IPR-T", name="Test", description="", severity="ADVISORY",
        confidence="LOW", filename_patterns=[], path_patterns=[],
        min_size_bytes=None, content_fingerprints=[], legal_note="",
        references=[], tags=[],
    )
    defaults.update(kw)
    return IPLeakRiskIndicator(**defaults)


class TestMatchMalware(unittest.TestCase):
    """Malware matching tests."""

    def test_exact_hash_match(self):
        sig = _mal(sha256_hashes=["deadbeef" * 8])
        hits = match_malware("f.bin", "f.bin", "deadbeef" * 8, 100, [sig])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].category, "malware")
        self.assertIn("SHA-256", hits[0].match_reasons[0])

    def test_hash_maps_to_critical_malware(self):
        sig = _mal(sha256_hashes=["deadbeef" * 8], severity="CRITICAL")
        hits = match_malware("f.bin", "f.bin", "deadbeef" * 8, 100, [sig])
        self.assertEqual(hits[0].severity, "CRITICAL_MALWARE")

    def test_high_maps_to_high_risk_lure(self):
        sig = _mal(filename_patterns=["evil.exe"], severity="HIGH")
        hits = match_malware("evil.exe", "evil.exe", "abc", 100, [sig])
        self.assertEqual(hits[0].severity, "HIGH_RISK_LURE")

    def test_hash_mismatch(self):
        sig = _mal(sha256_hashes=["deadbeef" * 8])
        hits = match_malware("f.bin", "f.bin", "cafebabe" * 8, 100, [sig])
        self.assertEqual(len(hits), 0)

    def test_filename_glob(self):
        sig = _mal(filename_patterns=["ClaudeCode_*.exe"], extensions=[".exe"])
        hits = match_malware(
            "x/ClaudeCode_x64.exe", "ClaudeCode_x64.exe", "abc", 5000, [sig],
        )
        self.assertEqual(len(hits), 1)

    def test_filename_case_insensitive(self):
        sig = _mal(filename_patterns=["claudecode_*.exe"])
        hits = match_malware(
            "ClaudeCode_X64.EXE", "ClaudeCode_X64.EXE", "abc", 5000, [sig],
        )
        self.assertEqual(len(hits), 1)

    def test_clean_file_no_match(self):
        sig = _mal(
            sha256_hashes=["deadbeef" * 8],
            filename_patterns=["evil.exe"],
        )
        hits = match_malware("readme.md", "readme.md", "aaa", 42, [sig])
        self.assertEqual(len(hits), 0)

    def test_size_added_as_context(self):
        sig = _mal(
            filename_patterns=["dropper.exe"],
            min_size_bytes=1000,
            max_size_bytes=9999999,
        )
        hits = match_malware("dropper.exe", "dropper.exe", "abc", 50000, [sig])
        self.assertEqual(len(hits), 1)
        reasons = " ".join(hits[0].match_reasons)
        self.assertIn("size", reasons.lower())

    def test_multiple_signatures(self):
        s1 = _mal(id="S1", filename_patterns=["a.exe"])
        s2 = _mal(id="S2", filename_patterns=["a.exe"])
        hits = match_malware("a.exe", "a.exe", "x", 10, [s1, s2])
        self.assertEqual(len(hits), 2)
        self.assertEqual({h.signature_id for h in hits}, {"S1", "S2"})

    def test_mtime_passed_through(self):
        sig = _mal(sha256_hashes=["deadbeef" * 8])
        hits = match_malware("f.bin", "f.bin", "deadbeef" * 8, 100, [sig],
                             mtime=1700000000.0)
        self.assertEqual(hits[0].mtime, 1700000000.0)


class TestMatchIPLeakRisk(unittest.TestCase):
    """IP/leak-risk matching tests."""

    def test_filename_pattern(self):
        ind = _ipr(filename_patterns=["INTERNAL_ONLY*"])
        hits = match_ip_leak_risk(
            "INTERNAL_ONLY.md", "INTERNAL_ONLY.md", "abc", 100, [ind],
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].category, "ip_leak_risk")

    def test_severity_maps_to_advisory_ip_risk(self):
        ind = _ipr(filename_patterns=["INTERNAL_ONLY*"], severity="ADVISORY")
        hits = match_ip_leak_risk(
            "INTERNAL_ONLY.md", "INTERNAL_ONLY.md", "abc", 100, [ind],
        )
        self.assertEqual(hits[0].severity, "ADVISORY_IP_RISK")

    def test_path_pattern(self):
        ind = _ipr(path_patterns=["**/claude-code/**/*.js.map"])
        hits = match_ip_leak_risk(
            "packages/claude-code/dist/bundle.js.map",
            "bundle.js.map", "abc", 100, [ind],
        )
        self.assertEqual(len(hits), 1)

    def test_size_threshold_blocks(self):
        ind = _ipr(
            filename_patterns=["*.js.map"],
            min_size_bytes=5_000_000,
        )
        # File is too small → no match
        hits = match_ip_leak_risk("x.js.map", "x.js.map", "a", 1000, [ind])
        self.assertEqual(len(hits), 0)

    def test_size_threshold_passes(self):
        ind = _ipr(
            filename_patterns=["*.js.map"],
            min_size_bytes=5_000_000,
        )
        hits = match_ip_leak_risk(
            "x.js.map", "x.js.map", "a", 10_000_000, [ind],
        )
        self.assertEqual(len(hits), 1)

    def test_no_pattern_no_match(self):
        ind = _ipr()  # no patterns at all
        hits = match_ip_leak_risk("f.txt", "f.txt", "a", 100, [ind])
        self.assertEqual(len(hits), 0)

    def test_confidence_and_legal_note(self):
        ind = _ipr(
            filename_patterns=["*.map"],
            confidence="HIGH",
            legal_note="Check with legal.",
        )
        hits = match_ip_leak_risk("a.map", "a.map", "x", 10, [ind])
        self.assertEqual(hits[0].confidence, "HIGH")
        self.assertEqual(hits[0].legal_note, "Check with legal.")


class TestMatchHeuristics(unittest.TestCase):
    """Heuristic matching tests."""

    def test_lure_keyword_exe(self):
        hits = match_heuristics(
            "releases/claude-code-leaked.exe",
            "claude-code-leaked.exe", "abc", 500000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-001" for h in hits))

    def test_premium_keyword(self):
        hits = match_heuristics(
            "premium-tool.zip", "premium-tool.zip", "abc", 5000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-001" for h in hits))

    def test_cracked_keyword(self):
        hits = match_heuristics(
            "cracked-app.rar", "cracked-app.rar", "abc", 5000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-001" for h in hits))

    def test_clean_name_no_heuristic(self):
        hits = match_heuristics(
            "src/utils.py", "utils.py", "abc", 500,
        )
        self.assertEqual(len(hits), 0)

    def test_exe_in_releases_dir(self):
        hits = match_heuristics(
            "releases/tool.exe", "tool.exe", "abc", 5000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-002" for h in hits))

    def test_oversized_jsmap(self):
        hits = match_heuristics(
            "dist/bundle.js.map", "bundle.js.map", "abc", 10_000_000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-003" for h in hits))

    def test_small_jsmap_ignored(self):
        hits = match_heuristics(
            "dist/bundle.js.map", "bundle.js.map", "abc", 1000,
        )
        self.assertFalse(any(h.signature_id == "HEUR-003" for h in hits))

    def test_heur_004_large_js_in_AI_lure_path(self):
        """HEUR-004: large JS in path with both AI vendor + lure keywords."""
        hits = match_heuristics(
            "claude-code-leaked/bundle.js", "bundle.js", "abc", 5_000_000,
        )
        self.assertTrue(any(h.signature_id == "HEUR-004" for h in hits))

    def test_heur_004_no_lure_keyword_no_match(self):
        """HEUR-004 should NOT fire without lure keywords in path."""
        hits = match_heuristics(
            "claude-code/bundle.js", "bundle.js", "abc", 5_000_000,
        )
        self.assertFalse(any(h.signature_id == "HEUR-004" for h in hits))


if __name__ == "__main__":
    unittest.main()
