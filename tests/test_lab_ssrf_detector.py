"""Unit tests for lab/ssrf_detector.py. No network, no live lab."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
from ssrf_detector import scan_path  # noqa: E402


class TestSsrfDetector(unittest.TestCase):
    def test_flags_dynamic_fetch_and_marks_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text(
                "import requests\n"
                "\n"
                "def unsafe(url):\n"
                "    return requests.get(url)\n"
                "\n"
                "def safe(url, allowed_hosts):\n"
                "    from urllib.parse import urlparse\n"
                "    if urlparse(url).hostname not in allowed_hosts:\n"
                "        raise ValueError('host not in allowlist')\n"
                "    return requests.get(url)\n"
            )
            report = scan_path(tmp)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["function"], "unsafe")
            self.assertEqual(len(report["review_needed"]), 1)
            self.assertEqual(report["review_needed"][0]["function"], "safe")

    def test_constant_url_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text("import requests\n\ndef fixed():\n    return requests.get('https://example.invalid/health')\n")
            report = scan_path(tmp)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["review_needed"], [])


if __name__ == "__main__":
    unittest.main()
