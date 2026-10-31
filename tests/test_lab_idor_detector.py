"""Unit tests for lab/idor_detector.py. No network, no live lab."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
from idor_detector import scan_path  # noqa: E402


class TestIdorDetector(unittest.TestCase):
    def test_flags_unchecked_lookup_and_marks_authorized(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text(
                "def unsafe(doc_id):\n"
                "    return documents.get(doc_id)\n"
                "\n"
                "def safe(doc_id, current_user):\n"
                "    doc = documents.get(doc_id)\n"
                "    if doc.owner_id != current_user.id:\n"
                "        raise PermissionError('not the owner')\n"
                "    return doc\n"
            )
            report = scan_path(tmp)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["function"], "unsafe")
            self.assertEqual(len(report["review_needed"]), 1)
            self.assertEqual(report["review_needed"][0]["function"], "safe")

    def test_constant_id_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text("def fixed():\n    return documents.get(42)\n")
            report = scan_path(tmp)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["review_needed"], [])

    def test_subscript_id_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text("def by_request(req):\n    return documents.get(req['doc_id'])\n")
            report = scan_path(tmp)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["id_arg_kind"], "Subscript")


if __name__ == "__main__":
    unittest.main()
