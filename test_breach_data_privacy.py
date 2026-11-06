import json
import unittest
from unittest.mock import patch

from email_osint_checker import check_dehashed


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps({
            "entries": [{
                "id": "entry-1",
                "database_name": "example breach",
                "username": "target@example.com",
                "hashed_password": "sensitive-hash-value",
                "obtained_from": "test fixture",
            }]
        }).encode("utf-8")


class BreachDataPrivacyTests(unittest.TestCase):
    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_dehashed_report_redacts_password_hashes(self, mocked_urlopen):
        result = check_dehashed(
            "target@example.com",
            api_key="test-api-key",
            username="account@example.com",
        )
        self.assertTrue(result["breached"])
        self.assertTrue(result["details"][0]["password_hash_present"])
        self.assertNotIn("hashed_password", result["details"][0])
        self.assertNotIn("sensitive-hash-value", json.dumps(result))
        mocked_urlopen.assert_called_once()

    def test_api_keys_are_not_accepted_as_command_line_flags(self):
        from pathlib import Path
        source = Path(__file__).with_name("email_osint_checker.py").read_text(encoding="utf-8")
        self.assertNotIn("--hibp-key", source)
        self.assertNotIn("--dehashed-key", source)
        self.assertNotIn("--leakcheck-key", source)
        self.assertIn("HIBP_API_KEY", source)
        self.assertIn("DEHASHED_API_KEY", source)
        self.assertIn("LEAKCHECK_API_KEY", source)


if __name__ == "__main__":
    unittest.main()
