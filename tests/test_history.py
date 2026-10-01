import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from password_analyzer import history as history_module
from password_analyzer.history import PasswordHistory, core_of


class HistoryTests(unittest.TestCase):
    def setUp(self):
        # the real iteration count makes each hash slow on purpose; the tests do not need that
        patcher = mock.patch.object(history_module, "ITERATIONS", 1_000)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "history.db"
        self.history = PasswordHistory(self.path)

    def test_core_ignores_case_digits_symbols_and_substitutions(self):
        self.assertEqual(core_of("Summer2023!"), "summer")
        self.assertEqual(core_of("P@ssw0rd"), "password")
        self.assertEqual(core_of("1234!"), "")

    def test_new_password_then_exact_reuse(self):
        self.assertEqual(self.history.check("billal", "Blue-Horse-42"), "new")
        self.history.add("billal", "Blue-Horse-42")
        self.assertEqual(self.history.check("billal", "Blue-Horse-42"), "exact")
        self.assertEqual(self.history.check("billal", "Totally-Other-77"), "new")

    def test_small_variation_of_an_old_password_is_similar(self):
        self.history.add("billal", "Summer2023!")
        self.assertEqual(self.history.check("billal", "Summer2024!"), "similar")
        self.assertEqual(self.history.check("billal", "summer#99"), "similar")
        self.assertEqual(self.history.check("billal", "Winter2024!"), "new")

    def test_passwords_with_few_letters_are_not_called_similar(self):
        self.history.add("billal", "ab12345!")
        self.assertEqual(self.history.check("billal", "ab99999?"), "new")

    def test_accounts_are_separate_and_names_ignore_case(self):
        self.history.add("Billal", "Blue-Horse-42")
        self.assertEqual(self.history.check("billal ", "Blue-Horse-42"), "exact")
        self.assertEqual(self.history.check("someone-else", "Blue-Horse-42"), "new")
        self.assertEqual(self.history.count("someone-else"), 0)

    def test_empty_account_name_uses_the_default_account(self):
        self.history.add("", "Blue-Horse-42")
        self.assertEqual(self.history.check("default", "Blue-Horse-42"), "exact")

    def test_only_the_newest_passwords_are_kept(self):
        with mock.patch.object(history_module, "KEEP", 3):
            for number in range(5):
                self.history.add("billal", f"Unique-Password-{number}-xk")
        self.assertEqual(self.history.count("billal"), 3)
        self.assertEqual(self.history.check("billal", "Unique-Password-4-xk"), "exact")
        self.assertEqual(len(self.history.dates("billal")), 3)

    def test_clear_forgets_the_account(self):
        self.history.add("billal", "Blue-Horse-42")
        self.assertEqual(self.history.clear("billal"), 1)
        self.assertEqual(self.history.check("billal", "Blue-Horse-42"), "new")
        self.assertEqual(self.history.clear("billal"), 0)

    def test_history_survives_reopening_the_database(self):
        self.history.add("billal", "Blue-Horse-42")
        reopened = PasswordHistory(self.path)
        self.assertEqual(reopened.check("billal", "Blue-Horse-42"), "exact")

    def test_the_password_is_not_stored_as_text(self):
        self.history.add("billal", "Blue-Horse-42")
        raw = self.path.read_bytes()
        self.assertNotIn(b"Blue-Horse-42", raw)
        self.assertNotIn(b"bluehorse", raw)
        con = sqlite3.connect(self.path)
        try:
            stored, core = con.execute("SELECT password_hash, core_hash FROM history").fetchone()
        finally:
            con.close()
        self.assertEqual((len(stored), len(core)), (32, 32))

    def test_same_password_gives_different_hashes_for_different_accounts(self):
        self.history.add("one", "Blue-Horse-42")
        self.history.add("two", "Blue-Horse-42")
        con = sqlite3.connect(self.path)
        try:
            hashes = [row[0] for row in con.execute("SELECT password_hash FROM history")]
        finally:
            con.close()
        self.assertNotEqual(hashes[0], hashes[1])

    def test_empty_password_is_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add("billal", "")
        self.assertEqual(self.history.check("billal", ""), "new")


if __name__ == "__main__":
    unittest.main()
