import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from password_analyzer import history as history_module
from password_analyzer.cli import main
from password_analyzer.history import PasswordHistory


def run(arguments, typed=""):
    """Run the command line with `typed` on standard input; return (exit code, printed text)."""
    output = io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(typed + "\n")), redirect_stdout(output):
        code = main(arguments)
    return code, output.getvalue()


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(history_module, "ITERATIONS", 1_000)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.db = str(Path(self.folder.name) / "history.db")

    def test_weak_password_report(self):
        code, text = run(["check", "--stdin", "--db", self.db], "Dragon123")
        self.assertEqual(code, 1)
        self.assertIn("Strength: Very weak", text)
        self.assertIn("[!!] Common passwords", text)
        self.assertIn("Stronger alternatives", text)
        self.assertNotIn("dragon", text.lower())  # no part of the password is ever printed

    def test_strong_password_report(self):
        code, text = run(["check", "--stdin", "--db", self.db], "kT9#mVx2$Lq8@wZp")
        self.assertEqual(code, 0)
        self.assertIn("Strength: Very strong", text)
        self.assertNotIn("Stronger alternatives", text)

    def test_json_output(self):
        code, text = run(["check", "--stdin", "--json", "--no-history", "--personal", "billal"], "billal2005")
        data = json.loads(text)
        self.assertEqual(code, 1)
        self.assertEqual(data["score"], 0)
        self.assertEqual(len(data["alternatives"]), 3)
        self.assertNotIn("text", data["patterns"][0])  # no pieces of the password in the output
        self.assertNotIn("billal", text.lower())
        self.assertIn("Personal information", [check["name"] for check in data["checks"]])

    def test_saved_password_is_refused_next_time(self):
        password = "kT9#mVx2$Lq8@wZp"
        code, text = run(["check", "--stdin", "--db", self.db, "--account", "billal", "--save"], password)
        self.assertEqual(code, 0)
        self.assertIn("Remembered", text)

        code, text = run(["check", "--stdin", "--db", self.db, "--account", "billal"], password)
        self.assertEqual(code, 1)
        self.assertIn("You have used this password before", text)

        code, text = run(["history", "--db", self.db, "--account", "billal"])
        self.assertIn("1 remembered password(s)", text)
        code, text = run(["history", "--db", self.db, "--account", "billal", "--clear"])
        self.assertIn("Removed 1", text)

    def test_byte_order_mark_from_the_shell_is_not_part_of_the_password(self):
        code, text = run(["check", "--stdin", "--no-history"], "﻿Summer2024")
        self.assertIn("Length: 10 characters", text)

    def test_generate(self):
        code, text = run(["generate", "--count", "2"])
        self.assertEqual(code, 0)
        self.assertEqual(len(text.strip().splitlines()), 6)
        self.assertIn("Passphrase", text)


class WindowTests(unittest.TestCase):
    """Builds the real window. Skipped where there is no screen (for example on a build server)."""

    def setUp(self):
        import tkinter as tk

        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"no display available: {error}")
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        patcher = mock.patch.object(history_module, "ITERATIONS", 1_000)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

        from password_analyzer.gui import App

        self.app = App(self.root, PasswordHistory(Path(self.folder.name) / "history.db"))

    def texts(self, frame):
        return [child.cget("text") for child in frame.winfo_children() if child.winfo_class() == "TLabel"]

    def test_verdict_follows_what_is_typed(self):
        self.assertEqual(self.app.verdict.cget("text"), "Type a password")
        self.app.password.set("password1")
        self.root.update()
        self.assertTrue(self.app.verdict.cget("text").startswith("Very weak"))
        self.assertIn("Common passwords", self.texts(self.app.checks))
        self.assertIn("common password", self.app.advice.cget("text"))

        self.app.password.set("kT9#mVx2$Lq8@wZp")
        self.root.update()
        self.assertTrue(self.app.verdict.cget("text").startswith("Very strong"))
        self.assertEqual(self.app.score, 4)

    def test_three_alternatives_are_offered_and_can_be_copied(self):
        entries = [child for child in self.app.alternatives.winfo_children() if child.winfo_class() == "TEntry"]
        self.assertEqual(len(entries), 3)
        self.app.copy(entries[0].get())
        self.assertEqual(self.root.clipboard_get(), entries[0].get())

    def test_remembered_password_is_flagged_as_reused(self):
        self.app.account.set("billal")
        self.app.password.set("kT9#mVx2$Lq8@wZp")
        self.app.remember()
        self.root.update()
        self.assertTrue(self.app.verdict.cget("text").startswith("Very weak"))
        self.assertIn("You have used this password before", self.texts(self.app.checks))


if __name__ == "__main__":
    unittest.main()
