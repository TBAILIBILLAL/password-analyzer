import math
import unittest

from password_analyzer.analyzer import analyze
from password_analyzer.generator import (
    DIGITS,
    LOWER,
    SYMBOLS,
    UPPER,
    passphrase,
    pronounceable,
    random_password,
    suggestions,
)
from password_analyzer.wordlists import WORDS


class GeneratorTests(unittest.TestCase):
    def test_passphrase_shape_and_strength(self):
        suggestion = passphrase()
        parts = suggestion.password.split("-")
        self.assertEqual(len(parts), 7)  # six words and a number
        self.assertTrue(parts[0][0].isupper())
        self.assertTrue(all(part.lower() in WORDS for part in parts[:6]))
        self.assertTrue(parts[6].isdigit() and len(parts[6]) == 2)
        self.assertAlmostEqual(suggestion.bits, 6 * math.log2(len(WORDS)) + math.log2(100), places=1)
        self.assertGreaterEqual(suggestion.bits, 60)

    def test_pronounceable_shape(self):
        suggestion = pronounceable()
        self.assertEqual(len(suggestion.password), 19)  # 5 syllables of 3, a symbol and 3 digits
        self.assertTrue(suggestion.password[:15].isalpha())
        self.assertIn(suggestion.password[15], SYMBOLS)
        self.assertTrue(suggestion.password[16:].isdigit())
        self.assertGreaterEqual(suggestion.bits, 60)

    def test_random_password_uses_every_kind_of_character(self):
        for _ in range(30):
            password = random_password().password
            self.assertEqual(len(password), 16)
            for group in (LOWER, UPPER, DIGITS, SYMBOLS):
                self.assertTrue(any(ch in group for ch in password))
            self.assertFalse(set(password) & set("lIO01"))  # easily confused characters are never used

    def test_random_password_bits_account_for_the_required_kinds(self):
        suggestion = random_password()
        unrestricted = 16 * math.log2(len(LOWER + UPPER + DIGITS + SYMBOLS))
        self.assertLess(suggestion.bits, unrestricted)
        self.assertGreater(suggestion.bits, unrestricted - 1)

    def test_suggestions_are_different_each_time(self):
        first = {s.password for s in suggestions()}
        second = {s.password for s in suggestions()}
        self.assertEqual(len(first), 3)
        self.assertFalse(first & second)

    def test_every_suggestion_passes_the_analyzer(self):
        for _ in range(10):
            for suggestion in suggestions():
                analysis = analyze(suggestion.password)
                self.assertGreaterEqual(analysis.score, 3, suggestion.password)
                self.assertIn(suggestion.label, ("Strong", "Very strong"))


if __name__ == "__main__":
    unittest.main()
