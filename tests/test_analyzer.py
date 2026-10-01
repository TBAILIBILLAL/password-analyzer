import unittest

from password_analyzer.analyzer import (
    analyze,
    common_password,
    crack_time,
    find_keyboard_patterns,
    find_patterns,
    find_repeats,
    find_sequences,
    find_words,
    find_years,
    pool_size,
    repeated_block,
)
from password_analyzer.wordlists import COMMON_PASSWORDS, WORDS


def kinds(patterns):
    return [(p.kind, p.text) for p in patterns]


def check(analysis, name):
    return next(c for c in analysis.checks if c.name == name)


class PatternTests(unittest.TestCase):
    def test_sequences_up_and_down(self):
        self.assertEqual(kinds(find_sequences("xx1234yy")), [("sequence", "1234")])
        self.assertEqual(kinds(find_sequences("zyxw")), [("sequence", "zyxw")])
        self.assertEqual(kinds(find_sequences("AbCd")), [("sequence", "AbCd")])  # case does not hide it
        self.assertEqual(find_sequences("ab"), [])  # two characters are not a sequence
        self.assertEqual(find_sequences("a1b2"), [])

    def test_keyboard_patterns(self):
        self.assertEqual(kinds(find_keyboard_patterns("myqwerty!")), [("keyboard", "qwerty")])
        self.assertEqual(kinds(find_keyboard_patterns("1qaz2wsx")), [("keyboard", "1qaz2wsx")])
        self.assertEqual(kinds(find_keyboard_patterns("lkjh")), [("keyboard", "lkjh")])  # backwards
        self.assertEqual(find_keyboard_patterns("qwe"), [])  # too short

    def test_repeats_and_years(self):
        self.assertEqual(kinds(find_repeats("baaad0000")), [("repeat", "aaa"), ("repeat", "0000")])
        self.assertEqual(find_repeats("aabb"), [])
        self.assertEqual(kinds(find_years("born1998ok")), [("year", "1998")])
        self.assertEqual(find_years("123456"), [])  # part of a longer number
        self.assertEqual(find_years("3024"), [])

    def test_words_are_found_through_substitutions_and_capitals(self):
        self.assertEqual(kinds(find_patterns("P@ssw0rd")), [("common", "P@ssw0rd")])
        self.assertEqual(kinds(find_patterns("xxElephantxx")), [("word", "Elephant")])
        self.assertLess(find_words("elephant")[0].bits, find_words("El3phant")[0].bits)

    def test_overlapping_patterns_keep_the_longest(self):
        patterns = find_patterns("password123")
        self.assertEqual(kinds(patterns), [("common", "password"), ("sequence", "123")])

    def test_personal_details(self):
        patterns = find_patterns("Billal#77", personal="billal.tbaili@example.com")
        self.assertEqual(kinds(patterns), [("personal", "Billal")])

    def test_repeated_block(self):
        self.assertEqual(repeated_block("abcabcabc"), "abc")
        self.assertEqual(repeated_block("aaaa"), "a")
        self.assertIsNone(repeated_block("abcab"))

    def test_common_password_sees_through_decoration(self):
        self.assertEqual(common_password("password"), "password")
        self.assertEqual(common_password("P@ssw0rd!"), "password")
        self.assertEqual(common_password("123Qwerty123"), "qwerty")
        self.assertEqual(common_password("123456"), "123456")
        self.assertIsNone(common_password("vK8#qLm2"))

    def test_pool_size(self):
        self.assertEqual(pool_size("abc"), 26)
        self.assertEqual(pool_size("aB3"), 62)
        self.assertEqual(pool_size("aB3!"), 95)
        self.assertEqual(pool_size(""), 0)


class StrengthTests(unittest.TestCase):
    def test_common_passwords_are_very_weak(self):
        for password in ("password", "123456", "qwerty", "P@ssw0rd123!", "iloveyou2", "Summer2024"):
            with self.subTest(password=password):
                self.assertEqual(analyze(password).score, 0)

    def test_predictable_passwords_score_below_random_ones_of_the_same_length(self):
        self.assertLess(analyze("abcdefgh1234").bits, analyze("kT9#mVx2$Lq8").bits)
        self.assertLess(analyze("aaaaaaaaaaaa").bits, analyze("qwertyuiopas").bits + 40)
        self.assertLess(analyze("elephant1234").bits, analyze("xq7vr2mk9wpz").bits)

    def test_longer_random_passwords_are_stronger(self):
        self.assertLess(analyze("kT9#mVx2").bits, analyze("kT9#mVx2$Lq8").bits)
        self.assertEqual(analyze("kT9#mVx2$Lq8@wZp").label, "Very strong")

    def test_short_passwords_are_never_above_weak(self):
        self.assertLessEqual(analyze("x7#Kq!").score, 1)

    def test_empty_password(self):
        analysis = analyze("")
        self.assertEqual((analysis.score, analysis.bits, analysis.checks), (0, 0.0, []))

    def test_checks_explain_what_is_wrong(self):
        analysis = analyze("qwerty2020")
        self.assertFalse(check(analysis, "Length").passed)
        self.assertFalse(check(analysis, "Character variety").passed)
        self.assertFalse(check(analysis, "Common passwords").passed)
        self.assertIn("year", check(analysis, "Patterns").message)
        self.assertTrue(any("12 characters" in s for s in analysis.suggestions))

        good = analyze("kT9#mVx2$Lq8@wZp")
        self.assertTrue(all(c.passed for c in good.checks))
        self.assertEqual(good.suggestions, [])

    def test_uniqueness_check(self):
        self.assertFalse(check(analyze("abcabcabcabc"), "Uniqueness").passed)
        self.assertFalse(check(analyze("xaaaay7#Kq2M"), "Uniqueness").passed)
        self.assertFalse(check(analyze("abababbabaab"), "Uniqueness").passed)  # only two different characters
        self.assertTrue(check(analyze("kT9#mVx2$Lq8"), "Uniqueness").passed)

    def test_personal_information_check(self):
        analysis = analyze("Billal-2005-xk", personal="Billal Tbaili")
        self.assertFalse(check(analysis, "Personal information").passed)
        self.assertTrue(check(analyze("kT9#mVx2$Lq8", personal="Billal"), "Personal information").passed)
        self.assertNotIn("Personal information", [c.name for c in analyze("kT9#mVx2$Lq8").checks])

    def test_reuse_overrides_the_score(self):
        strong = "kT9#mVx2$Lq8@wZp"
        self.assertEqual(analyze(strong, reuse="exact").score, 0)
        self.assertEqual(analyze(strong, reuse="similar").score, 1)
        self.assertEqual(analyze(strong, reuse="new").score, 4)
        self.assertTrue(check(analyze(strong, reuse="new"), "Reuse").passed)

    def test_one_common_word_in_a_long_passphrase_is_not_flagged(self):
        analysis = analyze("Maple-tiger-ocean-seven-cloud-rocket-47")
        self.assertTrue(check(analysis, "Common passwords").passed)
        self.assertGreaterEqual(analysis.score, 3)

    def test_result_converts_to_plain_data(self):
        data = analyze("password1").to_dict()
        self.assertEqual(data["label"], "Very weak")
        self.assertIsInstance(data["checks"][0], dict)


class CrackTimeTests(unittest.TestCase):
    def test_wording(self):
        self.assertEqual(crack_time(10, 1_000), "less than a second")
        self.assertEqual(crack_time(21, 1_000), "17 minutes")  # 2^20 guesses at 1,000 per second
        self.assertEqual(crack_time(1, 1), "1 second")
        self.assertEqual(crack_time(200, 1e10), "more than a billion years")

    def test_more_bits_never_take_less_time(self):
        order = ["second", "minute", "hour", "day", "year", "thousand", "million", "billion"]

        def rank(text):
            return max(i for i, unit in enumerate(order) if unit in text)

        ranks = [rank(crack_time(bits, 1e10)) for bits in range(30, 120, 5)]
        self.assertEqual(ranks, sorted(ranks))


class WordListTests(unittest.TestCase):
    def test_lists_have_no_duplicates_and_are_lowercase(self):
        for words in (WORDS, COMMON_PASSWORDS):
            self.assertEqual(len(words), len(set(words)))
            self.assertTrue(all(word == word.lower() for word in words))

    def test_passphrase_list_is_large_enough(self):
        self.assertGreaterEqual(len(WORDS), 1024)  # at least 10 bits per word
        self.assertTrue(all(word.isalpha() for word in WORDS))


if __name__ == "__main__":
    unittest.main()
