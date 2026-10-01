"""Generating strong passwords to suggest as alternatives.

Every suggestion is made with the operating system's secure random source
(`secrets`), and its strength is calculated exactly from how it was made:
the number of equally likely results the method can produce.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from itertools import combinations

from .analyzer import LABELS, THRESHOLDS, analyze
from .wordlists import WORDS

# characters that are easy to confuse (l, I, O, 0, 1) are left out
LOWER = "abcdefghijkmnopqrstuvwxyz"
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
DIGITS = "23456789"
SYMBOLS = "!#$%&*+-=?@"
CONSONANTS = "bdfghjkmnprstvz"
VOWELS = "aeiou"


@dataclass
class Suggestion:
    kind: str
    password: str
    bits: float
    label: str
    note: str


def label_for(bits: float) -> str:
    return LABELS[sum(bits >= threshold for threshold in THRESHOLDS)]


def passphrase(words: int = 6) -> Suggestion:
    """Random everyday words joined with hyphens, then two digits: easy to remember and to type."""
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    number = secrets.randbelow(100)
    text = "-".join([chosen[0].capitalize()] + chosen[1:]) + f"-{number:02d}"
    bits = words * math.log2(len(WORDS)) + math.log2(100)
    return Suggestion("Passphrase", text, round(bits, 1), label_for(bits), "Easiest to remember")


def pronounceable(syllables: int = 5) -> Suggestion:
    """Made-up syllables that can be said aloud, with a symbol and three digits."""
    parts = [secrets.choice(CONSONANTS) + secrets.choice(VOWELS) + secrets.choice(CONSONANTS) for _ in range(syllables)]
    text = "".join(parts).capitalize() + secrets.choice(SYMBOLS) + f"{secrets.randbelow(1000):03d}"
    per_syllable = len(CONSONANTS) * len(VOWELS) * len(CONSONANTS)
    bits = syllables * math.log2(per_syllable) + math.log2(len(SYMBOLS)) + math.log2(1000)
    return Suggestion("Pronounceable", text, round(bits, 1), label_for(bits), "Shorter, can be said aloud")


def random_password(length: int = 16) -> Suggestion:
    """Random characters with at least one lowercase letter, uppercase letter, digit and symbol."""
    groups = (LOWER, UPPER, DIGITS, SYMBOLS)
    alphabet = "".join(groups)
    while True:
        text = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in group for ch in text) for group in groups):
            break
    # count the strings that contain all four kinds: all strings minus those missing some kind
    valid = 0
    for missing in range(len(groups) + 1):
        for left_out in combinations(groups, missing):
            remaining = len(alphabet) - sum(len(group) for group in left_out)
            valid += (-1) ** missing * remaining**length
    bits = math.log2(valid)
    return Suggestion("Random", text, round(bits, 1), label_for(bits), "Strongest, best kept in a password manager")


def suggestions() -> list[Suggestion]:
    """One suggestion of each kind. Each is re-made until the analyzer finds nothing to complain about."""
    result = []
    for make in (passphrase, pronounceable, random_password):
        suggestion = make()
        for _ in range(50):
            analysis = analyze(suggestion.password)
            if analysis.score >= 3 and all(check.passed for check in analysis.checks):
                break
            suggestion = make()
        result.append(suggestion)
    return result
