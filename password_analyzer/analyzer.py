"""Estimating how strong a password is.

The analyzer looks at a password the way an attacker would. A password is only
as strong as the number of guesses needed to reach it, so the analyzer finds
the predictable parts (common passwords, dictionary words, sequences, keyboard
patterns, repeats, years) and counts each of them as a few guesses, not as a
string of random characters. What is left over is counted as random.

The result is an estimate in bits: each extra bit doubles the guesses needed.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .wordlists import COMMON_PASSWORDS, WORDS

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
THRESHOLDS = (25, 40, 60, 80)  # bits needed to reach scores 1, 2, 3 and 4
MIN_LENGTH = 8
GOOD_LENGTH = 12

# guesses per second an attacker can make
ONLINE_RATE = 1_000  # against a website that does not slow attackers down
OFFLINE_RATE = 10_000_000_000  # against a stolen database of quickly hashed passwords

# common letter substitutions ("p@ssw0rd"); attackers undo these automatically
LEET = str.maketrans({"@": "a", "4": "a", "8": "b", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s",
                      "7": "t", "+": "t", "9": "g"})
_COMMON_RANK = {password: rank for rank, password in enumerate(COMMON_PASSWORDS)}
_COMMON_WORDS = {password for password in COMMON_PASSWORDS if password.isalpha() and len(password) >= 4}
_EVERYDAY_WORDS = {word for word in WORDS if len(word) >= 4}
_DICTIONARY_FILE = Path(__file__).parent / "data" / "dictionary.txt"
_LARGE_DICTIONARY = set(_DICTIONARY_FILE.read_text(encoding="utf-8").split())
_DICTIONARY = _EVERYDAY_WORDS | _COMMON_WORDS | _LARGE_DICTIONARY
_LONGEST_WORD = max(len(word) for word in _DICTIONARY)
_EVERYDAY_BITS = math.log2(2_000)  # an everyday word is one of roughly 2,000 an attacker tries first
_DICTIONARY_BITS = math.log2(20_000)  # any other dictionary word is one of roughly 20,000

_KEYBOARD = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp")
_KEYBOARD += tuple(row[::-1] for row in _KEYBOARD)
_REPEAT = re.compile(r"(.)\1{2,}")
_YEAR = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")
_EDGES = re.compile(r"^[^a-z]+|[^a-z]+$")


@dataclass
class Pattern:
    """A predictable part of a password, from position start up to (not including) end."""

    start: int
    end: int
    kind: str  # common, word, sequence, keyboard, repeat, year or personal
    text: str
    bits: float


@dataclass
class Check:
    name: str
    passed: bool
    message: str


@dataclass
class Analysis:
    score: int
    label: str
    bits: float
    length: int
    checks: list[Check] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    patterns: list[Pattern] = field(default_factory=list)
    online_time: str = ""
    offline_time: str = ""

    def to_dict(self) -> dict:
        """Plain data for JSON output. Pattern texts are left out: they are pieces of the password."""
        data = asdict(self)
        for pattern in data["patterns"]:
            pattern.pop("text")
        return data


# ---------------------------------------------------------------------- patterns


def _same_kind(a: str, b: str) -> bool:
    return (a.isascii() and b.isascii()) and ((a.isalpha() and b.isalpha()) or (a.isdigit() and b.isdigit()))


def find_sequences(password: str) -> list[Pattern]:
    """Runs of three or more neighbouring letters or digits, up or down: abc, 4321."""
    lower = password.lower()
    found, i = [], 0
    while i < len(lower) - 2:
        step = ord(lower[i + 1]) - ord(lower[i])
        if step not in (1, -1) or not _same_kind(lower[i], lower[i + 1]):
            i += 1
            continue
        j = i + 1
        while j + 1 < len(lower) and ord(lower[j + 1]) - ord(lower[j]) == step and _same_kind(lower[j], lower[j + 1]):
            j += 1
        length = j - i + 1
        if length >= 3:
            # which character it starts on, how long it runs, and the direction
            found.append(Pattern(i, j + 1, "sequence", password[i : j + 1], math.log2(36) + math.log2(length) + 1))
        i = j
    return found


def find_keyboard_patterns(password: str) -> list[Pattern]:
    """Four or more keys that are next to each other on a keyboard: qwerty, asdf, 1qaz."""
    lower = password.lower()
    found, i = [], 0
    while i < len(lower) - 3:
        for length in range(min(len(lower) - i, 12), 3, -1):
            chunk = lower[i : i + length]
            if not chunk.isdigit() and any(chunk in row for row in _KEYBOARD):
                found.append(Pattern(i, i + length, "keyboard", password[i : i + length], 7 + math.log2(length)))
                i += length - 1
                break
        i += 1
    return found


def find_repeats(password: str) -> list[Pattern]:
    """The same character three or more times in a row: aaa, 0000."""
    return [
        Pattern(m.start(), m.end(), "repeat", m.group(), math.log2(pool_size(m.group(1))) + math.log2(m.end() - m.start()))
        for m in _REPEAT.finditer(password)
    ]


def find_years(password: str) -> list[Pattern]:
    """Four-digit years from 1900 to 2099."""
    return [Pattern(m.start(), m.end(), "year", m.group(), math.log2(200)) for m in _YEAR.finditer(password)]


def find_words(password: str) -> list[Pattern]:
    """Dictionary words and common passwords, also when written with substitutions like p@ssw0rd."""
    lower = password.lower()
    plain = lower.translate(LEET)
    found = []
    for i in range(len(plain) - 3):
        for length in range(min(len(plain) - i, _LONGEST_WORD), 3, -1):
            word = plain[i : i + length]
            if word not in _DICTIONARY:
                continue
            original = password[i : i + length]
            if word in _COMMON_WORDS:
                kind, bits = "common", math.log2(_COMMON_RANK[word] + 2) + 1
            elif word in _EVERYDAY_WORDS:
                kind, bits = "word", _EVERYDAY_BITS
            else:
                kind, bits = "word", _DICTIONARY_BITS
            if original != original.lower():
                bits += 1  # capital letters somewhere
            if lower[i : i + length] != word:
                bits += 1  # substitutions
            found.append(Pattern(i, i + length, kind, original, bits))
            break
    return found


def find_personal(password: str, personal: str) -> list[Pattern]:
    """Parts of the user's name, username or email (three characters or longer)."""
    lower = password.lower()
    found = []
    for token in set(re.split(r"[^a-z0-9]+", personal.lower())):
        if len(token) < 3:
            continue
        start = lower.find(token)
        while start >= 0:
            found.append(Pattern(start, start + len(token), "personal", password[start : start + len(token)], 4.0))
            start = lower.find(token, start + 1)
    return found


def find_patterns(password: str, personal: str = "") -> list[Pattern]:
    """The predictable parts of the password that do not overlap, longest first."""
    candidates = (find_personal(password, personal) + find_words(password) + find_sequences(password)
                  + find_keyboard_patterns(password) + find_repeats(password) + find_years(password))
    candidates.sort(key=lambda p: (-(p.end - p.start), p.start))
    chosen: list[Pattern] = []
    for candidate in candidates:
        if all(candidate.end <= other.start or candidate.start >= other.end for other in chosen):
            chosen.append(candidate)
    chosen.sort(key=lambda p: p.start)
    return chosen


# ---------------------------------------------------------------------- strength


def pool_size(text: str) -> int:
    """How many different characters the text could have been drawn from, judging by the kinds it uses."""
    size = 0
    if any(c.islower() and c.isascii() for c in text):
        size += 26
    if any(c.isupper() and c.isascii() for c in text):
        size += 26
    if any(c.isdigit() and c.isascii() for c in text):
        size += 10
    if any(c.isascii() and not c.isalnum() for c in text):
        size += 33
    if any(not c.isascii() for c in text):
        size += 100
    return size


def repeated_block(password: str) -> str | None:
    """The shortest block the password consists of when it is that block repeated (abcabc -> abc)."""
    for size in range(1, len(password) // 2 + 1):
        if len(password) % size == 0 and password == password[:size] * (len(password) // size):
            return password[:size]
    return None


def common_password(password: str) -> str | None:
    """The common password this one is, or is a decorated version of (P@ssw0rd! -> password)."""
    lower = password.lower()
    stripped = _EDGES.sub("", lower)
    for candidate in (lower, lower.translate(LEET), stripped, stripped.translate(LEET)):
        if candidate in _COMMON_RANK:
            return candidate
    return None


def estimate_bits(password: str, patterns: list[Pattern]) -> float:
    """Bits of strength: predictable parts count for little, everything else as random characters."""
    if not password:
        return 0.0
    block = repeated_block(password)
    if block is not None:
        inner = [p for p in patterns if p.end <= len(block)]
        return estimate_bits(block, inner) + math.log2(len(password) // len(block)) + 1

    covered = [False] * len(password)
    bits = 0.0
    for pattern in patterns:
        bits += pattern.bits
        for i in range(pattern.start, pattern.end):
            covered[i] = True

    leftover = "".join(ch for ch, used in zip(password, covered) if not used)
    per_character = math.log2(pool_size(leftover)) if leftover else 0.0
    for i, ch in enumerate(password):
        if covered[i]:
            continue
        between = 0 < i < len(password) - 1 and covered[i - 1] and covered[i + 1]
        # a lone symbol joining two predictable parts ("word-word") is one of a few usual separators
        bits += 2.0 if between and not ch.isalnum() else per_character
    return bits


def crack_time(bits: float, guesses_per_second: float) -> str:
    """How long an attacker needs on average, in words."""
    seconds = 2 ** max(bits - 1, 0) / guesses_per_second
    if seconds < 1:
        return "less than a second"
    for unit, size in (("second", 60), ("minute", 60), ("hour", 24), ("day", 365)):
        if seconds < size:
            amount = int(seconds)
            return f"{amount} {unit}{'' if amount == 1 else 's'}"
        seconds /= size
    if seconds < 1_000:
        amount = int(seconds)
        return f"{amount} year{'' if amount == 1 else 's'}"
    if seconds < 1_000_000:
        return f"{int(seconds / 1_000)} thousand years"
    if seconds < 1_000_000_000:
        return f"{int(seconds / 1_000_000)} million years"
    return "more than a billion years"


# ---------------------------------------------------------------------- the analysis


def _kinds_used(password: str) -> tuple[list[str], list[str]]:
    kinds = {
        "lowercase letters": any(c.islower() for c in password),
        "uppercase letters": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }
    return [name for name, used in kinds.items() if used], [name for name, used in kinds.items() if not used]


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def analyze(password: str, personal: str = "", reuse: str | None = None) -> Analysis:
    """Analyze a password.

    personal: the user's name, username or email, to check the password does not contain it.
    reuse: "exact" or "similar" if the password history says this password was used before.
    """
    if not password:
        return Analysis(0, LABELS[0], 0.0, 0, suggestions=["Type a password to analyze it."],
                        online_time="less than a second", offline_time="less than a second")

    patterns = find_patterns(password, personal)
    bits = estimate_bits(password, patterns)
    common = common_password(password)
    block = repeated_block(password)
    by_kind: dict[str, list[Pattern]] = {}
    for pattern in patterns:
        by_kind.setdefault(pattern.kind, []).append(pattern)

    checks: list[Check] = []
    suggestions: list[str] = []
    length = len(password)

    # length
    if length >= GOOD_LENGTH:
        checks.append(Check("Length", True, f"{length} characters"))
    else:
        checks.append(Check("Length", False, f"{length} characters; use at least {GOOD_LENGTH}"))
        suggestions.append(f"Use at least {GOOD_LENGTH} characters. Length adds more strength than anything else.")

    # complexity
    used, missing = _kinds_used(password)
    if len(used) >= 3:
        checks.append(Check("Character variety", True, f"Uses {_join(used)}"))
    else:
        checks.append(Check("Character variety", False, f"Only {_join(used)}"))
        suggestions.append(f"Mix in {_join(missing[:2])}.")

    # uniqueness
    distinct = len(set(password))
    repeats = by_kind.get("repeat", [])
    if block is not None:
        checks.append(Check("Uniqueness", False,
                            f"The same {len(block)} character(s) repeated {length // len(block)} times"))
        suggestions.append("Do not repeat the same characters or the same block of characters.")
    elif repeats:
        checks.append(Check("Uniqueness", False, "The same character several times in a row"))
        suggestions.append('Avoid repeating a character, as in "aaa" or "0000".')
    elif length >= MIN_LENGTH and distinct / length < 0.5:
        checks.append(Check("Uniqueness", False, f"Only {distinct} different characters in {length}"))
        suggestions.append("Use a wider range of different characters.")
    else:
        checks.append(Check("Uniqueness", True, f"{distinct} different characters in {length}"))

    # patterns
    problems = []
    if "sequence" in by_kind:
        problems.append("a sequence")
        suggestions.append('Avoid sequences such as "abc" or "1234".')
    if "keyboard" in by_kind:
        problems.append("a keyboard pattern")
        suggestions.append('Avoid keyboard patterns such as "qwerty" or "asdf".')
    if "year" in by_kind:
        problems.append("a year")
        suggestions.append("Avoid years and dates; attackers try them early.")
    if problems:
        checks.append(Check("Patterns", False, "Contains " + _join(problems)))
    else:
        checks.append(Check("Patterns", True, "No sequences, keyboard patterns or years"))

    # common passwords and dictionary words
    words = by_kind.get("word", []) + by_kind.get("common", [])
    word_characters = sum(p.end - p.start for p in words)
    if common:
        checks.append(Check("Common passwords", False, "Based on a very common password"))
        suggestions.append("Do not build on a common password. Swapping letters for digits or symbols, "
                           "or adding a few at the end, does not help.")
    elif "common" in by_kind and sum(p.end - p.start for p in by_kind["common"]) >= length / 3:
        checks.append(Check("Common passwords", False, "Contains a word that is very common in passwords"))
        suggestions.append("Leave out words that are common in passwords, such as names, teams and seasons.")
    elif len(words) == 1 and word_characters >= length / 2:
        checks.append(Check("Common passwords", False, "Mostly one dictionary word"))
        suggestions.append("One dictionary word with a few extras is easy to guess. "
                           "Combine several unrelated words instead.")
    else:
        checks.append(Check("Common passwords", True, "Not a common password"))

    # personal information
    if personal.strip():
        if "personal" in by_kind:
            checks.append(Check("Personal information", False, "Contains part of your name or email"))
            suggestions.append("Leave out your name, username and email address.")
        else:
            checks.append(Check("Personal information", True, "Does not contain your details"))

    # reuse
    if reuse == "exact":
        checks.append(Check("Reuse", False, "You have used this password before"))
        suggestions.append("Choose a password you have not used before.")
    elif reuse == "similar":
        checks.append(Check("Reuse", False, "Too close to a password you used before"))
        suggestions.append("Change more than a few characters of an old password; use a new one.")
    elif reuse == "new":
        checks.append(Check("Reuse", True, "Not in your password history"))

    score = sum(bits >= threshold for threshold in THRESHOLDS)
    if length < MIN_LENGTH:
        score = min(score, 1)
    if common or reuse == "exact":
        score = 0
    elif reuse == "similar":
        score = min(score, 1)

    return Analysis(
        score=score,
        label=LABELS[score],
        bits=round(bits, 1),
        length=length,
        checks=checks,
        suggestions=suggestions,
        patterns=patterns,
        online_time=crack_time(bits, ONLINE_RATE),
        offline_time=crack_time(bits, OFFLINE_RATE),
    )
