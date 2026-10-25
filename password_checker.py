#!/usr/bin/env python3
"""
PASSWORD CHECKER

For each password it shows exactly four things:
  1. Strength   (Weak / Moderate / Strong)
  2. Length     (number of characters)
  3. Breached?  (checked against Have I Been Pwned; only the first 5
                 characters of the SHA-1 hash are sent, never the password)
  4. Tips       (what to improve)
"""

import getpass
import hashlib
import re
import secrets
import string
import urllib.error
import urllib.request


# SETTINGS
# ----------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "qwerty123", "abc123", "111111", "000000", "letmein", "welcome",
    "admin", "administrator", "login", "iloveyou", "monkey", "dragon",
    "football", "baseball", "master", "sunshine", "princess", "shadow",
    "passw0rd", "password1", "password123", "trustno1", "changeme",
    "superman", "batman", "starwars", "whatever", "freedom", "hello123",
}

# Undo look-alike substitutions: P@ssw0rd -> password
LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "$": "s", "5": "s", "7": "t",
})

SEQUENCE_SOURCES = [
    string.ascii_lowercase, string.digits,
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]

SYMBOLS = "!@#$%^&*()-_=+"

# CHECKS
# ----------------------------------------------------------------------
def is_common_password(password):
    lowered = password.lower()
    trimmed = lowered.rstrip(string.digits + string.punctuation)
    versions = {lowered, lowered.translate(LEET_MAP),
                trimmed, trimmed.translate(LEET_MAP)}
    return any(v and v in COMMON_PASSWORDS for v in versions)


def find_sequence(password, min_length=4):
    lowered = password.lower()
    for source in SEQUENCE_SOURCES:
        for line in (source, source[::-1]):          # forwards and backwards
            for i in range(len(line) - min_length + 1):
                piece = line[i:i + min_length]
                if piece in lowered:
                    return piece
    return None


def has_repeats(password, times=3):
    return re.search(r"(.)\1{%d,}" % (times - 1), password) is not None


def contains_personal_info(password, personal_words):
    lowered = password.lower()
    disguised = lowered.translate(LEET_MAP)
    for word in personal_words:
        word = word.lower().strip()
        if len(word) >= 3 and (word in lowered or word in disguised):
            return word
    return None


def check_breach(password):
    """
    Returns how many times the password appears in known breaches
    (0 = not found), or None if the lookup failed (e.g. offline).

    SHA-1 is used only as a LOOKUP KEY because the HIBP database is indexed
    by it sending only the first 5 hash characters (k-anonymity).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_5, rest = sha1[:5], sha1[5:]
    request = urllib.request.Request(
        "https://api.pwnedpasswords.com/range/" + first_5,
        headers={"User-Agent": "simple-password-checker", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            text = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    for line in text.splitlines():
        hash_end, _, count = line.partition(":")
        if hash_end == rest:
            return int(count)
    return 0


# ANALYSIS
# ----------------------------------------------------------------------
def analyze_password(password, personal_words):
    tips = []
    n = len(password)

    # --- Length -------------------------------------------------------
    if n < 12:
        tips.append("Make it at least 12 characters (16+ is even better).")

    # --- Character variety -------------------------------------------
    if not re.search(r"[a-z]", password):
        tips.append("Add lowercase letters (a-z).")
    if not re.search(r"[A-Z]", password):
        tips.append("Add uppercase letters (A-Z).")
    if not re.search(r"[0-9]", password):
        tips.append("Add numbers (0-9).")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add symbols such as ! @ # $.")

    # --- Weak patterns -----------------------------------------------
    common = is_common_password(password)
    if common:
        tips.append("This is a commonly used password (even with symbol "
                    "swaps). Choose something unique.")

    seq = find_sequence(password)
    if seq:
        tips.append(f"Avoid predictable sequences like '{seq}'.")

    repeats = has_repeats(password)
    if repeats:
        tips.append("Avoid repeating the same character 3+ times in a row.")

    personal = contains_personal_info(password, personal_words)
    if personal:
        tips.append(f"Remove personal info ('{personal}') from the password.")

    # --- Breach check -------------------------------------------------
    breach_count = check_breach(password)
    if breach_count:
        tips.append("This password has leaked before. Never use it again, "
                    "and change it anywhere you've used it.")

    # --- Strength (3 levels) -----------------------------------------
    # Count how many character types are used (lowercase, uppercase,
    # numbers, symbols): a number from 0 to 4.
    types_used = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])

    # WEAK:     very short, common, breached, or short AND not varied
    # MODERATE: not terrible, but has a pattern, personal info, is under
    #           12 characters, or uses fewer than 3 character types
    # STRONG:   12+ characters, 3+ character types, and no red flags
    if n < 8 or common or breach_count or (n < 12 and types_used < 3):
        strength = "Weak"
    elif seq or repeats or personal or n < 12 or types_used < 3:
        strength = "Moderate"
    else:
        strength = "Strong"

    if breach_count is None:
        tips.append("Breach check failed (no internet?). Re-run online to "
                    "confirm it hasn't leaked.")

    return {
        "strength": strength,
        "length": n,
        "breach_count": breach_count,
        "tips": tips,
    }


def generate_password(length=16):
    """Secure random password (uses 'secrets', not 'random')."""
    length = max(length, 12)
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in SYMBOLS for c in pwd)):
            return pwd


# OUTPUT
# ----------------------------------------------------------------------
def print_report(result):
    breach = result["breach_count"]
    if breach is None:
        breached_text = "UNKNOWN (could not reach the breach database)"
    elif breach > 0:
        breached_text = f"YES, found {breach:,} times in known breaches"
    else:
        breached_text = "NO, not found in known breaches"

    print("\n" + "-" * 46)
    print(f"  Strength : {result['strength']}")
    print(f"  Length   : {result['length']} characters")
    print(f"  Breached : {breached_text}")
    print("-" * 46)

    if result["tips"]:
        print("  Tips for improvement:")
        for tip in result["tips"]:
            print(f"   - {tip}")
    else:
        print("  No improvements needed. Great password!")
    print("-" * 46)


def main():
    print("=" * 46)
    print("          PASSWORD CHECKER")
    print("=" * 46)

    personal_text = input(
        "Optional: your name/username (comma separated) to make sure they're not in the password, or press Enter to skip: "
    )
    personal_words = [w for w in personal_text.split(",") if w.strip()]

    while True:
        password = getpass.getpass(
            "\nEnter a password (hidden), 'gen' to generate, 'exit' to quit: "
        )

        if password.lower() == "exit":
            print("Goodbye! Stay safe online.")
            break
        if password.lower() == "gen":
            print(f"\n  Generated password: {generate_password()}")
            continue
        if not password:
            print("Password cannot be empty.")
            continue

        print_report(analyze_password(password, personal_words))


if __name__ == "__main__":
    main()