#!/usr/bin/env python3
"""
Password Strength Analyzer - CYB 333 Project

This simple version:
- Asks the user for a single password
- Checks length
- Checks for lowercase, uppercase, digits, and special characters
- Flags a few "obvious" bad passwords
- Prints a simple strength rating and short feedback
"""

import string

# Minimum length we want to recommend
MIN_LENGTH = 12

# Tiny list of very common bad passwords (can be expanded later)
COMMON_WEAK_PASSWORDS = {
    "password",
    "password1",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
}


def analyze_password(pw: str) -> dict:
    """
    Analyze a password and return the results as a dictionary.
    """
    length = len(pw)
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(c in string.punctuation for c in pw)

    # check against common weak passwords (case-insensitive)
    is_common = pw.lower() in COMMON_WEAK_PASSWORDS

    # very simple scoring system
    score = 0

    # length matters a lot
    if length >= MIN_LENGTH:
        score += 2
    elif length >= 8:
        score += 1

    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1

    # if it’s a known terrible password, force it to the worst score
    if is_common:
        score = 0

    # turn score into a label
    if is_common or score <= 2:
        strength = "WEAK"
    elif 3 <= score <= 4:
        strength = "MODERATE"
    else:
        strength = "STRONG"

    return {
        "password": pw,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "is_common": is_common,
        "score": score,
        "strength": strength,
    }


def format_feedback(result: dict) -> str:
    """
    Build a short human-readable explanation of the result.
    """
    parts = []

    if result["is_common"]:
        parts.append(
            "This password is on a list of very common passwords and should never be used."
        )

    if result["length"] < MIN_LENGTH:
        parts.append(
            f"Try using at least {MIN_LENGTH} characters; longer passwords are harder to guess."
        )
    else:
        parts.append("Good length: meets the minimum length recommendation.")

    if not result["has_lower"]:
        parts.append("Add lowercase letters to increase complexity.")
    if not result["has_upper"]:
        parts.append("Add uppercase letters to increase complexity.")
    if not result["has_digit"]:
        parts.append("Add digits (0–9) to make brute-force guessing harder.")
    if not result["has_special"]:
        parts.append(
            "Add special characters (e.g., !, ?, #, %) to further increase strength."
        )

    if (
        result["has_lower"]
        and result["has_upper"]
        and result["has_digit"]
        and result["has_special"]
    ):
        parts.append("Nice job: your password uses a good mix of character types.")

    return " ".join(parts)


def main() -> None:
    print("=== Password Strength Analyzer (CYB 333) ===")
    pw = input("Enter a password to evaluate: ").strip()

    if not pw:
        print("No password entered. Exiting.")
        return

    result = analyze_password(pw)

    print("\n--- Analysis ---")
    print(f"Password length: {result['length']}")
    print(f"Contains lowercase letters: {result['has_lower']}")
    print(f"Contains uppercase letters: {result['has_upper']}")
    print(f"Contains digits: {result['has_digit']}")
    print(f"Contains special characters: {result['has_special']}")
    print(f"Matches common weak password list: {result['is_common']}")

    print(f"\nOverall strength: {result['strength']}")
    print("\nFeedback:")
    print(format_feedback(result))


if __name__ == "__main__":
    main()
