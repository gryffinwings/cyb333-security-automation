#!/usr/bin/env python3
"""
Password Strength Analyzer (CYB 333)
- Single password via -p / --password
- Batch passwords via -f / --file (one per line)
- Optional output report via -o / --output (.txt, .csv, .json)
- Optional banned/common list via --banned-file
- If no -p or -f is provided, the script prompts interactively.

Educational scope:
This is a transparent, rules-based checker (length, variety, common passwords, patterns).
It does NOT query breach databases or perform large dictionary attacks.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Set


# Small built-in weak/common list (you can expand via --banned-file)
DEFAULT_COMMON_PASSWORDS: Set[str] = {
    "password", "123456", "123456789", "qwerty", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "football", "abc123", "111111", "000000"
}

# Regex checks
RE_LOWER = re.compile(r"[a-z]")
RE_UPPER = re.compile(r"[A-Z]")
RE_DIGIT = re.compile(r"\d")
RE_SPECIAL = re.compile(r"[^a-zA-Z0-9]")

# Simple pattern detection
RE_SEQUENTIAL = re.compile(
    r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|qwer|asdf|zxcv)",
    re.IGNORECASE,
)
RE_REPEAT_CHAR = re.compile(r"(.)\1\1")  # 3+ of same char in a row


@dataclass
class Result:
    password: str
    length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_special: bool
    is_common: bool
    entropy_bits: float
    score: int
    strength: str
    feedback: List[str]


def load_lines(path: Path) -> List[str]:
    """Read non-empty, non-comment lines from a file."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    lines: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def load_banned_list(path: Path) -> Set[str]:
    """Load additional banned/common passwords (one per line)."""
    return {x.lower() for x in load_lines(path)}


def estimate_entropy_bits(password: str, has_lower: bool, has_upper: bool, has_digit: bool, has_special: bool) -> float:
    """
    Educational estimate:
    pool_size approximates character set used; entropy ≈ length * log2(pool_size).
    Not a guarantee of real-world strength.
    """
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_special:
        pool += 33  # rough estimate of printable specials

    if pool <= 1 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool), 1)


def strength_label(score: int) -> str:
    if score >= 85:
        return "STRONG"
    if score >= 60:
        return "MODERATE"
    return "WEAK"


def analyze_password(pw: str, common_list: Set[str]) -> Result:
    pw = pw.rstrip("\n")
    pw_lower = pw.lower()

    length = len(pw)
    has_lower = bool(RE_LOWER.search(pw))
    has_upper = bool(RE_UPPER.search(pw))
    has_digit = bool(RE_DIGIT.search(pw))
    has_special = bool(RE_SPECIAL.search(pw))

    entropy_bits = estimate_entropy_bits(pw, has_lower, has_upper, has_digit, has_special)
    is_common = pw_lower in common_list

    feedback: List[str] = []
    score = 0

    # --- Length scoring (max 45)
    if length >= 15:
        score += 45
    elif length >= 12:
        score += 35
        feedback.append("Try using 15+ characters (a passphrase is easier to remember).")
    elif length >= 8:
        score += 20
        feedback.append("Increase length to at least 12–15 characters for stronger resistance to guessing.")
    else:
        score += 5
        feedback.append("Too short: aim for at least 12–15 characters (prefer a passphrase).")

    # --- Variety scoring (max 40)
    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety == 4:
        score += 40
    elif variety == 3:
        score += 30
        if not has_upper:
            feedback.append("Add uppercase letters to increase complexity.")
        if not has_lower:
            feedback.append("Add lowercase letters to increase complexity.")
        if not has_digit:
            feedback.append("Add digits to increase complexity.")
        if not has_special:
            feedback.append("Add special characters (e.g., !, ?, #, %) to increase strength.")
    elif variety == 2:
        score += 18
        feedback.append("Add more character types (upper/lower, numbers, symbols) to increase strength.")
    else:
        score += 5
        feedback.append("Very low variety: mix letters, numbers, and symbols.")

    # --- Pattern penalties (up to -25)
    if RE_SEQUENTIAL.search(pw):
        score -= 10
        feedback.append("Avoid sequences like 1234, abcd, qwer, asdf.")
    if RE_REPEAT_CHAR.search(pw):
        score -= 8
        feedback.append("Avoid repeating the same character 3+ times in a row (e.g., 'aaa', '111').")
    if " " in pw:
        # Not a penalty—spaces can be fine in passphrases—but some systems reject them.
        feedback.append("Note: some systems may not allow spaces; if rejected, remove spaces and keep length high.")

    # --- Common/banned password penalty (big)
    if is_common:
        score = max(score - 60, 0)
        feedback.insert(0, "Matches a common/banned password — choose something unique.")

    # Clamp to 0-100
    score = max(0, min(100, score))
    strength = strength_label(score)

    # Clean feedback if none
    if not feedback and strength == "STRONG":
        feedback = ["Looks good. Use unique passwords and consider a password manager."]

    return Result(
        password=pw,
        length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special,
        is_common=is_common,
        entropy_bits=entropy_bits,
        score=score,
        strength=strength,
        feedback=feedback,
    )


def print_one(r: Result) -> None:
    print("\n--- Analysis ---")
    print(f"Password length: {r.length}")
    print(f"Contains lowercase letters: {r.has_lower}")
    print(f"Contains uppercase letters: {r.has_upper}")
    print(f"Contains digits: {r.has_digit}")
    print(f"Contains special characters: {r.has_special}")
    print(f"Matches common weak password list: {r.is_common}")
    print(f"Estimated entropy (educational): {r.entropy_bits} bits")
    print(f"\nOverall strength: {r.strength} (Score: {r.score}/100)")
    print("\nFeedback:")
    for item in r.feedback:
        print(f"- {item}")


def save_results(results: List[Result], out_path: Path) -> None:
    ext = out_path.suffix.lower()

    if ext in ("", ".txt"):
        lines: List[str] = []
        for r in results:
            lines.append("=" * 60)
            lines.append(f"Password: {r.password}")
            lines.append(f"Length: {r.length}")
            lines.append(f"lower={r.has_lower}, upper={r.has_upper}, digit={r.has_digit}, special={r.has_special}")
            lines.append(f"Common/banned: {r.is_common}")
            lines.append(f"Entropy (educational): {r.entropy_bits} bits")
            lines.append(f"Strength: {r.strength} (Score: {r.score}/100)")
            lines.append("Feedback:")
            for item in r.feedback:
                lines.append(f"- {item}")
        lines.append("=" * 60)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    elif ext == ".csv":
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "password", "length", "has_lower", "has_upper", "has_digit", "has_special",
                    "is_common", "entropy_bits", "score", "strength", "feedback"
                ],
            )
            writer.writeheader()
            for r in results:
                row = asdict(r)
                row["feedback"] = " | ".join(r.feedback)
                writer.writerow(row)

    elif ext == ".json":
        payload = [asdict(r) for r in results]
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    else:
        raise ValueError("Unsupported output type. Use .txt, .csv, or .json")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Password Strength Analyzer (CYB 333)")
    parser.add_argument("-p", "--password", help="Password to analyze (single).")
    parser.add_argument("-f", "--file", help="Analyze passwords from a file (one per line).")
    parser.add_argument("-o", "--output", help="Optional report output file (.txt, .csv, .json).")
    parser.add_argument("--banned-file", help="Optional banned/common password list file (one per line).")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    common_list = set(DEFAULT_COMMON_PASSWORDS)
    if args.banned_file:
        common_list |= load_banned_list(Path(args.banned_file))

    print("\n=== Password Strength Analyzer (CYB 333) ===")

    # Determine input mode
    passwords: List[str] = []
    if args.password:
        passwords = [args.password]
    elif args.file:
        passwords = load_lines(Path(args.file))
    else:
        pw = input("Enter a password to evaluate: ").strip()
        if not pw:
            print("No password entered. Exiting.")
            return 1
        passwords = [pw]

    results = [analyze_password(pw, common_list) for pw in passwords]

    # Print results
    if len(results) == 1:
        print_one(results[0])
    else:
        for idx, r in enumerate(results, start=1):
            print("\n" + "=" * 60)
            print(f"Password {idx}/{len(results)}: {r.password}")
            print_one(r)

    # Save report if requested
    if args.output:
        out_path = Path(args.output)
        save_results(results, out_path)
        print(f"\nSaved report to: {out_path}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
