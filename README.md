# CYB 333 Security Automation – Password Strength Analyzer

This project is a Python-based **Password Strength Analyzer** created for **CYB 333 (Security Automation)**. The script evaluates password strength using transparent, educational rules and provides actionable feedback to help users create stronger passwords.

The analyzer supports **interactive mode**, **single-password mode**, and **batch analysis from a file**, with optional report output in `.txt`, `.csv`, or `.json`.

---

## Features

- **Interactive prompt** (enter a password when the script runs)
- **Single password analysis** via command-line flag (`-p`)
- **Batch password analysis** from a text file (`-f`) — one password per line
- Strength output includes:
  - length check
  - character variety (lower/upper/digits/special)
  - common/banned password detection (basic list)
  - simple pattern detection (sequences and repeated characters)
  - score (0–100), strength label, and feedback
- Optional **report output** to `.txt`, `.csv`, or `.json` (`-o`)
- Optional custom **banned/common password list file** (`--banned-file`)

---

## Requirements

- **Python 3.x**
- No external Python packages required (standard library only)

Check your Python version:

```bash
python3 --version