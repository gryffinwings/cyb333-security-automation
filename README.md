# CYB 333 Security Automation – Password Strength Analyzer

This project is a Python-based **Password Strength Analyzer** created for **CYB 333 (Security Automation)**. The script evaluates password strength using transparent, educational rules and provides actionable feedback to help users create stronger passwords.

The analyzer supports **interactive mode**, **single-password mode**, and **batch analysis from a file**, with optional **report output** to `.txt` (and optional `.csv` / `.json` if supported by the script).

---

## Project Objectives

- Demonstrate **security automation concepts** using Python.
- Implement an **explainable** password analysis method (not a “black box”).
- Support automation-friendly workflows via **command-line options** and **batch processing**.
- Produce clear output that explains **why** a password is weak/moderate/strong and how to improve it.

---

## Features

- **Interactive prompt** (enter a password when the script runs with no flags)
- **Single password analysis** via command-line flag (`-p`)
- **Batch password analysis** from a text file (`-f`) – one password per line
- Strength output includes:
  - length check
  - character variety (lower/upper/digits/special)
  - common/banned password detection (basic list)
  - simple pattern detection (sequences and repeated characters)
  - score (0–100), strength label, and feedback
- **Optional report export** using `-o` (example: `results.txt`)
- Uses **Python standard library only** (no external dependencies)

---

## Requirements / Prerequisites

- **Python 3.x**
- No external Python packages required

Check your Python version:

```bash
python3 --version
