# Password Strength Checker & Generator

A comprehensive Python tool for generating secure passwords and evaluating their strength. This utility helps you create cryptographically strong passwords and provides detailed analysis of existing passwords with actionable recommendations for improvement.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Programmatic Usage](#programmatic-usage)
  - [Command-Line Examples](#command-line-examples)
- [How Password Generation Works](#how-password-generation-works)
- [How Strength Evaluation Works](#how-strength-evaluation-works)
  - [Scoring System](#scoring-system)
  - [Strength Levels](#strength-levels)
  - [Common Pattern Detection](#common-pattern-detection)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Secure Password Generation**: Creates cryptographically secure random passwords using Python's `secrets` module
- **Customizable Options**:
  - Adjustable length (minimum 4 characters, recommended 16+)
  - Toggle inclusion of uppercase letters (A-Z)
  - Toggle inclusion of lowercase letters (a-z)
  - Toggle inclusion of digits (0-9)
  - Toggle inclusion of special characters (!@#$%^&*...)
  - Option to exclude visually ambiguous characters (l, I, 1, L, o, O, 0)
- **Comprehensive Strength Analysis**:
  - Numerical scoring from 0 to 100
  - Categorical ratings (Very Weak to Very Strong)
  - Detailed feedback with specific improvement suggestions
- **Pattern Detection**: Identifies and penalizes:
  - Repeated characters (e.g., "aaa")
  - Sequential patterns (e.g., "abc", "123", "qwerty")
  - Common dictionary words (e.g., "password", "admin")
- **No External Dependencies**: Uses only Python standard library modules

## Requirements

- Python 3.6 or higher
- No external packages required (uses only standard library: `secrets`, `string`, `re`, `typing`)

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed (check with `python --version` or `python3 --version`)
3. No additional installation steps required

## Usage

### Interactive Mode

The easiest way to use this tool is through its interactive command-line interface. Run the following command from your terminal:

```bash
python password_tool.py
```

Upon starting, you will see a menu with three options:

```
============================================================
Password Strength Checker & Generator
============================================================

Options:
1. Generate a new password
2. Check password strength
3. Exit

Enter your choice (1-3):
```

#### Option 1: Generate a New Password

When you select option 1, the tool will prompt you to configure the password parameters:

1. **Password Length**: Enter the desired length (default is 16 if you press Enter without typing a number). Minimum is 4 characters.
2. **Character Types**: For each character type, press Enter to include it or type 'n' to exclude it:
   - Uppercase letters (A-Z)
   - Lowercase letters (a-z)
   - Digits (0-9)
   - Special characters (!@#$%^&*...)
3. **Exclude Ambiguous Characters**: Type 'y' if you want to exclude characters that look similar (like l, I, 1, O, 0), or press Enter to keep them.

After configuration, the tool displays:
- The generated password
- Its strength rating and score
- Quick tips if improvements are possible

#### Option 2: Check Password Strength

Select option 2 to evaluate an existing password:

1. Enter the password you want to check (it will not be displayed as you type for privacy)
2. The tool analyzes the password and displays:
   - Masked password display (shown as asterisks)
   - Strength category (Very Weak, Weak, Fair, Strong, or Very Strong)
   - Numerical score (0-100)
   - List of specific suggestions for improvement

#### Option 3: Exit

Select option 3 to close the application.

### Programmatic Usage

You can import and use the functions directly in your own Python scripts:

```python
from password_tool import generate_password, check_strength

# Example 1: Generate a default 16-character password
password = generate_password()
print(f"Generated: {password}")

# Example 2: Generate a 20-character password with all character types
password = generate_password(
    length=20,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=True,
    exclude_ambiguous=False
)
print(f"Strong password: {password}")

# Example 3: Generate a password without ambiguous characters (easier to read/type)
password = generate_password(
    length=16,
    exclude_ambiguous=True
)
print(f"Easy-to-read password: {password}")

# Example 4: Check the strength of any password
strength, score, feedback = check_strength("MySecureP@ss123")
print(f"Strength: {strength}")
print(f"Score: {score}/100")
if feedback:
    print("Suggestions:")
    for suggestion in feedback:
        print(f"  - {suggestion}")
```

### Command-Line Examples

Here are some common usage scenarios:

**Generate a quick secure password:**
```bash
python password_tool.py
# Choose option 1, accept defaults by pressing Enter throughout
```

**Check if your current password is strong enough:**
```bash
python password_tool.py
# Choose option 2, enter your password when prompted
```

**Generate a password for a system that doesn't allow special characters:**
```bash
python password_tool.py
# Choose option 1
# Enter length: 16
# Uppercase: (press Enter)
# Lowercase: (press Enter)
# Digits: (press Enter)
# Special chars: n
# Exclude ambiguous: (press Enter)
```

## How Password Generation Works

The password generation algorithm ensures both security and randomness:

1. **Character Pool Construction**: Based on your selections, the tool builds a pool of allowed characters from four categories:
   - Lowercase: a-z
   - Uppercase: A-Z
   - Digits: 0-9
   - Special: !@#$%^&*()_+-=[]{}|;:,.<>?

2. **Guaranteed Character Inclusion**: If you enable multiple character types, the algorithm guarantees at least one character from each enabled type appears in the password. This prevents accidentally generating passwords that lack variety.

3. **Ambiguous Character Exclusion**: When enabled, the following visually confusing characters are removed from all pools:
   - Lowercase L (l)
   - Uppercase I (I)
   - Number one (1)
   - Uppercase L (L)
   - Lowercase O (o)
   - Uppercase O (O)
   - Number zero (0)

4. **Cryptographic Randomness**: The tool uses Python's `secrets` module, which generates cryptographically secure random numbers suitable for managing data such as passwords and authentication tokens. This is more secure than the standard `random` module.

5. **Random Shuffling**: After building the password character by character, the algorithm performs a Fisher-Yates shuffle using `secrets.randbelow()` to ensure guaranteed characters don't appear in predictable positions.

## How Strength Evaluation Works

The strength checker analyzes passwords using multiple criteria and produces a score from 0 to 100.

### Scoring System

**Positive Points (what makes a password stronger):**

| Criterion | Points | Details |
|-----------|--------|---------|
| Length 16-19 characters | +25 | Good length |
| Length 20+ characters | +30 | Excellent length |
| Length 12-15 characters | +20 | Acceptable length |
| Length 8-11 characters | +10 | Minimum acceptable |
| Contains lowercase letters | +10 | Adds variety |
| Contains uppercase letters | +10 | Adds variety |
| Contains digits | +10 | Adds variety |
| Contains special characters | +15 | Significantly increases complexity |

**Negative Points (what makes a password weaker):**

| Issue | Penalty | Example |
|-------|---------|---------|
| Repeated characters (3+ same char) | -10 | "aaa", "1111" |
| Sequential patterns | -5 | "abc", "123", "qwerty" |
| Common dictionary words | -15 | "password", "admin", "letmein" |

### Strength Levels

Based on the final score, passwords are categorized as follows:

| Score Range | Rating | Recommendation |
|-------------|--------|----------------|
| 0-19 | Very Weak | Change immediately. This password offers minimal protection. |
| 20-39 | Weak | Improve significantly. Not suitable for important accounts. |
| 40-59 | Fair | Acceptable for low-risk accounts, but should be strengthened. |
| 60-79 | Strong | Good for most purposes. Consider minor improvements. |
| 80-100 | Very Strong | Excellent. Suitable for high-security applications. |

### Common Pattern Detection

The tool checks for several types of predictable patterns that attackers commonly try:

1. **Sequential Letters**: Detects sequences like "abc", "xyz", "ABC"
2. **Sequential Numbers**: Detects "123", "456", "789"
3. **Keyboard Patterns**: Detects common keyboard walks like "qwerty", "asdf", "zxcv"
4. **Repeated Characters**: Flags any character repeated 3 or more times consecutively
5. **Common Words**: Checks against a list of frequently used (and easily guessed) words:
   - password
   - admin
   - user
   - login
   - welcome
   - letmein

## Security Best Practices

Follow these guidelines to maximize your password security:

1. **Use Long Passwords**: Aim for at least 16 characters. Every additional character exponentially increases the time required to crack the password.

2. **Maximize Character Variety**: Include all four character types (uppercase, lowercase, digits, special characters) whenever the system allows it.

3. **Avoid Personal Information**: Never use names, birthdays, addresses, or other information that could be discovered through social engineering or public records.

4. **Use Unique Passwords**: Never reuse passwords across different accounts. If one account is compromised, all accounts with the same password are at risk.

5. **Consider a Password Manager**: Use a reputable password manager to store your generated passwords securely. This allows you to use long, complex passwords without needing to memorize them.

6. **Enable Two-Factor Authentication (2FA)**: Wherever possible, enable 2FA as an additional security layer beyond just a password.

7. **Change Passwords Periodically**: While the need for frequent changes is debated, consider updating passwords for critical accounts annually or if you suspect any compromise.

8. **Beware of Phishing**: No password can protect you if you willingly give it to attackers through phishing emails or fake websites.

## Troubleshooting

**Issue: "Python is not recognized"**
- Solution: Ensure Python 3.6+ is installed and added to your system PATH. Download from python.org if needed.

**Issue: "ValueError: Password length must be at least 4 characters"**
- Solution: Enter a length of 4 or greater when generating passwords.

**Issue: "At least one character type must be selected"**
- Solution: When generating a password, ensure at least one character type (uppercase, lowercase, digits, or special) is enabled.

**Issue: Generated password seems predictable**
- Note: The tool uses cryptographically secure randomness. If you're seeing patterns, it's coincidental. Try generating again.

**Issue: Want to use in automated scripts**
- Solution: Use the programmatic API shown above. You can also modify the source code to accept command-line arguments for non-interactive use.

## License

MIT License - Feel free to use, modify, and distribute this software for any purpose. No warranty is provided; use at your own discretion.
