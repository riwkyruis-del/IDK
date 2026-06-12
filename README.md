# Password Strength Checker & Generator

Advanced Edition - NIST Compliant

A comprehensive Python tool for generating secure passwords and evaluating their strength using industry-standard guidelines. This utility incorporates principles from NIST SP 800-63B, OWASP authentication recommendations, and information theory to provide accurate password security analysis.

## Table of Contents

- [Features](#features)
- [Security References](#security-references)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Programmatic Usage](#programmatic-usage)
  - [Command-Line Examples](#command-line-examples)
- [How Password Generation Works](#how-password-generation-works)
- [How Strength Evaluation Works](#how-strength-evaluation-works)
  - [Entropy Calculation](#entropy-calculation)
  - [Crack Time Estimation](#crack-time-estimation)
  - [NIST Compliance Checks](#nist-compliance-checks)
  - [Pattern Detection](#pattern-detection)
  - [Scoring System](#scoring-system)
  - [Strength Levels](#strength-levels)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

### Password Generation
- **Cryptographically Secure**: Uses Python's `secrets` module for true random number generation
- **Customizable Options**:
  - Adjustable length (4-128 characters, recommended 16+)
  - Toggle uppercase letters (A-Z)
  - Toggle lowercase letters (a-z)
  - Toggle digits (0-9)
  - Toggle special characters (!@#$%^&*...)
  - Exclude visually ambiguous characters (l, I, 1, L, o, O, 0)
  - Automatic pattern avoidance

### Strength Analysis
- **Shannon Entropy Calculation**: Measures password unpredictability in bits
- **Crack Time Estimation**: Shows how long it would take to brute-force
- **NIST SP 800-63B Compliance**: Checks against federal security guidelines
- **Pattern Detection**: Identifies weak patterns including:
  - Repeated characters (aaa, 111)
  - Sequential patterns (abc, 123, cba, 321)
  - Keyboard walks (qwerty, asdf, zxcv)
  - Common passwords from breach databases
  - Dictionary words and substrings
  - Date patterns (years, MMDD formats)
- **Detailed Feedback**: Actionable suggestions for improvement
- **Numerical Scoring**: 0-100 scale with categorical ratings

## Security References

This tool implements recommendations from:

1. **NIST Special Publication 800-63B** (Digital Identity Guidelines)
   - Minimum 8-character length requirement
   - Breached password screening
   - No mandatory composition rules (but variety still recommended)
   - Maximum 64-character support

2. **OWASP Authentication Cheat Sheet**
   - Strong random password generation
   - Pattern detection and prevention
   - Entropy-based strength measurement

3. **Information Theory (Shannon Entropy)**
   - Mathematical measurement of password randomness
   - Pool size and length-based calculations

4. **Common Password Databases**
   - RockYou breach data
   - Have I Been Pwned top lists
   - SecLists common passwords

## Requirements

- Python 3.6 or higher
- No external packages required (uses only standard library)

## Installation

1. Clone or download this repository
2. Verify Python installation: `python --version` or `python3 --version`
3. No additional setup needed - ready to use immediately

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
from password_tool import generate_password, check_strength, calculate_entropy, estimate_crack_time

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

# Example 4: Check the strength of any password (returns 4 values now)
strength, score, feedback, metrics = check_strength("MySecureP@ss123")
print(f"Strength: {strength}")
print(f"Score: {score}/100")
print(f"Entropy: {metrics['entropy']} bits")
print(f"Crack time: {metrics['crack_time']}")
print(f"NIST Compliant: {metrics['nist_compliant']}")
if feedback:
    print("Suggestions:")
    for suggestion in feedback:
        print(f"  - {suggestion}")

# Example 5: Calculate entropy directly
entropy = calculate_entropy("MyPassword123!")
print(f"Entropy: {entropy} bits")

# Example 6: Estimate crack time
crack_time = estimate_crack_time(entropy=80.0)
print(f"Estimated crack time: {crack_time}")
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
   - Lowercase: a-z (26 characters)
   - Uppercase: A-Z (26 characters)
   - Digits: 0-9 (10 characters)
   - Special: !@#$%^&*()_+-=[]{}|;:,.<>? (32 characters)

2. **Guaranteed Character Inclusion**: If you enable multiple character types, the algorithm guarantees at least one character from each enabled type appears in the password. This prevents accidentally generating passwords that lack variety.

3. **Ambiguous Character Exclusion**: When enabled, the following visually confusing characters are removed from all pools:
   - Lowercase L (l)
   - Uppercase I (I)
   - Number one (1)
   - Uppercase L (L)
   - Lowercase O (o)
   - Uppercase O (O)
   - Number zero (0)

4. **Cryptographic Randomness**: The tool uses Python's `secrets` module, which generates cryptographically secure random numbers suitable for managing data such as passwords and authentication tokens. This is more secure than the standard `random` module because it uses operating system sources of randomness.

5. **Random Shuffling**: After building the password character by character, the algorithm performs a Fisher-Yates shuffle using `secrets.randbelow()` to ensure guaranteed characters don't appear in predictable positions.

6. **Pattern Avoidance**: The generator automatically checks for sequential or repeated patterns and regenerates the password if any are detected (for passwords 8+ characters).

## How Strength Evaluation Works

The strength checker analyzes passwords using multiple scientific criteria and produces a comprehensive security assessment.

### Entropy Calculation

Entropy measures the unpredictability of a password in bits, based on information theory developed by Claude Shannon.

**Formula**: `Entropy = Length * log2(Pool Size)`

Where:
- Length = number of characters in the password
- Pool Size = total number of possible characters used (e.g., 26 for lowercase only, 94 for all ASCII printable)

**Interpretation**:
- 0-30 bits: Very weak, easily cracked
- 30-50 bits: Weak to fair
- 50-60 bits: Good for basic protection
- 60-80 bits: Strong, suitable for most applications
- 80+ bits: Very strong, resistant to brute-force attacks

### Crack Time Estimation

Based on entropy, the tool estimates how long it would take an attacker to crack the password via brute force.

**Assumptions**:
- Default attack speed: 10 billion guesses per second (high-end GPU cluster)
- Average case: attacker needs to try half of all possible combinations

**Example estimates**:
- 40 bits entropy: ~9 minutes
- 60 bits entropy: ~6 days
- 80 bits entropy: ~4 years
- 100 bits entropy: ~centuries

### NIST Compliance Checks

The tool evaluates passwords against NIST SP 800-63B Digital Identity Guidelines:

| Check | Requirement | Why It Matters |
|-------|-------------|----------------|
| Minimum Length | At least 8 characters | Short passwords are easily brute-forced |
| Maximum Length | Up to 64 characters supported | Some systems have input limits |
| Not Common | Not in breach databases | Common passwords are tried first by attackers |
| No Repeated Chars | No 3+ consecutive identical characters | Patterns reduce effective entropy |
| Printable ASCII | All characters must be printable | Ensures compatibility across systems |

### Pattern Detection

The tool identifies several types of weak patterns:

1. **Sequential Letters**: Detects "abc", "xyz", "ABC", and reverse sequences like "cba"
2. **Sequential Numbers**: Detects "123", "456", "789", and reverse sequences like "321"
3. **Keyboard Patterns**: Detects common keyboard walks:
   - Top row: qwertyuiop
   - Home row: asdfghjkl
   - Bottom row: zxcvbnm
   - Diagonal patterns: qazwsx, 1qaz, 2wsx
4. **Repeated Characters**: Flags any character repeated 3+ times (aaa, 1111)
5. **Common Passwords**: Checks against 40+ most breached passwords
6. **Dictionary Words**: Detects common substrings like "password", "admin", "secret"
7. **Date Patterns**: Identifies years (1990-2099) and date formats (MMDD)

### Scoring System

**Positive Points (what makes a password stronger):**

| Criterion | Points | Details |
|-----------|--------|---------|
| Length 20+ characters | +35 | Excellent length |
| Length 16-19 characters | +30 | Very good length |
| Length 12-15 characters | +25 | Good length |
| Length 8-11 characters | +15 | Minimum acceptable |
| Contains lowercase letters | +10 | Adds variety |
| Contains uppercase letters | +10 | Adds variety |
| Contains digits | +10 | Adds variety |
| Contains special characters | +15 | Significantly increases complexity |
| Uses 3+ character types | +5 | Bonus for variety |
| Uses all 4 character types | +5 | Additional bonus |

**Negative Points (what makes a password weaker):**

| Issue | Penalty | Example |
|-------|---------|---------|
| Too short (<8 chars) | -20 | "abc123" |
| Common password | -30 | "password123" |
| Contains common words | -20 | "MyPassword1" |
| Repeated characters | -15 | "aaabbb" |
| Sequential/keyboard patterns | -10 | "qwerty123" |
| Year pattern detected | -5 | "Summer2024" |
| Date pattern detected | -5 | "01151990" |

### Strength Levels

Based on the final score AND entropy, passwords are categorized as follows:

| Score Range | Min Entropy | Rating | Recommendation |
|-------------|-------------|--------|----------------|
| 0-24 | <30 bits | Very Weak | Change immediately. Easily cracked in seconds. |
| 25-44 | <40 bits | Weak | Improve significantly. Cracked in hours to days. |
| 45-64 | <50 bits | Fair | Acceptable for low-risk accounts only. |
| 65-84 | <60 bits | Strong | Good for most purposes. Minor improvements optional. |
| 85-100 | 60+ bits | Very Strong | Excellent. Suitable for high-security applications. |

Note: Both score AND entropy must meet thresholds for higher ratings. A password with high score but low entropy (due to patterns) will receive a lower rating.

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
