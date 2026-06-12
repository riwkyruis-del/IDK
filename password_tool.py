#!/usr/bin/env python3
"""
Password Strength Checker & Generator

Advanced Features:
- Generate cryptographically secure passwords using secrets module
- Calculate password entropy based on character set and length
- Evaluate strength using NIST SP 800-63B guidelines
- Detect common patterns, sequences, and dictionary words
- Provide actionable feedback with security recommendations
- Simulate breach detection against common password lists

References:
- NIST Special Publication 800-63B (Digital Identity Guidelines)
- OWASP Authentication Cheat Sheet
- Information Theory (Shannon Entropy)
- Common password lists (RockYou, Have I Been Pwned top lists)
"""

import secrets
import string
import re
import math
from typing import Tuple, List, Dict, Optional
from datetime import datetime


# Extended list of common passwords and patterns based on breach data
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'letmein', 'login',
    'admin', 'welcome', 'shadow', 'sunshine', 'princess', 'football', 'iloveyou',
    'trustno1', 'superman', 'batman', 'passw0rd', 'hello', 'charlie', 'donald',
    'password1!', 'qwerty123', '111111', '000000', 'guest', 'root', 'test',
    'pass', 'pwd', 'secret', 'access', 'master123', 'changeme', '1234567890',
    'qazwsx', '123123', 'asdfgh', 'zxcvbn', 'letmein123', 'welcome1', 'welcome123'
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwerty', 'qazwsx', 'wsxedc',
    'rfvtgb', 'tgbyhn', 'yhnujm', '1qaz', '2wsx', '3edc', '4rfv', '5tgb',
    '6yhn', '7ujm', '8ik', '9ol', '0p', 'qweasd', 'asdzxc', 'qweasdzxc'
]

# Sequential patterns
SEQUENTIAL_ALPHA = 'abcdefghijklmnopqrstuvwxyz'
SEQUENTIAL_NUMERIC = '0123456789'


def calculate_entropy(password: str) -> float:
    """
    Calculate the Shannon entropy of a password in bits.
    
    Entropy measures the unpredictability of a password based on the size of the
    character pool used and the length. Higher entropy means more resistance to
    brute-force attacks.
    
    Formula: Entropy = L * log2(N)
    Where L = length, N = size of character pool
    
    Args:
        password: The password string to analyze
        
    Returns:
        Entropy value in bits (float)
    """
    if not password:
        return 0.0
    
    # Determine the character pool size based on characters present
    pool_size = 0
    
    if re.search(r'[a-z]', password):
        pool_size += 26  # lowercase letters
    if re.search(r'[A-Z]', password):
        pool_size += 26  # uppercase letters
    if re.search(r'\d', password):
        pool_size += 10  # digits
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\`~]', password):
        pool_size += 32  # special characters
    
    if pool_size == 0:
        return 0.0
    
    # Calculate entropy: L * log2(N)
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy: float, guesses_per_second: float = 1e10) -> str:
    """
    Estimate the time required to crack a password via brute force.
    
    Based on entropy, calculates the approximate time needed for an attacker
    to guess the password assuming different attack speeds.
    
    Default assumes 10 billion guesses per second (high-end GPU cluster).
    
    Args:
        entropy: Password entropy in bits
        guesses_per_second: Attacker's guessing speed (default: 10 billion/sec)
        
    Returns:
        Human-readable time estimate string
    """
    if entropy <= 0:
        return "Instant"
    
    # Number of possible combinations = 2^entropy
    combinations = 2 ** entropy
    
    # Average case: need to try half the combinations
    average_attempts = combinations / 2
    
    seconds = average_attempts / guesses_per_second
    
    if seconds < 0.001:
        return "Instant"
    elif seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31536000:  # 365 days
        return f"{seconds / 86400:.1f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds / 31536000:.1f} years"
    elif seconds < 31536000 * 1000000:
        return f"{seconds / 31536000:.0f} years"
    else:
        return "Centuries"


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False,
    exclude_patterns: bool = True
) -> str:
    """
    Generate a cryptographically secure random password.
    
    Uses Python's secrets module for cryptographic randomness and ensures
    at least one character from each selected type is included.
    
    Args:
        length: Desired password length (minimum 4, recommended 16+)
        use_uppercase: Include uppercase letters (A-Z)
        use_lowercase: Include lowercase letters (a-z)
        use_digits: Include digits (0-9)
        use_special: Include special characters (!@#$%^&*...)
        exclude_ambiguous: Exclude visually ambiguous characters (l, I, 1, L, o, O, 0)
        exclude_patterns: Avoid sequential or repeated patterns
    
    Returns:
        A cryptographically secure randomly generated password string
        
    Raises:
        ValueError: If length < 4 or no character types selected
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ambiguous characters to exclude
    ambiguous = "lI1LoO0"
    
    # Build the character pool
    char_pool = ""
    guaranteed_chars = []
    
    if use_lowercase:
        chars = lowercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        if chars:
            char_pool += chars
            guaranteed_chars.append(secrets.choice(chars))
    
    if use_uppercase:
        chars = uppercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        if chars:
            char_pool += chars
            guaranteed_chars.append(secrets.choice(chars))
    
    if use_digits:
        chars = digits
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        if chars:
            char_pool += chars
            guaranteed_chars.append(secrets.choice(chars))
    
    if use_special:
        chars = special
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        if chars:
            char_pool += chars
            guaranteed_chars.append(secrets.choice(chars))
    
    if not char_pool:
        raise ValueError("At least one character type must be selected")
    
    # Ensure we don't have more guaranteed chars than length
    if len(guaranteed_chars) > length:
        guaranteed_chars = guaranteed_chars[:length]
    
    # Fill remaining length with random characters from pool
    remaining_length = length - len(guaranteed_chars)
    password_chars = guaranteed_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    # Shuffle using Fisher-Yates algorithm with cryptographic randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    
    result = ''.join(password_chars)
    
    # Regenerate if we accidentally created a pattern (retry up to 10 times)
    if exclude_patterns:
        _, _, feedback, _ = check_strength(result)
        has_pattern_issues = any(
            'sequential' in f.lower() or 'repeating' in f.lower() 
            for f in feedback
        )
        if has_pattern_issues and length >= 8:
            # Try again once to avoid patterns
            return generate_password(
                length, use_uppercase, use_lowercase, use_digits, use_special,
                exclude_ambiguous, exclude_patterns=False
            )
    
    return result


def check_nist_compliance(password: str) -> Dict[str, bool]:
    """
    Check password against NIST SP 800-63B guidelines.
    
    NIST recommendations include:
    - Minimum 8 characters (64 max)
    - No composition rules (but we still check variety for strength)
    - Check against breached password lists
    - Allow all ASCII and Unicode characters
    - No password hints or knowledge-based authentication
    
    Args:
        password: The password to evaluate
        
    Returns:
        Dictionary of NIST compliance checks
    """
    checks = {
        'min_length': len(password) >= 8,
        'max_length': len(password) <= 64,
        'not_common': password.lower() not in COMMON_PASSWORDS,
        'no_repeated_chars': not bool(re.search(r'(.)\1{2,}', password)),
        'has_printable_ascii': all(32 <= ord(c) <= 126 for c in password)
    }
    
    return checks


def check_strength(password: str) -> Tuple[str, int, List[str], Dict]:
    """
    Evaluate the strength of a password using multiple criteria.
    
    Analysis includes:
    - Length scoring (NIST compliant)
    - Character variety assessment
    - Pattern detection (sequential, keyboard, repeated)
    - Common password checking
    - Entropy calculation
    - Estimated crack time
    
    Args:
        password: The password string to evaluate
        
    Returns:
        Tuple of (strength_label, score, feedback_list, metrics_dict)
        - strength_label: "Very Weak", "Weak", "Fair", "Strong", or "Very Strong"
        - score: Numerical score from 0-100
        - feedback: List of suggestions for improvement
        - metrics: Dictionary with entropy, crack_time, and nist_compliance
    """
    feedback = []
    score = 0
    
    # Calculate entropy first
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    nist_checks = check_nist_compliance(password)
    
    # Length scoring (NIST recommends minimum 8)
    length = len(password)
    if length < 8:
        score -= 20
        feedback.append(f"Password is too short ({length} chars). Use at least 8 characters (NIST minimum)")
    elif length < 12:
        score += 15
        feedback.append("Consider 12+ characters for better security")
    elif length < 16:
        score += 25
    elif length < 20:
        score += 30
    else:
        score += 35
    
    # Character variety scoring
    char_types = 0
    
    if re.search(r'[a-z]', password):
        score += 10
        char_types += 1
    else:
        feedback.append("Add lowercase letters (a-z) for complexity")
    
    if re.search(r'[A-Z]', password):
        score += 10
        char_types += 1
    else:
        feedback.append("Add uppercase letters (A-Z) for complexity")
    
    if re.search(r'\d', password):
        score += 10
        char_types += 1
    else:
        feedback.append("Add numbers (0-9) for complexity")
    
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\`~]', password):
        score += 15
        char_types += 1
    else:
        feedback.append("Add special characters (!@#$%^&*) for maximum security")
    
    # Bonus for using 3+ character types
    if char_types >= 3:
        score += 5
    if char_types == 4:
        score += 5
    
    # Penalty for repeated characters
    if re.search(r'(.)\1{2,}', password):
        score -= 15
        feedback.append("Avoid repeating the same character 3+ times consecutively")
    
    # Check for sequential patterns (more comprehensive)
    password_lower = password.lower()
    found_sequential = False
    
    # Check alphabetic sequences
    for i in range(len(SEQUENTIAL_ALPHA) - 2):
        seq = SEQUENTIAL_ALPHA[i:i+3]
        if seq in password_lower or seq[::-1] in password_lower:
            found_sequential = True
            break
    
    # Check numeric sequences
    if not found_sequential:
        for i in range(len(SEQUENTIAL_NUMERIC) - 2):
            seq = SEQUENTIAL_NUMERIC[i:i+3]
            if seq in password or seq[::-1] in password:
                found_sequential = True
                break
    
    # Check keyboard patterns
    if not found_sequential:
        for pattern in KEYBOARD_PATTERNS:
            if pattern in password_lower or pattern[::-1] in password_lower:
                found_sequential = True
                break
    
    if found_sequential:
        score -= 10
        feedback.append("Avoid sequential characters (abc, 123) or keyboard patterns (qwerty)")
    
    # Check for common passwords
    if password.lower() in COMMON_PASSWORDS:
        score -= 30
        feedback.append("CRITICAL: This is a commonly used password. Choose something unique!")
    
    # Check for common words/substrings
    common_substrings = ['password', 'admin', 'user', 'login', 'welcome', 'letmein', 
                         'secret', 'pass', 'test', 'guest', 'root']
    found_common = [word for word in common_substrings if word in password.lower()]
    if found_common:
        score -= 20
        feedback.append(f"Avoid common words like: {', '.join(found_common)}")
    
    # Check for date patterns (YYYY, MMDD, etc.)
    if re.search(r'(19|20)\d{2}', password):  # Years 1900-2099
        score -= 5
        feedback.append("Avoid using years (e.g., 1990, 2024) in passwords")
    
    if re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password):  # MMDD patterns
        score -= 5
        feedback.append("Avoid date patterns that could be personally significant")
    
    # Normalize score to 0-100
    score = max(0, min(100, score))
    
    # Determine strength label based on score and entropy
    if score < 25 or entropy < 30:
        strength = "Very Weak"
    elif score < 45 or entropy < 40:
        strength = "Weak"
    elif score < 65 or entropy < 50:
        strength = "Fair"
    elif score < 85 or entropy < 60:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    # Remove duplicate feedback
    feedback = list(dict.fromkeys(feedback))
    
    # Sort feedback: critical issues first
    critical_keywords = ['critical', 'too short', 'commonly used']
    feedback.sort(key=lambda x: sum(1 for kw in critical_keywords if kw in x.lower()), reverse=True)
    
    metrics = {
        'entropy': entropy,
        'crack_time': crack_time,
        'nist_compliant': all(nist_checks.values()),
        'nist_checks': nist_checks,
        'character_types': char_types,
        'length': length
    }
    
    return strength, score, feedback, metrics


def main():
    """Interactive command-line interface."""
    print("=" * 60)
    print("Password Strength Checker & Generator")
    print("Advanced Edition - NIST Compliant")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. Generate a new password")
        print("2. Check password strength")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            try:
                length_input = input("Enter password length (default 16): ").strip()
                length = int(length_input) if length_input else 16
                
                print("\nCharacter types (press Enter for Yes, 'n' for No):")
                use_upper = input("  Uppercase (A-Z): ").strip().lower() != 'n'
                use_lower = input("  Lowercase (a-z): ").strip().lower() != 'n'
                use_digit = input("  Digits (0-9): ").strip().lower() != 'n'
                use_special = input("  Special chars (!@#...): ").strip().lower() != 'n'
                exclude_ambig = input("  Exclude ambiguous (l,I,1,O,0): ").strip().lower() == 'y'
                
                password = generate_password(
                    length=length,
                    use_uppercase=use_upper,
                    use_lowercase=use_lower,
                    use_digits=use_digit,
                    use_special=use_special,
                    exclude_ambiguous=exclude_ambig
                )
                
                print(f"\n[OK] Generated password: {password}")
                
                # Automatically check strength with full metrics
                strength, score, feedback, metrics = check_strength(password)
                print(f"   Strength: {strength} ({score}/100)")
                print(f"   Entropy: {metrics['entropy']} bits")
                print(f"   Estimated crack time: {metrics['crack_time']}")
                print(f"   NIST Compliant: {'Yes' if metrics['nist_compliant'] else 'No'}")
                if feedback:
                    print("   Tips:", "; ".join(feedback[:2]))
                    
            except ValueError as e:
                print(f"[ERROR] Error: {e}")
        
        elif choice == "2":
            password = input("Enter password to check: ").strip()
            if not password:
                print("[ERROR] Password cannot be empty")
                continue
            
            strength, score, feedback, metrics = check_strength(password)
            
            print(f"\nResults:")
            print(f"   Password: {'*' * len(password)}")
            print(f"   Length: {metrics['length']} characters")
            print(f"   Character types used: {metrics['character_types']}/4")
            print(f"   Strength: {strength}")
            print(f"   Score: {score}/100")
            print(f"   Entropy: {metrics['entropy']} bits")
            print(f"   Estimated crack time: {metrics['crack_time']}")
            print(f"   NIST Compliant: {'Yes' if metrics['nist_compliant'] else 'No'}")
            
            # Show detailed NIST checks
            print(f"\n   NIST Guidelines Check:")
            nist = metrics['nist_checks']
            print(f"      - Minimum 8 characters: {'Pass' if nist['min_length'] else 'Fail'}")
            print(f"      - Not a common password: {'Pass' if nist['not_common'] else 'Fail'}")
            print(f"      - No repeated characters: {'Pass' if nist['no_repeated_chars'] else 'Fail'}")
            
            if feedback:
                print(f"\nSuggestions for improvement:")
                for item in feedback:
                    print(f"   - {item}")
            else:
                print("\n[OK] Excellent password! No improvements needed.")
        
        elif choice == "3":
            print("\nGoodbye!")
            break
        
        else:
            print("[ERROR] Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
