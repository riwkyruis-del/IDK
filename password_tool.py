#!/usr/bin/env python3
"""
Password Strength Checker & Generator

Features:
- Generate secure random passwords with customizable length and character types
- Evaluate password strength based on length, character variety, and common patterns
- Provide actionable feedback for weak passwords
"""

import secrets
import string
import re
from typing import Tuple, List


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a cryptographically secure random password.
    
    Args:
        length: Desired password length (minimum 4)
        use_uppercase: Include uppercase letters (A-Z)
        use_lowercase: Include lowercase letters (a-z)
        use_digits: Include digits (0-9)
        use_special: Include special characters (!@#$%^&*...)
        exclude_ambiguous: Exclude ambiguous characters (l, I, 1, L, o, O, 0)
    
    Returns:
        A randomly generated password string
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
        char_pool += chars
        guaranteed_chars.append(secrets.choice(chars))
    
    if use_uppercase:
        chars = uppercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        char_pool += chars
        guaranteed_chars.append(secrets.choice(chars))
    
    if use_digits:
        chars = digits
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        char_pool += chars
        guaranteed_chars.append(secrets.choice(chars))
    
    if use_special:
        chars = special
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        char_pool += chars
        guaranteed_chars.append(secrets.choice(chars))
    
    if not char_pool:
        raise ValueError("At least one character type must be selected")
    
    # Fill remaining length with random characters from pool
    remaining_length = length - len(guaranteed_chars)
    password_chars = guaranteed_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    # Shuffle to avoid predictable positions of guaranteed characters
    # Using Fisher-Yates shuffle with secrets for cryptographic randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    
    return ''.join(password_chars)


def check_strength(password: str) -> Tuple[str, int, List[str]]:
    """
    Evaluate the strength of a password.
    
    Args:
        password: The password string to evaluate
    
    Returns:
        Tuple of (strength_label, score, list_of_feedback)
        - strength_label: "Very Weak", "Weak", "Fair", "Strong", or "Very Strong"
        - score: Numerical score from 0-100
        - feedback: List of suggestions for improvement
    """
    feedback = []
    score = 0
    
    # Check length
    length = len(password)
    if length < 8:
        feedback.append("Password is too short (minimum 8 characters recommended)")
    elif length < 12:
        score += 10
        feedback.append("Consider using 12+ characters for better security")
    elif length < 16:
        score += 20
    elif length < 20:
        score += 25
    else:
        score += 30
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("Add lowercase letters (a-z)")
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 10
    else:
        feedback.append("Add uppercase letters (A-Z)")
    
    # Check for digits
    if re.search(r'\d', password):
        score += 10
    else:
        feedback.append("Add numbers (0-9)")
    
    # Check for special characters
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        score += 15
    else:
        feedback.append("Add special characters (!@#$%^&*...)")
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times")
    
    # Check for sequential characters (abc, 123, etc.)
    sequential_patterns = [
        'abcdefghijklmnopqrstuvwxyz',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]
    
    password_lower = password.lower()
    for pattern in sequential_patterns:
        for i in range(len(pattern) - 2):
            if pattern[i:i+3].lower() in password_lower:
                score -= 5
                feedback.append("Avoid sequential characters (e.g., abc, 123, qwerty)")
                break
        else:
            continue
        break
    
    # Check for common patterns
    common_words = ['password', 'admin', 'user', 'login', 'welcome', 'letmein']
    if any(word in password.lower() for word in common_words):
        score -= 15
        feedback.append("Avoid common words like 'password', 'admin', etc.")
    
    # Normalize score to 0-100 range
    score = max(0, min(100, score))
    
    # Determine strength label
    if score < 20:
        strength = "Very Weak"
    elif score < 40:
        strength = "Weak"
    elif score < 60:
        strength = "Fair"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    # Remove duplicate feedback
    feedback = list(dict.fromkeys(feedback))
    
    return strength, score, feedback


def main():
    """Interactive command-line interface."""
    print("=" * 60)
    print("Password Strength Checker & Generator")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. Generate a new password")
        print("2. Check password strength")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            try:
                length = int(input("Enter password length (default 16): ").strip() or "16")
                
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
                
                # Automatically check strength
                strength, score, feedback = check_strength(password)
                print(f"   Strength: {strength} ({score}/100)")
                if feedback:
                    print("   Tips:", "; ".join(feedback[:2]))
                    
            except ValueError as e:
                print(f"[ERROR] Error: {e}")
        
        elif choice == "2":
            password = input("Enter password to check: ").strip()
            if not password:
                print("[ERROR] Password cannot be empty")
                continue
            
            strength, score, feedback = check_strength(password)
            
            print(f"\nResults:")
            print(f"   Password: {'*' * len(password)}")
            print(f"   Strength: {strength}")
            print(f"   Score: {score}/100")
            
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
