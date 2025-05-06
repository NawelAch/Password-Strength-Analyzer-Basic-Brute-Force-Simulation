import re
from zxcvbn import zxcvbn
import random
import string

def should_suggest_password(score, feedback):
    """Determine if we should suggest a password based on strength score and feedback"""
    return score < 3 or len(feedback) > 0  # Suggest if score < 3 (not strong) or has feedback

def generate_password(length=12):
    """Generate a strong password with mixed characters"""
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(random.choice(charset) for _ in range(length))
        # Ensure the generated password meets basic strength criteria
        if (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*" for c in password)):
            return password

def check_password_strength(password):
    # Regex analysis
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    # zxcvbn realistic strength estimation
    result = zxcvbn(password)
    score = result['score']  # 0-4
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    suggestions = result.get('feedback', {}).get('suggestions', [])

    # Only suggest password if not already strong
    suggested_password = None
    if should_suggest_password(score, suggestions):
        suggested_password = generate_password()
        suggestions.append(f"Try this strong password: {suggested_password}")

    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": score,
        "crack_time_display": crack_time,
        "suggestions": suggestions,
        "suggested_password": suggested_password
    }

if __name__ == "__main__":
    pw = input("Enter a password to test: ")
    result = check_password_strength(pw)
    print(f"\nPassword Analysis:")
    print(f"Length: {result['length']}")
    print(f"Contains uppercase: {result['has_upper']}")
    print(f"Contains lowercase: {result['has_lower']}")
    print(f"Contains digits: {result['has_digit']}")
    print(f"Contains symbols: {result['has_symbol']}")
    print(f"Strength score (0-4): {result['score']}")
    print(f"Estimated crack time: {result['crack_time_display']}")
    print("\nSuggestions:")
    for suggestion in result['suggestions']:
        print(f"- {suggestion}")
    if result['suggested_password']:
        print(f"\nSuggested strong password: {result['suggested_password']}")