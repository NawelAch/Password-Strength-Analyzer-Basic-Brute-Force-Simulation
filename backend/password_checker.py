import re
from zxcvbn import zxcvbn

def check_password_strength(password):
    # Regex analysis
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    print(f"Length: {length}")
    print(f"Contains uppercase: {has_upper}")
    print(f"Contains lowercase: {has_lower}")
    print(f"Contains digits: {has_digit}")
    print(f"Contains symbols: {has_symbol}")

    # zxcvbn realistic strength estimation
    result = zxcvbn(password)
    score = result['score']  # 0-4
    print(f"zxcvbn score (0-4): {score}")
    print(f"Estimated crack time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")

if __name__ == "__main__":
    pw = input("Enter a password to test: ")
    check_password_strength(pw)