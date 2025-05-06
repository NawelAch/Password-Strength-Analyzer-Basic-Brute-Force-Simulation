from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib
import re
from typing import Optional
import asyncio
import concurrent.futures
import time
import itertools
import string

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Warning: zxcvbn module not found. Using simplified strength checking.")
    zxcvbn = None

app = FastAPI(title="Password Strength Tester API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PasswordCheckRequest(BaseModel):
    password: str

class BruteForceRequest(BaseModel):
    password: str
    algorithm: str = "sha256"
    max_attempts: Optional[int] = 1000000

class PasswordStrengthResponse(BaseModel):
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    score: int
    crack_time_display: str
    strength_text: str
    suggestions: list

class BruteForceResponse(BaseModel):
    success: bool
    cracked_password: Optional[str] = None
    time_taken: float
    attempts: int
    algorithm: str

def check_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    if zxcvbn:
        result = zxcvbn(password)
        score = result['score']
        crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
        suggestions = result.get('feedback', {}).get('suggestions', [])
    else:
        score = 0
        if length >= 8: score += 1
        if has_upper and has_lower: score += 1
        if has_digit: score += 1
        if has_symbol: score += 1
        if length >= 12: score += 1
        score = min(score, 4)

        if score == 0: crack_time = "less than a second"
        elif score == 1: crack_time = "minutes"
        elif score == 2: crack_time = "hours"
        elif score == 3: crack_time = "months"
        else: crack_time = "centuries"

        suggestions = []
        if not has_upper: suggestions.append("Add uppercase letters")
        if not has_lower: suggestions.append("Add lowercase letters")
        if not has_digit: suggestions.append("Add numbers")
        if not has_symbol: suggestions.append("Add symbols")
        if length < 12: suggestions.append("Make your password longer")

    strength_texts = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": score,
        "crack_time_display": crack_time,
        "strength_text": strength_texts[score],
        "suggestions": suggestions
    }

def hash_password(password, algo='sha256'):
    h = hashlib.new(algo)
    h.update(password.encode())
    return h.hexdigest()

def detect_charset(password):
    charset = ''
    if any(c.isdigit() for c in password): charset += string.digits
    if any(c.islower() for c in password): charset += string.ascii_lowercase
    if any(c.isupper() for c in password): charset += string.ascii_uppercase
    if any(c in string.punctuation for c in password): charset += string.punctuation
    return charset

def brute_force_worker(charset, length, target_hash, algo, max_attempts, stop_flag):
    attempts = 0
    for guess in itertools.product(charset, repeat=length):
        if stop_flag['found'] or attempts >= max_attempts:
            break
        attempts += 1
        guess_pw = ''.join(guess)
        guess_hash = hash_password(guess_pw, algo)
        if guess_hash == target_hash:
            stop_flag['found'] = True
            stop_flag['password'] = guess_pw
            stop_flag['attempts'] = attempts
            break
    return attempts

async def brute_force_async(password, algo="sha256", max_attempts=1000000):
    length = len(password)
    charset = detect_charset(password)
    target_hash = hash_password(password, algo)

    if not charset or not password:
        return {
            "success": False,
            "cracked_password": None,
            "time_taken": 0,
            "attempts": 0,
            "algorithm": algo
        }

    stop_flag = {'found': False, 'password': None, 'attempts': 0}
    start_time = time.time()

    if len(charset) ** length <= 10000 or length <= 3:
        attempts = brute_force_worker(charset, length, target_hash, algo, max_attempts, stop_flag)
    else:
        loop = asyncio.get_event_loop()
        num_workers = min(8, length)
        chunk_size = max_attempts // num_workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for i in range(num_workers):
                worker_max = chunk_size if i < num_workers - 1 else max_attempts - (i * chunk_size)
                futures.append(
                    loop.run_in_executor(
                        executor,
                        brute_force_worker,
                        charset, length, target_hash, algo, worker_max, stop_flag
                    )
                )
            worker_attempts = await asyncio.gather(*futures)
            attempts = sum(worker_attempts)

    end_time = time.time()
    return {
        "success": stop_flag['found'],
        "cracked_password": stop_flag['password'],
        "time_taken": end_time - start_time,
        "attempts": stop_flag['attempts'] if stop_flag['found'] else attempts,
        "algorithm": algo
    }

@app.post("/check-password", response_model=PasswordStrengthResponse)
async def api_check_password(request: PasswordCheckRequest):
    if not request.password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")
    return check_password_strength(request.password)

@app.post("/brute-force", response_model=BruteForceResponse)
async def api_brute_force(request: BruteForceRequest):
    if not request.password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    if len(request.password) > 6:
        return {
            "success": False,
            "cracked_password": None,
            "time_taken": 0,
            "attempts": 0,
            "algorithm": request.algorithm,
        }

    if request.algorithm not in ["sha256", "sha1", "md5"]:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")

    return await brute_force_async(
        request.password,
        request.algorithm,
        min(request.max_attempts, 1000000)
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
