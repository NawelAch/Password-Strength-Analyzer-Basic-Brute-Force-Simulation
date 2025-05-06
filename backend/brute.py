import itertools
import string
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

def brute_worker(target, target_hash, charset, length, start, end, found_flag, algorithm):
    for index, combo in enumerate(itertools.product(charset, repeat=length)):
        if index < start:
            continue
        if index >= end:
            break
        if found_flag["found"]:
            break

        attempt = ''.join(combo)
        attempt_hash = hashlib.new(algorithm, attempt.encode()).hexdigest()
        if attempt_hash == target_hash:
            found_flag["found"] = True
            found_flag["password"] = attempt
            return 1
    return 0

def split_range(total, threads):
    step = total // threads
    return [(i * step, (i + 1) * step if i != threads - 1 else total) for i in range(threads)]

def start_cracking(target_password, algorithm="sha256", min_length=1, max_length=6, charset=None, threads=4):
    charset = charset or string.ascii_letters + string.digits + string.punctuation
    found_flag = {"found": False, "password": None}
    start_time = time.time()
    target_hash = hashlib.new(algorithm, target_password.encode()).hexdigest()

    for length in range(min_length, max_length + 1):
        total = len(charset) ** length
        print(f"\n🔍 Trying length {length} ({total:,} combinations)")
        ranges = split_range(total, threads)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for start, end in ranges:
                futures.append(executor.submit(
                    brute_worker, 
                    target_password, 
                    target_hash,
                    charset, 
                    length, 
                    start, 
                    end, 
                    found_flag,
                    algorithm
                ))
            for future in as_completed(futures):
                if found_flag["found"]:
                    break

        if found_flag["found"]:
            break

    end_time = time.time()
    return {
        "success": found_flag["found"],
        "password": found_flag["password"],
        "time": end_time - start_time,
        "algorithm": algorithm
    }

def main():
    parser = argparse.ArgumentParser(description="🧠 Brute-force password cracker")
    parser.add_argument("password", help="The password to crack")
    parser.add_argument("-a", "--algorithm", default="sha256", choices=["sha256", "sha1", "md5"], 
                       help="Hash algorithm to use")
    parser.add_argument("-min", "--min-length", type=int, default=1, help="Minimum length to try")
    parser.add_argument("-max", "--max-length", type=int, default=6, help="Maximum length to try")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads to use")
    parser.add_argument("-cs", "--charset", default="full", choices=["lower", "upper", "digits", "full"], 
                       help="Charset to use")

    args = parser.parse_args()

    if args.charset == "lower":
        charset = string.ascii_lowercase
    elif args.charset == "upper":
        charset = string.ascii_uppercase
    elif args.charset == "digits":
        charset = string.digits
    else:
        charset = string.ascii_letters + string.digits + string.punctuation

    print(f"🔓 Cracking password: {args.password}")
    print(f"🔐 Algorithm: {args.algorithm}")
    print(f"🛠 Charset: {args.charset}, Threads: {args.threads}")
    print(f"📏 Length range: {args.min_length} to {args.max_length}")

    result = start_cracking(
        target_password=args.password,
        algorithm=args.algorithm,
        min_length=args.min_length,
        max_length=args.max_length,
        charset=charset,
        threads=args.threads
    )

    if result["success"]:
        print(f"\n✅ Password cracked: {result['password']}")
        print(f"⏱️ Time taken: {result['time']:.2f}s")
        print(f"🔑 Algorithm: {result['algorithm']}")
    else:
        print("\n❌ Failed to crack password.")

if __name__ == "__main__":
    main()