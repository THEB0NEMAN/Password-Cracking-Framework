import string
from zxcvbn import zxcvbn
import time
import hashlib
from itertools import product
from tqdm import tqdm

from hash_helpers import hash_password, verify_password, HASH_FUNCTIONS

def estimate_crack_time(password):
    """
    Estimate the time it would take to crack a password using zxcvbn.
    """
    result = zxcvbn(password)
    score = result['score']
    if result['crack_times_seconds']['offline_slow_hashing_1e4_per_second'] == 0:
        return "Instantly"
    else:
        return f"{result['crack_times_display']['offline_slow_hashing_1e4_per_second']}"

def dictionary_crack(hash_to_crack, dictionary, algorithm='sha256', **params):
    """
    Attempt to crack a password hash using a dictionary of common passwords.
    """
    start = time.time()
    with open(dictionary, 'r', encoding='utf-8', errors='ignore') as file:
        total_lines = sum(1 for _ in file)
        file.seek(0)  # Reset file pointer to the beginning

        for line in tqdm(file, total=total_lines, desc="Dictionary Crack", unit="Words"):
            password = line.strip()
            if verify_password(password, hash_to_crack, algorithm=algorithm, **params):
                elapsed = time.time() - start
                return password, elapsed
    return None, time.time() - start

def brute_force_crack(hash_to_crack, max_length=6, charset=string.ascii_letters + string.digits + string.punctuation,
                      algorithm='sha256', **params):
    """
    Attempt to brute-force crack a password hash with a progress bar.
    """
    start = time.time()
    charset_length = len(charset)

    try:
        for length in range(1, max_length + 1):
            total_combinations = charset_length ** length

            for guess_tuple in tqdm(product(charset, repeat=length), total=total_combinations,
                                    desc=f"Length {length}"):
                guess_password = ''.join(guess_tuple)
                if verify_password(guess_password, hash_to_crack, algorithm=algorithm, **params):
                    tqdm.write("")  # clean separation from progress bar
                    elapsed = time.time() - start
                    return guess_password, elapsed

    except KeyboardInterrupt:
        tqdm.write("\nBrute-force cracking interrupted by user.")
    return None, time.time() - start


if __name__ == "__main__":
    password = input("Enter a password to estimate crack time: ")
    estimated_time = estimate_crack_time(password)
    print(f"Estimated crack time for '{password}': {estimated_time}")

    algorithm = input("Enter hashing algorithm (argon2, bcrypt, scrypt, sha256): ").lower()
    if algorithm not in HASH_FUNCTIONS:
        print(f"Invalid algorithm '{algorithm}' specified. Defaulting to SHA-256.")
        algorithm = 'sha256'

    if algorithm in ('bcrypt', 'argon2'):
        print("Warning: dictionary and brute-force cracking will be very slow with this algorithm. ")


    hashed_password = hash_password(password, algorithm=algorithm)

    print("Attempting to crack the password using a dictionary of common passwords...")
    guess, actual_time = dictionary_crack(hashed_password, 'rockyou.txt', algorithm=algorithm)

    if guess:
        tqdm.write(f"Password '{password}' cracked using dictionary in {actual_time:.2f} seconds: {guess}")
    else:
        tqdm.write(f"Password '{password}' could not be cracked using the dictionary in {actual_time:.2f} seconds.")
        tqdm.write("")  # clean line before next progress bar

        brute_guess, brute_time = brute_force_crack(hashed_password, algorithm=algorithm)
        total_time = actual_time + brute_time

        if brute_guess:
            tqdm.write("")  # clean line before result
            tqdm.write(f"Password '{password}' cracked using brute force in {brute_time:.2f} seconds: {brute_guess}")
        else:
            tqdm.write("")
            tqdm.write(f"Password '{password}' could not be cracked using a dictionary or brute force in {total_time:.2f} seconds.")
