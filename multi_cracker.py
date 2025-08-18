import time
import string
from itertools import product
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
from functools import partial

from hash_helpers import verify_password

def dictionary_worker(candidate_password, hash_to_crack, algorithm, params):
    """
    Worker function for dictionary cracking.
    """
    if verify_password(candidate_password, hash_to_crack, algorithm=algorithm, **params):
        return candidate_password
    return None

def brute_force_worker(guess_tuple, hash_to_crack, algorithm, params):
    """
    Worker function for brute-force cracking.
    """
    guess_password = ''.join(guess_tuple)
    if verify_password(guess_password, hash_to_crack, algorithm=algorithm, **params):
        return guess_password
    return None

def multi_dictionary_crack(hash_to_crack, dictionary, algorithm='sha256', processes=None, **params):
    """
    Attempt to crack a password hash using a dictionary of common passwords with multiprocessing.
    """
    start = time.time()
    if processes is None:
        processes = cpu_count()

    with open(dictionary, 'r', encoding='utf-8', errors='ignore') as file:
        candidates = [line.strip() for line in file]

    worker = partial(dictionary_worker, hash_to_crack=hash_to_crack, algorithm=algorithm, params=params)

    with Pool(processes=processes) as pool:
        for guess in tqdm(pool.imap_unordered(worker, candidates),
            total=len(candidates), desc="Multi Dictionary Crack", unit="Words"):
            if guess:
                return guess, time.time() - start

    return None, time.time() - start

def multi_brute_force_crack(hash_to_crack, max_length=6,
                            charset=string.ascii_letters + string.digits + string.punctuation,
                            algorithm='sha256', processes=None, **params):
    """
    Attempt to brute-force crack a password hash with multiprocessing.
    """
    start = time.time()
    if processes is None:
        processes = cpu_count()

    charset_length = len(charset)

    worker = partial(brute_force_worker, hash_to_crack=hash_to_crack, algorithm=algorithm, params=params)

    with Pool(processes=processes) as pool:
        for length in range(1, max_length + 1):
            total_combinations = charset_length ** length
            guess_space = product(charset, repeat=length)

            for guess in tqdm(pool.imap_unordered(worker, guess_space),
                total=total_combinations, desc=f"Length {length}"):
                if guess:
                    return guess, time.time() - start

    return None, time.time() - start
