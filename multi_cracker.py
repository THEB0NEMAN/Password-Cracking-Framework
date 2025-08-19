import time
import string
from itertools import product, islice
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
from functools import partial

from hash_helpers import verify_password

def dictionary_chunk_worker(password_chunk, hash_to_crack, algorithm, params):
    """
    Worker function for dictionary cracking.
    """
    for candidate_password in password_chunk:
        if verify_password(candidate_password, hash_to_crack, algorithm=algorithm, **params):
            return candidate_password
    return None

def brute_force_chunk_worker(tuple_chunk, hash_to_crack, algorithm, params):
    """
    Worker function for brute-force cracking.
    """
    for guess_tuple in tuple_chunk:
        guess_password = ''.join(guess_tuple)
        if verify_password(guess_password, hash_to_crack, algorithm=algorithm, **params):
            return guess_password
    return None

def chunker(iterable, chunk_size):
    it = iter(iterable)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk


def auto_chunk_size(total_candidates, processes=None, k=20):
    """
    Generic auto chunk size calculator.
    For dictionary attacks, k is fixed.
    For brute force, you should pass in a bigger k (or compute dynamically).
    """
    if processes is None:
        processes = cpu_count()

    return max(1, total_candidates // (processes * k))

def brute_force_k(length, base_k=50, growth=2.0):
    """
    Dynamically scale k based on password length.
    - base_k: starting multiplier for length=1
    - growth: exponential growth factor per length
    """
    return int(base_k * (growth ** (length - 1)))

def time_chunk(worker, guess_space, chunk_size, pool):
    """
    Time how long it takes to process one chunk with the given worker.
    """
    chunk = list(islice(guess_space, chunk_size))
    if not chunk:
        return None

    start = time.time()
    list(pool.imap_unordered(worker, [chunk], chunksize=1))  # process just this one chunk
    return time.time() - start

def auto_k(worker, charset, length, pool, target_time=(0.1, 0.5)):
    """
        Dynamically adjust k to get chunk runtimes in the target range.
    """
    k = 50  # start guess
    while True:
        guess_space = product(charset, repeat=length)
        elapsed = time_chunk(worker, guess_space, k, pool)
        if elapsed is None:
            break

        if elapsed < target_time[0]:  # too fast → increase chunk size
            k = int(k * 2)
        elif elapsed > target_time[1]:  # too slow → decrease chunk size
            k = max(1, int(k / 2))
        else:
            break

    return k

def multi_dictionary_crack(hash_to_crack, dictionary, algorithm='sha256', processes=None, **params):
    """
    Attempt to crack a password hash using a dictionary of common passwords with multiprocessing.
    """
    start = time.time()
    if processes is None:
        processes = cpu_count()

    with open(dictionary, 'r', encoding='utf-8', errors='ignore') as file:
        candidates = [line.strip() for line in file]

    chunk_size = auto_chunk_size(len(candidates), processes=processes)

    worker = partial(dictionary_chunk_worker, hash_to_crack=hash_to_crack, algorithm=algorithm, params=params)

    with Pool(processes=processes) as pool:
        for guess in tqdm(pool.imap_unordered(worker, chunker(candidates, chunk_size)),
            total=(len(candidates) + chunk_size - 1) // chunk_size, desc="Multi Dictionary Crack", unit="Word Chunks"):
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

    #chunk_size = 1000

    worker = partial(brute_force_chunk_worker, hash_to_crack=hash_to_crack, algorithm=algorithm, params=params)

    with Pool(processes=processes) as pool:
        for length in range(1, max_length + 1):
            total_combinations = charset_length ** length
            guess_space = product(charset, repeat=length)

            k = brute_force_k(length)
            chunk_size = auto_chunk_size(total_combinations, processes=processes, k=k)

            for guess in tqdm(pool.imap_unordered(worker, chunker(guess_space, chunk_size)),
                total=(total_combinations + chunk_size - 1) // chunk_size, desc=f"Length {length}"):
                if guess:
                    return guess, time.time() - start

    return None, time.time() - start
