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

    Args:
        password_chunk (list): A chunk of passwords to test.
        hash_to_crack (str): The hash to crack.
        algorithm (str): The hashing algorithm used.
        params (dict): Additional parameters for the hashing algorithm.

    Returns:
        str or None: The cracked password if found, else None.
    """
    for candidate_password in password_chunk:
        if verify_password(candidate_password, hash_to_crack, algorithm=algorithm, **params):
            return candidate_password
    return None

def brute_force_chunk_worker(tuple_chunk, hash_to_crack, algorithm, params):
    """
    Worker function for brute-force cracking.

    Args:
        tuple_chunk (list): A chunk of password tuples to test.
        hash_to_crack (str): The hash to crack.
        algorithm (str): The hashing algorithm used.
        params (dict): Additional parameters for the hashing algorithm.

    Returns:
        str or None: The cracked password if found, else None.
    """
    for guess_tuple in tuple_chunk:
        guess_password = ''.join(guess_tuple)
        if verify_password(guess_password, hash_to_crack, algorithm=algorithm, **params):
            return guess_password
    return None

def chunker(iterable, chunk_size):
    """
    Yield successive n-sized chunks from iterable.

    Args:
        iterable (iterable[T]): Supplied iterable object.
        chunk_size (int): Size of each chunk.

    Returns:
        Generator[List[T]]: Chunks of the iterable.
    """
    it = iter(iterable)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk


def auto_chunk_size(total_candidates, k=20, processes=None):
    """
    Calculate an optimal chunk size for multiprocessing.

    Args:
        total_candidates (int): Number of items to process (e.g., len(dictionary)).
        k (int): Number of chunks per core (default=20).
        processes (int): Number of worker processes (defaults to cpu_count()).

    Returns:
        int: Recommended chunk size.
    """
    if processes is None:
        processes = cpu_count()

    # Avoid divide-by-zero, and ensure at least 1
    chunk_size = max(1, total_candidates // (processes * k))
    return chunk_size

def multi_dictionary_crack(hash_to_crack, dictionary, algorithm='sha256', processes=None, **params):
    """
    Attempt to crack a password hash using a dictionary of common passwords with multiprocessing.

    Args:
        hash_to_crack (str): The hash to crack.
        dictionary (str): Path to the dictionary file.
        algorithm (str): The hashing algorithm used.
        processes (int): Number of worker processes (defaults to cpu_count()).
        params (dict): Additional parameters for the hashing algorithm.

    Returns:
        str or None: The cracked password if found, else None, prompting a change to brute force attack.
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

    Args:
        hash_to_crack (str): The hash to crack.
        max_length (int): Maximum length of passwords to try.
        charset (str): Characters to use in brute-force attempts.
        algorithm (str): The hashing algorithm used.
        processes (int): Number of worker processes (defaults to cpu_count()).
        params (dict): Additional parameters for the hashing algorithm.

    Returns:
        str or None: The cracked password if found, else None.
    """
    start = time.time()
    if processes is None:
        processes = cpu_count()

    charset_length = len(charset)

    worker = partial(brute_force_chunk_worker, hash_to_crack=hash_to_crack, algorithm=algorithm, params=params)

    with Pool(processes=processes) as pool:
        for length in range(1, max_length + 1):
            total_combinations = charset_length ** length
            guess_space = product(charset, repeat=length)

            base_k = 20  # starting value for length 1
            growth_factor = 3.5  # how fast k scales with length
            k = int(base_k * (growth_factor ** (length - 1)))

            chunk_size = auto_chunk_size(total_combinations, k, processes=processes)

            for guess in tqdm(pool.imap_unordered(worker, chunker(guess_space, chunk_size)),
                total=(total_combinations + chunk_size - 1) // chunk_size, desc=f"Length {length}"):
                if guess:
                    return guess, time.time() - start

    return None, time.time() - start
