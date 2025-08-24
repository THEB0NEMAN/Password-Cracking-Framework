import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt

def hash_argon2(password, **params):
    """
    Hash a password using Argon2.

    Args:
        password (str): The password to hash.
        **params: Additional parameters for Argon2 hashing.

    Returns:
        str: The Argon2 hashed password.
    """

    ph = PasswordHasher(**params)
    return ph.hash(password)

def verify_argon2(password, hash_password, **params):
    """
    Verify a password against an Argon2 hash.

    Args:
        password (str): The password to verify.
        hash_password (str): The Argon2 hashed password.
        **params: Additional parameters for Argon2 hashing.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """

    ph = PasswordHasher(**params)
    try:
        return ph.verify(hash_password, password)
    except VerifyMismatchError:
        return False

def hash_bcrypt(password, **params):
    """
    Hash a password using bcrypt.

    Args:
        password (str): The password to hash.
        **params: Additional parameters for bcrypt hashing (e.g., rounds).

    Returns:
        str: The bcrypt hashed password.
    """

    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(**params)).decode()

def verify_bcrypt(password, hash_password):
    """
    Verify a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hash_password (str): The bcrypt hashed password.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """

    return bcrypt.checkpw(password.encode(), hash_password.encode())

def hash_scrypt(password, **params):
    """
    Hash a password using scrypt.

    Args:
        password (str): The password to hash.
        **params: Additional parameters for scrypt hashing (e.g., salt, n, r, p).

    Returns:
        str: The scrypt hashed password in hexadecimal format.
    """
    return hashlib.scrypt(password.encode(), salt=params.get('salt', b'some_salt'),
                          n=params.get('n', 16384), r=params.get('r', 8), p=params.get('p', 1)).hex()

def verify_scrypt(password, hash_password, **params):
    """
    Verify a password against an scrypt hash.

    Args:
        password (str): The password to verify.
        hash_password (str): The scrypt hashed password in hexadecimal format.
        **params: Additional parameters for scrypt hashing (e.g., salt, n, r, p).

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """

    salt = params.get('salt', b'some_salt')
    computed_hash = hashlib.scrypt(password.encode(), salt=salt,
                                   n=params.get('n', 16384),
                                   r=params.get('r', 8),
                                   p=params.get('p', 1)).hex()
    return computed_hash == hash_password

def hash_sha256(password):
    """
    Hash a password using SHA-256.

    Args:
        password (str): The password to hash.

    Returns:
        str: The SHA-256 hashed password in hexadecimal format.
    """

    return hashlib.sha256(password.encode()).hexdigest()

def verify_sha256(password, hash_password):
    """
    Verify a password against an SHA-256 hash.

    Args:
        password (str): The password to verify.
        hash_password (str): The SHA-256 hashed password in hexadecimal format.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """

    return hashlib.sha256(password.encode()).hexdigest() == hash_password

HASH_FUNCTIONS = {
    'argon2': hash_argon2,
    'bcrypt': hash_bcrypt,
    'scrypt': hash_scrypt,
    'sha256': hash_sha256
}

VERIFY_FUNCTIONS = {
    'argon2': verify_argon2,
    'bcrypt': verify_bcrypt,
    'scrypt': verify_scrypt,
    'sha256': verify_sha256
}

def hash_password(password, algorithm='sha256', **params):
    """
    Hash a password using the specified algorithm.

    Args:
        password (str): The password to hash.
        algorithm (str): The hashing algorithm to use.
        **params: Additional parameters for the hashing algorithm.

    Returns:
        str: The hashed password.
    """

    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    return HASH_FUNCTIONS[algorithm](password, **params)



def verify_password(password, hash_password, algorithm='sha256', **params):
    """
    Verify a password against a hashed password using the specified algorithm.

    Args:
        password (str): The password to verify.
        hash_password (str): The hashed password to verify against.
        algorithm (str): The hashing algorithm to use.
        **params: Additional parameters for the hashing algorithm.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    if algorithm not in VERIFY_FUNCTIONS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    return VERIFY_FUNCTIONS[algorithm](password, hash_password, **params)
