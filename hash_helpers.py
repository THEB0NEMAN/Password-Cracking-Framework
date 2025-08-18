import time
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt

def hash_argon2(password, **params):
    """
    Hash a password using Argon2.
    """
    ph = PasswordHasher(**params)
    return ph.hash(password)

def verify_argon2(password, hash_password, **params):
    """
    Verify a password against an Argon2 hash.
    """
    ph = PasswordHasher(**params)
    try:
        return ph.verify(hash_password, password)
    except VerifyMismatchError:
        return False

def hash_bcrypt(password, **params):
    """
    Hash a password using bcrypt.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(**params)).decode()

def verify_bcrypt(password, hash_password, **params):
    return bcrypt.checkpw(password.encode(), hash_password.encode())

def hash_scrypt(password, **params):
    """
    Hash a password using scrypt.
    """
    return hashlib.scrypt(password.encode(), salt=params.get('salt', b'some_salt'),
                          n=params.get('n', 16384), r=params.get('r', 8), p=params.get('p', 1)).hex()

def verify_scrypt(password, hash_password, **params):
    salt = params.get('salt', b'some_salt')
    computed_hash = hashlib.scrypt(password.encode(), salt=salt,
                                   n=params.get('n', 16384),
                                   r=params.get('r', 8),
                                   p=params.get('p', 1)).hex()
    return computed_hash == hash_password

def hash_sha256(password):
    """
    Hash a password using SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def verify_sha256(password, hash_password):
    """
    Verify a password against a SHA-256 hash.
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
    """
    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    return HASH_FUNCTIONS[algorithm](password, **params)



def verify_password(password, hash_password, algorithm='sha256', **params):
    """
    Verify a password against a hashed password using the specified algorithm.
    """
    if algorithm not in VERIFY_FUNCTIONS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    return VERIFY_FUNCTIONS[algorithm](password, hash_password, **params)
