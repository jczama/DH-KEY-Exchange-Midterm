"""
parameters.py
Prime generation wrapper, modulus validation, trial division factorization,
and primitive root generator verification.
"""

import time
import secrets
from typing import Set, Tuple
from Crypto.Util.number import getPrime, isPrime
from modular_math import modular_exponentiation

def generate_prime(bits: int = 16) -> Tuple[int, float]:
    """
    Generates an exact bits-bit prime using pycryptodome with cryptographically
    secure randomness from python's secrets module. Measures elapsed time.
    """
    if type(bits) is not int or isinstance(bits, bool):
        raise TypeError("Bit length must be an integer.")
    if bits < 16 or bits > 32:
        raise ValueError("Prime bit length must be between 16 and 32 inclusive.")

    t0 = time.perf_counter()
    p = getPrime(bits, randfunc=secrets.token_bytes)
    duration = time.perf_counter() - t0

    # Verification: must have exact bit length and be odd (for bits >= 16)
    if p.bit_length() != bits:
        raise ValueError(f"Generated prime length {p.bit_length()} does not match requested {bits}")
    if p % 2 == 0:
        raise ValueError("Generated prime is even.")
    if not isPrime(p):
        raise ValueError("Generated candidate failed primality verification.")

    return p, duration


def validate_modulus(p: int, allow_fixture: bool = False) -> None:
    """
    Validates a received prime modulus p.
    """
    if type(p) is not int or isinstance(p, bool):
        raise TypeError("Modulus must be an integer.")

    if allow_fixture and p == 23:
        return

    bit_len = p.bit_length()
    if bit_len < 16 or bit_len > 32:
        raise ValueError(f"Modulus bit length {bit_len} out of allowed range [16, 32].")

    if not isPrime(p):
        raise ValueError(f"Received modulus {p} is composite or invalid.")


def prime_factors(n: int) -> Set[int]:
    """
    Finds all distinct prime factors of n using trial division up to sqrt(n).
    Accepts positive integers. For n=1, returns an empty set.
    """
    if type(n) is not int or isinstance(n, bool):
        raise TypeError("Input must be an integer.")
    if n <= 0:
        raise ValueError("Input must be a positive integer.")
    if n == 1:
        return set()

    factors = set()
    num = n

    # Step 1: Divide out 2s
    if num % 2 == 0:
        factors.add(2)
        while num % 2 == 0:
            num //= 2

    # Step 2: Odd divisors starting at 3
    d = 3
    while d * d <= num:
        if num % d == 0:
            factors.add(d)
            while num % d == 0:
                num //= d
        d += 2

    # Step 3: Remaining prime component
    if num > 1:
        factors.add(num)

    return factors


def is_generator(g: int, p: int, distinct_factors_p_minus_1: Set[int]) -> bool:
    """
    Checks if g is a primitive root modulo p.
    Criterion: For all prime factors r of p - 1, g^((p-1)/r) mod p != 1.
    """
    if not (2 <= g <= p - 2):
        return False
    for r in distinct_factors_p_minus_1:
        power = (p - 1) // r
        if modular_exponentiation(g, power, p) == 1:
            return False
    return True


def find_generator(p: int) -> Tuple[int, float]:
    """
    Finds the smallest primitive root generator g for prime modulus p.
    Measures search time.
    """
    t0 = time.perf_counter()
    factors = prime_factors(p - 1)
    for candidate in range(2, p - 1):
        if is_generator(candidate, p, factors):
            duration = time.perf_counter() - t0
            return candidate, duration
    raise RuntimeError(f"No primitive generator found for prime {p}")
