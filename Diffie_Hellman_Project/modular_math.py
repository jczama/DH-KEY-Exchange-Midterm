"""
modular_math.py
Custom square-and-multiply modular exponentiation implementation.
Does NOT rely on Python's built-in 3-argument pow() for algorithm execution.
"""

def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """
    Computes (base ^ exponent) % modulus using binary square-and-multiply.
    
    Validation rules:
      - base, exponent, and modulus must be exact integers (reject booleans and floats).
      - exponent >= 0
      - modulus > 0
    Returns an integer in the range [0, modulus - 1].
    """
    # Reject booleans (which are subclasses of int in Python) and non-integers
    if type(base) is not int or type(exponent) is not int or type(modulus) is not int:
        raise TypeError("Inputs base, exponent, and modulus must be strictly integers.")
    
    if exponent < 0:
        raise ValueError("Exponent must be non-negative.")
    
    if modulus <= 0:
        raise ValueError("Modulus must be strictly positive.")

    # Boundary: any number mod 1 is 0
    if modulus == 1:
        return 0

    result = 1 % modulus
    base = base % modulus

    exp = exponent
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exp //= 2

    return result
