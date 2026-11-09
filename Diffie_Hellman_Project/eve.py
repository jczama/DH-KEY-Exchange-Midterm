"""
eve.py
Simulates active adversary (Eve) performing:
  1. Classic MITM key exchange attack on unauthenticated Diffie-Hellman.
  2. Protocol tampering, credential spoofing, and replay attacks against
     the authenticated protocol.
"""

from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from modular_math import modular_exponentiation
from authentication import (
    parse_canonical_envelope,
    canonical_encode,
    sign_payload
)

class ActiveAdversaryEve:
    def __init__(self):
        self.signing_private_key = ed25519.Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_private_key.public_key()

    def simulate_unauthenticated_mitm(
        self,
        p: int,
        g: int,
        A: int,
        B: int,
        e1: int = 3,
        e2: int = 7
    ) -> Tuple[int, int, int, int]:
        """
        Demonstrates Eve intercepting unauthenticated DH.
        Eve injects E1 = g^e1 mod p towards Alice, and E2 = g^e2 mod p towards Bob.
        Computes independent shared secrets with Alice and Bob.
        """
        E1 = modular_exponentiation(g, e1, p)
        E2 = modular_exponentiation(g, e2, p)
        
        # Secret established with Alice: Eve calculates A^e1 mod p
        s_eve_alice = modular_exponentiation(A, e1, p)
        # Secret established with Bob: Eve calculates B^e2 mod p
        s_eve_bob = modular_exponentiation(B, e2, p)
        
        return E1, E2, s_eve_alice, s_eve_bob

    @staticmethod
    def tamper_public_value(response_bytes: bytes, replacement_B: int) -> bytes:
        """Modifies B in Bob's response message while retaining Bob's original signature."""
        env = parse_canonical_envelope(response_bytes)
        env["payload"]["transcript"]["B"] = replacement_B
        return canonical_encode(env)

    @staticmethod
    def tamper_prime_modulus(init_bytes: bytes, replacement_p: int) -> bytes:
        """Modifies prime modulus p in Alice's init message without modifying signature."""
        env = parse_canonical_envelope(init_bytes)
        env["payload"]["p"] = replacement_p
        return canonical_encode(env)

    @staticmethod
    def corrupt_signature(message_bytes: bytes) -> bytes:
        """Corrupts signature hex string."""
        env = parse_canonical_envelope(message_bytes)
        sig = env["signature"]
        # Flip the last hex digit
        corrupted = sig[:-1] + ('0' if sig[-1] != '0' else '1')
        env["signature"] = corrupted
        return canonical_encode(env)

    def forge_alice_signature_with_eve_key(self, init_bytes: bytes) -> bytes:
        """Signs Alice's initiation payload using Eve's untrusted signing key."""
        env = parse_canonical_envelope(init_bytes)
        forged_sig = sign_payload(self.signing_private_key, env["payload"])
        env["signature"] = forged_sig
        return canonical_encode(env)
