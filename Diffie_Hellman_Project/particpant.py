"""
participant.py
Encapsulates participant identity, local state, ephemeral private exponents,
and shared secret computation.
"""

import secrets
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from modular_math import modular_exponentiation

class Participant:
    def __init__(self, name: str):
        self.name = name
        self.signing_private_key = ed25519.Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_private_key.public_key()
        
        # Ephemeral session state
        self.reset_session()

    def reset_session(self) -> None:
        self.private_exponent: Optional[int] = None
        self.public_value: Optional[int] = None
        self.local_nonce: Optional[str] = None
        self.peer_nonce: Optional[str] = None
        self.p: Optional[int] = None
        self.g: Optional[int] = None
        self.shared_secret: Optional[int] = None
        self.session_authenticated: bool = False
        self.session_active: bool = False

    def generate_exponent_and_public(self, p: int, g: int) -> int:
        """
        Picks private exponent in range [2, p - 2] via secrets.randbelow(p - 3) + 2.
        Computes public value = (g ^ exp) mod p.
        Retries if public value is outside [2, p - 2].
        """
        self.p = p
        self.g = g
        while True:
            exp = secrets.randbelow(p - 3) + 2
            pub = modular_exponentiation(g, exp, p)
            if 2 <= pub <= p - 2:
                self.private_exponent = exp
                self.public_value = pub
                return pub

    def compute_shared_secret(self, peer_public_value: int) -> int:
        if self.private_exponent is None or self.p is None:
            raise RuntimeError("Missing private exponent or modulus.")
        if not (2 <= peer_public_value <= self.p - 2):
            self.abort_session()
            raise ValueError("Peer public value falls outside acceptable interval [2, p-2].")
        
        secret = modular_exponentiation(peer_public_value, self.private_exponent, self.p)
        self.shared_secret = secret
        return secret

    def abort_session(self) -> None:
        self.reset_session()
