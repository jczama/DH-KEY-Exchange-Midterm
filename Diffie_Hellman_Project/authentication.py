"""
authentication.py
Ed25519 identity key generation, signing, verification, and deterministic
JSON canonical encoding.
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

MAX_MESSAGE_SIZE = 4096


def canonical_encode(data: Dict[str, Any]) -> bytes:
    """
    Deterministic canonical serialization: UTF-8, keys sorted, compact delimiters.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_canonical_envelope(message_bytes: bytes) -> Dict[str, Any]:
    """
    Enforces maximum message size and strictly parses JSON envelopes.
    Rejects duplicate JSON keys.
    """
    if len(message_bytes) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message exceeds maximum size limit of {MAX_MESSAGE_SIZE} bytes.")

    def _reject_duplicates(ordered_pairs):
        d = {}
        for k, v in ordered_pairs:
            if k in d:
                raise ValueError(f"Duplicate key detected in JSON payload: {k}")
            d[k] = v
        return d

    text = message_bytes.decode("utf-8")
    return json.loads(text, object_pairs_hook=_reject_duplicates)


class IdentityKeyStore:
    """
    Maintains long-term trusted Ed25519 verification keys.
    """
    def __init__(self):
        self._keys: Dict[str, ed25519.Ed25519PublicKey] = {}

    def register(self, name: str, public_key: ed25519.Ed25519PublicKey) -> None:
        self._keys[name] = public_key

    def get(self, name: str) -> ed25519.Ed25519PublicKey:
        if name not in self._keys:
            raise KeyError(f"No trusted identity key registered for: {name}")
        return self._keys[name]


def sign_payload(signing_key: ed25519.Ed25519PrivateKey, payload_dict: Dict[str, Any]) -> str:
    """
    Signs canonical JSON bytes and returns the hex signature.
    """
    canonical_bytes = canonical_encode(payload_dict)
    raw_sig = signing_key.sign(canonical_bytes)
    return raw_sig.hex()


def verify_payload_signature(
    verification_key: ed25519.Ed25519PublicKey,
    payload_dict: Dict[str, Any],
    hex_signature: str
) -> bool:
    """
    Verifies signature against canonical JSON representation.
    Returns True if valid; raises InvalidSignature or returns False on failure.
    """
    canonical_bytes = canonical_encode(payload_dict)
    try:
        sig_bytes = bytes.fromhex(hex_signature)
        verification_key.verify(sig_bytes, canonical_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False
