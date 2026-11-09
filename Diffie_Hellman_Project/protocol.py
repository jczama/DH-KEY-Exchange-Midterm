"""
protocol.py
Executes the 3-message authenticated Diffie-Hellman exchange:
  Msg 1 (init):     Alice -> Bob (payload: protocol, message_type='init', initiator, responder, p, g, A, nonce_A)
  Msg 2 (response): Bob -> Alice (payload: message_type='response', transcript={...})
  Msg 3 (finish):   Alice -> Bob (payload: message_type='finish', transcript={...})
"""

import secrets
from typing import Dict, Any, Tuple
from parameters import validate_modulus, prime_factors, is_generator
from authentication import (
    IdentityKeyStore,
    sign_payload,
    verify_payload_signature,
    canonical_encode,
    parse_canonical_envelope
)
from participant import Participant

PROTOCOL_LABEL = "DH-CLASSROOM-AUTH-v1"


def create_init_message(alice: Participant, bob_name: str, p: int, g: int, fixed_exp: int = None) -> bytes:
    alice.reset_session()
    alice.session_active = True
    alice.p = p
    alice.g = g
    alice.local_nonce = secrets.token_bytes(32).hex()

    if fixed_exp is not None:
        alice.private_exponent = fixed_exp
        from modular_math import modular_exponentiation
        alice.public_value = modular_exponentiation(g, fixed_exp, p)
    else:
        alice.generate_exponent_and_public(p, g)

    payload = {
        "protocol": PROTOCOL_LABEL,
        "message_type": "init",
        "initiator": alice.name,
        "responder": bob_name,
        "p": alice.p,
        "g": alice.g,
        "A": alice.public_value,
        "nonce_A": alice.local_nonce
    }
    signature = sign_payload(alice.signing_private_key, payload)
    envelope = {"payload": payload, "signature": signature}
    return canonical_encode(envelope)


def process_init_and_create_response(
    bob: Participant,
    message_bytes: bytes,
    keystore: IdentityKeyStore,
    allow_fixture: bool = False,
    fixed_exp: int = None
) -> bytes:
    bob.reset_session()
    bob.session_active = True

    envelope = parse_canonical_envelope(message_bytes)
    payload = envelope["payload"]
    signature = envelope["signature"]

    # 1. Message structure & expected labels
    if payload.get("protocol") != PROTOCOL_LABEL or payload.get("message_type") != "init":
        bob.abort_session()
        raise ValueError("Invalid protocol label or message type.")
    if payload.get("responder") != bob.name:
        bob.abort_session()
        raise ValueError("Responder name mismatch.")

    initiator = payload.get("initiator")
    p = payload.get("p")
    g = payload.get("g")
    A = payload.get("A")
    nonce_A = payload.get("nonce_A")

    if not isinstance(p, int) or not isinstance(g, int) or not isinstance(A, int):
        bob.abort_session()
        raise TypeError("Mathematical parameters must be integers.")
    if not isinstance(nonce_A, str) or len(nonce_A) != 64:
        bob.abort_session()
        raise ValueError("Invalid nonce_A format.")

    # 2. Verify signature using Alice's trusted key
    alice_trusted_pub = keystore.get(initiator)
    if not verify_payload_signature(alice_trusted_pub, payload, signature):
        bob.abort_session()
        raise ValueError("Alice initiation signature verification failed.")

    # 3. Parameter validation
    validate_modulus(p, allow_fixture=allow_fixture)
    factors = prime_factors(p - 1)
    if not is_generator(g, p, factors):
        bob.abort_session()
        raise ValueError(f"Value {g} is not a valid generator mod {p}.")
    if not (2 <= A <= p - 2):
        bob.abort_session()
        raise ValueError("Public value A out of bounds.")

    # Store validated parameters in Bob's session
    bob.p = p
    bob.g = g
    bob.peer_nonce = nonce_A
    bob.local_nonce = secrets.token_bytes(32).hex()

    if fixed_exp is not None:
        bob.private_exponent = fixed_exp
        from modular_math import modular_exponentiation
        bob.public_value = modular_exponentiation(g, fixed_exp, p)
    else:
        bob.generate_exponent_and_public(p, g)

    # 4. Construct complete transcript
    transcript = {
        "protocol": PROTOCOL_LABEL,
        "initiator": initiator,
        "responder": bob.name,
        "p": p,
        "g": g,
        "A": A,
        "B": bob.public_value,
        "nonce_A": nonce_A,
        "nonce_B": bob.local_nonce
    }
    bob.pending_transcript = transcript
    bob.peer_public_value = A

    response_payload = {
        "message_type": "response",
        "transcript": transcript
    }
    resp_sig = sign_payload(bob.signing_private_key, response_payload)
    resp_envelope = {"payload": response_payload, "signature": resp_sig}
    return canonical_encode(resp_envelope)


def process_response_and_create_finish(
    alice: Participant,
    message_bytes: bytes,
    keystore: IdentityKeyStore
) -> bytes:
    if not alice.session_active:
        raise RuntimeError("Alice has no active session.")

    envelope = parse_canonical_envelope(message_bytes)
    payload = envelope["payload"]
    signature = envelope["signature"]

    if payload.get("message_type") != "response":
        alice.abort_session()
        raise ValueError("Invalid message type.")

    transcript = payload.get("transcript", {})
    responder = transcript.get("responder")
    bob_trusted_pub = keystore.get(responder)

    # 1. Verify Bob's signature over the response payload
    if not verify_payload_signature(bob_trusted_pub, payload, signature):
        alice.abort_session()
        raise ValueError("Bob response signature verification failed.")

    # 2. Confirm session fields match Alice's pending session exactly
    if (
        transcript.get("protocol") != PROTOCOL_LABEL or
        transcript.get("initiator") != alice.name or
        transcript.get("p") != alice.p or
        transcript.get("g") != alice.g or
        transcript.get("A") != alice.public_value or
        transcript.get("nonce_A") != alice.local_nonce
    ):
        alice.abort_session()
        raise ValueError("Transcript mismatch with pending Alice session.")

    B = transcript.get("B")
    nonce_B = transcript.get("nonce_B")
    if not isinstance(B, int) or not (2 <= B <= alice.p - 2):
        alice.abort_session()
        raise ValueError("Invalid peer public value B.")
    if not isinstance(nonce_B, str) or len(nonce_B) != 64:
        alice.abort_session()
        raise ValueError("Invalid nonce_B.")

    alice.peer_nonce = nonce_B
    alice.session_transcript = transcript
    alice.compute_shared_secret(B)
    alice.session_authenticated = True

    # 3. Create Finish message signing the complete transcript
    finish_payload = {
        "message_type": "finish",
        "transcript": transcript
    }
    finish_sig = sign_payload(alice.signing_private_key, finish_payload)
    finish_envelope = {"payload": finish_payload, "signature": finish_sig}
    return canonical_encode(finish_envelope)


def process_finish(
    bob: Participant,
    message_bytes: bytes,
    keystore: IdentityKeyStore
) -> None:
    if not bob.session_active or not hasattr(bob, "pending_transcript"):
        raise RuntimeError("Bob has no pending session.")

    envelope = parse_canonical_envelope(message_bytes)
    payload = envelope["payload"]
    signature = envelope["signature"]

    if payload.get("message_type") != "finish":
        bob.abort_session()
        raise ValueError("Expected finish message type.")

    transcript = payload.get("transcript")
    alice_trusted_pub = keystore.get(bob.pending_transcript["initiator"])

    # 1. Verify Alice's signature on the finish payload
    if not verify_payload_signature(alice_trusted_pub, payload, signature):
        bob.abort_session()
        raise ValueError("Alice finish signature verification failed.")

    # 2. Require exact agreement with Bob's pending transcript
    if canonical_encode(transcript) != canonical_encode(bob.pending_transcript):
        bob.abort_session()
        raise ValueError("Finished transcript does not match pending transcript.")

    # 3. Complete exchange and compute secret
    bob.compute_shared_secret(bob.peer_public_value)
    bob.session_authenticated = True
    bob.session_active = False  # Completed session
