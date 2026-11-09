"""
main.py
Demonstrates:
  1. Textbook classroom fixture run (p=23, g=5, a=6, b=15).
  2. Unauthenticated Eve MITM attack.
  3. Authenticated runs at 16, 24, and 32 bits with time measurements.
  4. Active adversary tampering and rejection.
"""

from authentication import IdentityKeyStore
from participant import Participant
from parameters import generate_prime, find_generator
from protocol import (
    create_init_message,
    process_init_and_create_response,
    process_response_and_create_finish,
    process_finish
)
from eve import ActiveAdversaryEve
from modular_math import modular_exponentiation

def run_worked_fixture_demo():
    print("================================================================================")
    print(" 1. WORKED MATHEMATICAL FIXTURE DEMO (Classroom teaching example: p=23, g=5)")
    print("================================================================================")
    p, g = 23, 5
    a, b = 6, 15
    keystore = IdentityKeyStore()
    alice = Participant("Alice")
    bob = Participant("Bob")
    keystore.register("Alice", alice.signing_public_key)
    keystore.register("Bob", bob.signing_public_key)

    msg1 = create_init_message(alice, "Bob", p, g, fixed_exp=a)
    print(f"Alice sent Init: p={p}, g={g}, a={a}, A={alice.public_value}, nonce_A={alice.local_nonce[:8]}...")

    msg2 = process_init_and_create_response(bob, msg1, keystore, allow_fixture=True, fixed_exp=b)
    print(f"Bob sent Response: b={b}, B={bob.public_value}, nonce_B={bob.local_nonce[:8]}...")

    msg3 = process_response_and_create_finish(alice, msg2, keystore)
    print(f"Alice verified Bob. Alice S_A = {alice.shared_secret}. Alice sent Finish.")

    process_finish(bob, msg3, keystore)
    print(f"Bob verified Alice. Bob S_B = {bob.shared_secret}.")
    print(f"Transcript authenticated: YES | Shared secret match: {alice.shared_secret == bob.shared_secret}")
    print(f"Explicit key confirmation: NOT IMPLEMENTED\n")


def run_unauthenticated_eve_mitm():
    print("================================================================================")
    print(" 2. UNAUTHENTICATED DIFFIE-HELLMAN MITM ATTACK")
    print("================================================================================")
    p, g = 23, 5
    a, b = 6, 15
    A = modular_exponentiation(g, a, p) # 8
    B = modular_exponentiation(g, b, p) # 19

    eve = ActiveAdversaryEve()
    e1, e2 = 3, 7
    E1, E2, s_eve_alice, s_eve_bob = eve.simulate_unauthenticated_mitm(p, g, A, B, e1, e2)

    # Alice receives E1=10 believing it's from Bob
    alice_s = modular_exponentiation(E1, a, p)
    # Bob receives E2=17 believing it's from Alice
    bob_s = modular_exponentiation(E2, b, p)

    print(f"Parameters: p={p}, g={g}")
    print(f"Alice computed A = {A} (private a={a})")
    print(f"Bob computed B = {B} (private b={b})")
    print(f"Eve intercepts messages. Eve generates e1={e1} (E1={E1}) and e2={e2} (E2={E2})")
    print(f"Alice receives E1: Alice computes secret = {E1}^{a} mod {p} = {alice_s}")
    print(f"Eve computes with Alice: secret = {A}^{e1} mod {p} = {s_eve_alice}")
    print(f"Bob receives E2: Bob computes secret = {E2}^{b} mod {p} = {bob_s}")
    print(f"Eve computes with Bob: secret = {B}^{e2} mod {p} = {s_eve_bob}")
    print(f"Alice and Bob hold different secrets! Eve decrypts/relays both.\n")


def run_benchmarks():
    print("================================================================================")
    print(" 3. SUCCESSFUL GENERATED EXCHANGES & BENCHMARKS (16, 24, 32 bits)")
    print("================================================================================")
    print(f"{'Bits':<6}{'Trial':<7}{'Prime Gen (s)':<16}{'Factorization (s)':<20}{'Gen Search (s)':<17}{'Auth':<8}{'Match':<8}")
    print("-" * 82)

    for bits in [16, 24, 32]:
        for trial in range(1, 4):
            keystore = IdentityKeyStore()
            alice = Participant("Alice")
            bob = Participant("Bob")
            keystore.register("Alice", alice.signing_public_key)
            keystore.register("Bob", bob.signing_public_key)

            p, prime_time = generate_prime(bits)
            import time
            from parameters import prime_factors
            t_f0 = time.perf_counter()
            _ = prime_factors(p - 1)
            factor_time = time.perf_counter() - t_f0

            g, gen_time = find_generator(p)

            msg1 = create_init_message(alice, "Bob", p, g)
            msg2 = process_init_and_create_response(bob, msg1, keystore)
            msg3 = process_response_and_create_finish(alice, msg2, keystore)
            process_finish(bob, msg3, keystore)

            auth_ok = alice.session_authenticated and bob.session_authenticated
            match_ok = alice.shared_secret == bob.shared_secret

            print(f"{bits:<6}{trial:<7}{prime_time:<16.6f}{factor_time:<20.6f}{gen_time:<17.6f}{str(auth_ok):<8}{str(match_ok):<8}")
    print()


def run_attack_tampering_demonstration():
    print("================================================================================")
    print(" 4. DEMONSTRATE EVE'S ATTACK AGAINST AUTHENTICATED PROTOCOL")
    print("================================================================================")
    keystore = IdentityKeyStore()
    alice = Participant("Alice")
    bob = Participant("Bob")
    keystore.register("Alice", alice.signing_public_key)
    keystore.register("Bob", bob.signing_public_key)

    p, _ = generate_prime(16)
    g, _ = find_generator(p)
    msg1 = create_init_message(alice, "Bob", p, g)
    msg2 = process_init_and_create_response(bob, msg1, keystore)

    eve = ActiveAdversaryEve()
    tampered_msg2 = eve.tamper_public_value(msg2, replacement_B=17)
    
    print("Eve intercepted Message 2 and modified Bob's public value B to 17...")
    try:
        process_response_and_create_finish(alice, tampered_msg2, keystore)
        print("ERROR: Alice accepted tampered value!")
    except ValueError as e:
        print(f"Alice rejected Bob response: {e}")
        print("Alice session aborted, usable state cleared, secret discarded.")
        print(f"Alice shared secret: {alice.shared_secret} | Session authenticated: {alice.session_authenticated}\n")


if __name__ == "__main__":
    run_worked_fixture_demo()
    run_unauthenticated_eve_mitm()
    run_benchmarks()
    run_attack_tampering_demonstration()
