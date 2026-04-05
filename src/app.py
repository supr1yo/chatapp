import sys
from src import crypto, network

def setup():
    mode = input("server/client: ").strip().lower()
    conn = network.connect(mode)

    # ECDH key exchange
    other_ecdh = network.exchange_pubkey(conn, crypto.ecdh_pub)
    shared_key = crypto.derive_shared_key(other_ecdh)

    # Signing key exchange 
    other_sign = network.exchange_pubkey(conn, crypto.sign_pub)

    # MITM fingerprint check
    print("\n=== VERIFY IDENTITY ===")
    print("Your fingerprint:\n", crypto.fingerprint(crypto.sign_pub))
    print("Peer  fingerprint:\n", crypto.fingerprint(other_sign))

    if input("\nDo fingerprints match? (yes/no): ").strip().lower() != "yes":
        # Warning and shutdown
        print("MITM ATTACK DETECTED! Closing connection.")
        conn.close()
        sys.exit(1)

    print("Secure connection established!\n")
    return conn, shared_key, other_sign