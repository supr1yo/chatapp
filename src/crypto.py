import os, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ECDH keys (for key exchange)
ecdh_priv = ec.generate_private_key(ec.SECP256R1())
ecdh_pub  = ecdh_priv.public_key()

# ECDSA keys (for signing)
sign_priv = ec.generate_private_key(ec.SECP256R1())
sign_pub  = sign_priv.public_key()

def fingerprint(pubkey):
    data = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fp = hashlib.sha256(data).hexdigest()
    return ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

def derive_shared_key(other_pub):
    secret = ecdh_priv.exchange(ec.ECDH(), other_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat'
    ).derive(secret)

def encrypt(msg, key):
    aes   = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, msg.encode(), None)

def decrypt(data, key):
    aes = AESGCM(key)
    return aes.decrypt(data[:12], data[12:], None).decode()

def sign(data):
    return sign_priv.sign(data, ec.ECDSA(hashes.SHA256()))

def verify(data, sig, pub):
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False