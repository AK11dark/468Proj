from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_file(content, key):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()

    ciphertext = encryptor.update(content) + encryptor.finalize()
    tag = encryptor.tag

    return {
        "iv": iv,
        "tag": tag,
        "ciphertext": ciphertext
    }
