from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def create_aes_ctr(key, iv):
    class EncryptorAdapter:
        def __init__(self, cipher):
            self.encryptor = cipher.encryptor()
            self.decryptor = cipher.decryptor()

        def encrypt(self, data):
            return self.encryptor.update(data)

        def decrypt(self, data):
            return self.decryptor.update(data)

    iv_bytes = int.to_bytes(iv, 16, "big")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv_bytes), default_backend())
    return EncryptorAdapter(cipher)


def create_aes_cbc(key, iv):
    class EncryptorAdapter:
        def __init__(self, cipher):
            self.encryptor = cipher.encryptor()
            self.decryptor = cipher.decryptor()

        def encrypt(self, data):
            return self.encryptor.update(data)

        def decrypt(self, data):
            return self.decryptor.update(data)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    return EncryptorAdapter(cipher)
