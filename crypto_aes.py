try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    class CtrAESCtx:
        __slots__ = ['encryptor', 'decryptor']

        def __init__(self, key, iv):
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
            self.encryptor = cipher.encryptor()
            self.decryptor = cipher.decryptor()

        def decrypt(self, data):
            return self.decryptor.update(data)

        def encrypt(self, data):
            return self.encryptor.update(data)


    class CbcAESCtx:
        __slots__ = ['encryptor', 'decryptor']

        def __init__(self, key, iv):
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            self.encryptor = cipher.encryptor()
            self.decryptor = cipher.decryptor()

        def decrypt(self, data):
            return self.decryptor.update(data)

        def encrypt(self, data):
            return self.encryptor.update(data)


    def create_aes_ctr(key, iv):
        return CtrAESCtx(key, iv)


    def create_aes_cbc(key, iv):
        return CbcAESCtx(key, iv)


    print("Using cryptography module")

except ImportError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter


        def create_aes_ctr(key, iv):
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            return AES.new(key, AES.MODE_CTR, counter=ctr)


        def create_aes_cbc(key, iv):
            return AES.new(key, AES.MODE_CBC, iv)


        print("Using pycrypto module")

    except ImportError:
        print("Failed to find pycrypto, using slow AES version", flush=True, file=sys.stderr)
        import pyaes


        def create_aes_ctr(key, iv):
            ctr = pyaes.Counter(int.from_bytes(iv, "big"))
            return pyaes.AESModeOfOperationCTR(key, ctr)


        def create_aes_cbc(key, iv):
            class EncryptorAdapter:
                def __init__(self, mode):
                    self.mode = mode

                def encrypt(self, data):
                    encrypter = pyaes.Encrypter(self.mode, pyaes.PADDING_NONE)
                    return encrypter.feed(data) + encrypter.feed()

                def decrypt(self, data):
                    decrypter = pyaes.Decrypter(self.mode, pyaes.PADDING_NONE)
                    return decrypter.feed(data) + decrypter.feed()

            mode = pyaes.AESModeOfOperationCBC(key, iv)
            return EncryptorAdapter(mode)
