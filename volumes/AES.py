import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import pad, unpad

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        cipher = AES.new(self.key, AES.MODE_CBC)
        padtext = pad(plain_text, AES.block_size)
        ctext = cipher.encrypt(padtext)
        encodedctext= base64.standard_b64encode(ctext)
        return encodedctext, cipher.iv

    def decrypt(self, encrypted_text, iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decodedctext = base64.standard_b64decode(encrypted_text)
        padded_plaintext = cipher.decrypt(decodedctext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext
        