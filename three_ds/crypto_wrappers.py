from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct
import sys

def aes_cbc_enc(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_cbc_dec(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def aes_ctr(key, ctr, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def aes_cmac(key, data):
    backend = default_backend()
    cmac = CMAC(algorithms.AES(key), backend=backend)
    return cmac.update(data) + cmac.finalize()

def xor(a, b):
    a = a[:len(b)]
    int_var = int.from_bytes(a, sys.byteorder)
    int_key = int.from_bytes(b, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(a), sys.byteorder)

def aes_ctr_dsi(key, ctr, data):
    pad = aes_ctr(key, ctr, b'\x00' * len(data))

    data_dec = b""
    for i in range(0, len(data), 0x10):
        data_dec += xor(pad[i:i+16][::-1], data[i:i+16])
    return data_dec

def aes_ecb_enc(key, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def aes_ecb_dec(key, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()