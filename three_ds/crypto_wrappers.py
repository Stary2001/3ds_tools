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

def aes_ctr_buff(key, ctr, data, buff):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update_into(data, buff) #+ decryptor.finalize()

def aes_cmac(key, data):
    backend = default_backend()
    cmac = CMAC(algorithms.AES(key), backend=backend)
    cmac.update(data)
    return cmac.finalize()

def aes_ctr_dsi(key, ctr, data):
    l = len(data)

    data_rev = bytearray(l)
    data_out = bytearray(l + 16)
    for i in range(0, len(data), 0x10):
        data_rev[i:i+0x10] = data[i:i+0x10][::-1]

    aes_ctr_buff(key, ctr, bytes(data_rev), data_out)

    for i in range(0, len(data), 0x10):
        data_out[i:i+0x10] = data_out[i:i+0x10][::-1]
    return data_out[0:l]

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
