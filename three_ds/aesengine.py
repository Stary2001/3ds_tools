import os
from binascii import hexlify, unhexlify
import hashlib
from .crypto_wrappers import aes_cbc_enc, aes_cbc_dec, aes_ctr, aes_ctr_dsi, aes_ecb_dec
import struct

class AESEngine:
    b9 = None
    b9_keyblob_offset = None

    slots = {}
    keyx_slots = {}
    keyy_slots = {}
    cached_normalkeys = {}

    @staticmethod
    def init_keys(b9_path = None, otp_path = None, movable_path = None, dev = False):
        def set(slot, t, key):
            if t == "keyx":
                AESEngine.set(slot, keyx=key)
            elif t == "keyy":
                AESEngine.set(slot, keyy=key)
            elif t == "key":
                AESEngine.set(slot, key=key)

        if b9_path == None:
            b9_path = os.environ["HOME"] + "/.3ds/boot9.bin"
        if otp_path == None:
            otp_path = os.environ["HOME"] + "/.3ds/otp.bin"
        
        AESEngine.b9_keyblob_offset = 0x8000+0x5860
        if dev:
            AESEngine.b9_keyblob_offset += 0x400
        
        if b9_path == None:
            return

        b9 = open(b9_path, "rb")
        AESEngine.b9 = b9.read()
        b9.close()

        o = AESEngine.b9_keyblob_offset
        b9_keys = AESEngine.b9[o + 0x170: o + 0x170 + 16*38]

        key_ranges = [
        #    type    start end   repeat?
            ('keyx', 0x2c, 0x3c, True),
            ('keyx', 0x3c, 0x40, False),
            ('keyy', 0x04, 0x0c, False),
            ('key',  0x0c, 0x14, True),
            ('key',  0x14, 0x18, False),
            ('key',  0x18, 0x28, True),
            ('key',  0x28, 0x2c, False),
            ('key',  0x2c, 0x3c, True),
            ('key',  0x3c, 0x40, False)
        ]

        off = 0
        for k in key_ranges:
            step = 1
            if k[3] == True:
                step = 4

            for i in range(k[1], k[2], step):
                if k[3]:
                    for j in range(i,i+4):
                        set(j, k[0], b9_keys[off:off+16])
                    if k[0] != "key" or (i != 0x24 and i != 0x38):
                        # Don't advance the counter for the keyblocks before normalkey 0x28 and normalkey 0x3c because
                        # NINTENDO PLEASE
                        off += 16
                else:
                    set(i, k[0], b9_keys[off:off+16])
                    off += 16

        hardcoded_keys = [
            ('keyy', 0x24, unhexlify(b'74CA074884F4228DEB2A1CA72D287762'), 'all'),
            ('keyx', 0x25, unhexlify(b'CEE7D8AB30C00DAE850EF5E382AC5AF3'), 'retail'),
            ('keyx', 0x25, unhexlify(b'81907A4B6F1B47323A677974CE4AD71B'), 'dev'),
            ('keyy', 0x2f, unhexlify(b'C369BAA21E188A88A9AA94E5506A9F16'), 'retail'),
            ('keyy', 0x2f, unhexlify(b'7325C4EB143A0D5F5DB6E5C57A2195AC'), 'dev'),
            ('keyy', 0x05, unhexlify(b'4D804F4E9990194613A204AC584460BE'), 'all'),
        ]

        for k in hardcoded_keys:
            if k[3] == 'all':
                set(k[1], k[0], k[2])
            elif k[3] == 'retail' and not dev:
                set(k[1], k[0], k[2])
            elif k[3] == 'dev' and dev:
                set(k[1], k[0], k[2])

        otp = None
        if otp_path == None:
            return
        with open(otp_path, "rb") as f:
            otp = f.read()

        AESEngine.setup_console_unique_keys(otp, dev=dev)
        if movable_path == None:
            return
        
        movable = None
        with open(movable_path, "rb") as f:
            movable = f.read()

        AESEngine.setup_movable_sed_keys(movable)

    @staticmethod
    def get_otp_key(dev=False):
        otpkey_off = 0x56E0 + 0x8000
        if dev:
            otpkey_off += 0x20

        otp_key = AESEngine.b9[otpkey_off:otpkey_off+0x10]
        otp_iv = AESEngine.b9[otpkey_off+0x10:otpkey_off+0x20]
        return (otp_key, otp_iv)

    @staticmethod
    def setup_console_unique_keys(otp, dev=False):
        # is it already decrypted?
        d_otp = None
        if otp[0:4] == b'\x0f\xb0\xad\xde':
            d_otp = otp
        else:
            otp_key, otp_iv = AESEngine.get_otp_key(dev=dev)
            d_otp = aes_cbc_dec(otp_key, otp_iv, otp)

        twl_cid_lo, twl_cid_hi = struct.unpack("II", d_otp[0x08:0x10])
        twl_cid_lo ^= 0xB358A6AF
        twl_cid_lo |= 0x80000000
        twl_cid_hi ^= 0x08C267B7
        twl_cid_lo = struct.pack("I", twl_cid_lo)
        twl_cid_hi = struct.pack("I", twl_cid_hi)

        key3X = twl_cid_lo + b"NINTENDO" + twl_cid_hi
        key3Y = unhexlify(b"76DCB90AD3C44DBD1DDD2D200500A0E1")
        AESEngine.set(3, keyx=key3X)
        AESEngine.set(3, keyy=key3Y)

        o = AESEngine.b9_keyblob_offset
        b9_extra_data = AESEngine.b9[o:o+0x200]

        tmp_otp_dat = d_otp[0x90:0xac] + b9_extra_data[0:0x24]
        console_keyxy = hashlib.sha256(tmp_otp_dat).digest()

        console_keyx = console_keyxy[0:16]
        console_keyy = console_keyxy[16:32]
        console_normalkey = AESEngine.scramble_ctr(console_keyx, console_keyy)

        extra_data_off = 0

        def gen(n):
            nonlocal extra_data_off
            extra_data_off += 36
            iv = b9_extra_data[extra_data_off:extra_data_off+16]
            extra_data_off += 16

            data = aes_cbc_enc(console_normalkey, iv, b9_extra_data[extra_data_off:extra_data_off+64])

            extra_data_off += n
            return data

        a = gen(64)
        for i in range(0x4, 0x8):
            AESEngine.set(i, keyx=a[0:16])

        for i in range(0x8, 0xc):
            AESEngine.set(i, keyx=a[16:32])

        for i in range(0xc, 0x10):
            AESEngine.set(i, keyx=a[32:48])
        
        AESEngine.set(0x10, keyx=a[48:64])

        b = gen(16)
        off = 0
        for i in range(0x14, 0x18):
            AESEngine.set(i, keyx=b[off:off+16])
            off += 16

        c = gen(64)
        for i in range(0x18, 0x1c):
            AESEngine.set(i, keyx=c[0:16])
        
        for i in range(0x1c, 0x20):
            AESEngine.set(i, keyx=c[16:32])
        
        for i in range(0x20, 0x24):
            AESEngine.set(i, keyx=c[32:48])
        
        AESEngine.set(0x24, keyx=c[48:64])

        d = gen(16)
        off = 0

        for i in range(0x28, 0x2c):
            AESEngine.set(i, keyx=d[off:off+16])
            off += 16

    @staticmethod
    def setup_movable_sed_keys(movable):
        k = movable[0x110:0x120]
        AESEngine.set(0x30, keyy=k)
        AESEngine.set(0x34, keyy=k)
        AESEngine.set(0x3a, keyy=k)

    @staticmethod
    def set(slot, key=None, keyx=None, keyy=None):
        trace = False
        if key:
            if trace:
                print("0x{:X} normalkey={}".format(slot, hexlify(key).decode('ascii')))
            AESEngine.slots[slot] = key
        if keyx:
            if trace:
                print("0x{:X} keyX={}".format(slot, hexlify(keyx).decode('ascii')))
            AESEngine.keyx_slots[slot] = keyx
            if slot in AESEngine.keyy_slots:
                if slot > 0x3:
                    AESEngine.cached_normalkeys[slot] = AESEngine.scramble_ctr(keyx, AESEngine.keyy_slots[slot])
                else:
                    AESEngine.cached_normalkeys[slot] = AESEngine.scramble_twl(keyx, AESEngine.keyy_slots[slot])
        if keyy:
            if trace:
                print("0x{:X} keyY={}".format(slot, hexlify(keyy).decode('ascii')))
            AESEngine.keyy_slots[slot] = keyy
            if slot in AESEngine.keyx_slots:
                if slot > 0x3:
                    AESEngine.cached_normalkeys[slot] = AESEngine.scramble_ctr(AESEngine.keyx_slots[slot], keyy)
                else:
                    AESEngine.cached_normalkeys[slot] = AESEngine.scramble_twl(AESEngine.keyx_slots[slot], keyy)

    @staticmethod
    def scramble_ctr(keyX, keyY):
        keyX = int.from_bytes(keyX, 'big')
        keyY = int.from_bytes(keyY, 'big')

        #http://www.falatic.com/index.php/108/python-and-bitwise-rotation
        rol = lambda val, r_bits, max_bits: \
            (val << r_bits%max_bits) & (2**max_bits-1) | \
            ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
        normalkey = rol((rol(keyX, 2, 128) ^ keyY) + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87, 128)
        return normalkey.to_bytes(16, 'big')

    @staticmethod
    def scramble_twl(keyX, keyY):
        keyX = int.from_bytes(keyX, 'little')
        keyY = int.from_bytes(keyY, 'little')
        keyXY = keyX^keyY

        #http://www.falatic.com/index.php/108/python-and-bitwise-rotation
        rol = lambda val, r_bits, max_bits: \
            (val << r_bits%max_bits) & (2**max_bits-1) | \
            ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

        a = keyXY + 0xFFFEFB4E295902582A680F5F1A4F3E79
        a = rol(a, 42, 128)
        normalkey = a.to_bytes(16, 'little')
        return normalkey[::-1] # yes, dsi keys are reversed...

    @staticmethod
    def encrypt(mode, keyslot, data, iv=None):
        if mode == 'ecb':
            return aes_ecb_enc(AESEngine.cached_normalkeys[keyslot], data)
        elif mode == 'ctr':
            return aes_ctr(AESEngine.cached_normalkeys[keyslot], iv, data)
        elif mode == 'ctr-dsi':
            return aes_ctr_dsi(AESEngine.cached_normalkeys[keyslot], iv, data)

    @staticmethod
    def decrypt(mode, keyslot, data, iv=None):
        if mode == 'ecb':
            return aes_ecb_dec(AESEngine.cached_normalkeys[keyslot], data)
        elif mode == 'ctr':
            return aes_ctr(AESEngine.cached_normalkeys[keyslot], iv, data)
        elif mode == 'ctr-dsi':
            return aes_ctr_dsi(AESEngine.cached_normalkeys[keyslot], iv, data)
