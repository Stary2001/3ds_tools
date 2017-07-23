from .aesengine import AESEngine
from .crypto_wrappers import aes_cbc_enc, aes_cbc_dec
import hashlib

class OTP:
	def __init__(self, data, dev=False):
		otp_key, otp_iv = AESEngine.get_otp_key(dev=dev)

		if data[0:4] == b'\x0f\xb0\xad\xde':
			# a valid, decrypted OTP
			self.initial_type = 'decrypted'
			self.decrypted = data
			self.encrypted = aes_cbc_enc(otp_key, otp_iv, data)
		else:
			# maybe it's encrypted?
			self.initial_type = 'encrypted'
			self.encrypted = data
			self.decrypted = aes_cbc_dec(otp_key, otp_iv, data)
			if self.decrypted[0:4] != b'\x0f\xb0\xad\xde':
				raise ValueError("Invalid OTP when decrypted!")		