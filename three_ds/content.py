from .crypt_file import CryptFile
import hashlib

class SDFile(CryptFile):
	def __init__(self, upper, relpath):
		super().__init__(upper)
		self.keyslot = 0x34
		self.mode = 'ctr'
		path_enc = relpath.lower().encode('UTF-16LE') + b"\x00\x00"
		path_hash = hashlib.sha256(path_enc).digest()
		self.iv = b''
		for i in range(0, 16):
			self.iv += (path_hash[i] ^ path_hash[i+16]).to_bytes(1, 'big')