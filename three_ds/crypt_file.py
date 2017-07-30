from .aesengine import AESEngine
from os import SEEK_SET, SEEK_END

class CryptFile:
	def __init__(self, upper):
		self.upper = upper
		self.offset = 0
		self.internal_offset = 0

	def __len__(self):
		if hasattr(self, 'length'):
			return self.length
		else:
			self.upper.seek(0, SEEK_END)
			l = self.upper.tell()
			self.upper.seek(0)
			return l

	def seek(self, offset, where=SEEK_SET):
		self.internal_offset = offset
		off = self.offset + self.internal_offset
		self.upper.seek(off, where)

	def read(self, count):
		off = self.offset + self.internal_offset

		before = off % 16
		after = (off + count) % 16
		if count%16 != 0:
			count = count + 16-count%16

		enc = self.upper.read(count)
		enc = b'\x00' * before + enc + b'\x00' * after

		if self.mode == 'none':
			return enc

		iv = None
		if self.mode == 'ctr' or self.mode == 'ctr-dsi':
			if not self.iv:
				raise ValueError("Missing a CTR!")

			off = off // 16
			iv = self.iv

			iv = int.from_bytes(iv, 'big')
			iv += off
			iv = iv.to_bytes(16, 'big')
			self.internal_offset += count

		data = AESEngine.decrypt(self.mode, self.keyslot, enc, iv=iv)
		if before != 0:
			data = data[before:]
		if after != 0:
			data = data[:-after]
		return data

	def write(self, data):
		if self.mode == 'none':
			self.upper.write(data)
			return

		count = len(data)
		off = self.offset + self.internal_offset

		before = off % 16
		after = (off + count) % 16
		if count%16 != 0:
			count = count + 16-count%16
		data = b'\x00' * before + data + b'\x00' * after

		iv = None
		if self.mode == 'ctr' or self.mode == 'ctr-dsi':
			if not self.upper.ctr_ctr:
				raise ValueError("No NAND CTR!")

			off = off // 16
			iv = None
			if self.keyslot > 0x3:
				iv = self.upper.ctr_ctr
			else:
				iv = self.upper.twl_ctr

			iv = int.from_bytes(iv, 'big')
			iv += off
			iv = iv.to_bytes(16, 'big')

		data = AESEngine.encrypt(self.mode, self.keyslot, data, iv=iv)
		if before != 0:
			data = data[before:]
		if after != 0:
			data = data[:-after]

		self.internal_offset += len(data)
		self.upper.write(data)
