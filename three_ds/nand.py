from sys import argv
import struct
from .aesengine import AESEngine
from .crypt_file import CryptFile
import hashlib
from os import SEEK_CUR, SEEK_SET
from binascii import unhexlify

fs_type_map = [
	'none',
	'normal',
	'what',
	'firm',
	'agbsave'
]

keyslot_map = [
	[0x03, 0x04, 0x05],
	[None, None, None],
	[None, 0x06, None],
	[None, 0x07, None],
]

mode_map = [
	'none',
	'ctr',
	'what',
	'ctr',
	'none'
]

class NCSDPartition(CryptFile):
	def __init__(self, nand, fs_type, crypt_type, offset, length):
		super().__init__(nand)

		global keyslot_map

		self.type = fs_type_map[fs_type]
		self.fs_type = fs_type
		self.crypt_type = crypt_type
		self.offset = offset
		self.length = length
		self.keyslot = keyslot_map[fs_type-1][crypt_type-1]
		self.mode = mode_map[fs_type]
		if self.mode == 'ctr':
			if self.keyslot == 3:
				self.mode = 'ctr-dsi'
				self.iv = nand.twl_ctr
			else:
				self.iv = nand.ctr_ctr

		self.internal_offset = 0
		self.mbr = None
		self.real = self.upper.real

	def __str__(self):
		return "{} (crypto {}) using keyslot 0x{:02x} at {:x} - {:x}".format(self.type, self.crypt_type, self.keyslot, self.offset, self.offset + self.length)

class NCSD:
	def __init__(self, nand, partitions):
		self.partitions = []

		if nand.real == True:
			nand.seek(0)
			data = nand.read(0x200)
			if data[0x100:0x104] != b'NCSD':
				raise ValueError("Bad NCSD magic!")
			
			self.signature = data[0:0x100]
			
			for i in range(0, 8):
				if data[0x110+i] != 0:
					fs_type = data[0x110+i]
					crypt_type = data[0x118+i]
					offset, length = struct.unpack("II", data[0x120+i*8:0x128+i*8])
						
					# Media units... smh
					offset *= 0x200
					length *= 0x200

					p = NCSDPartition(nand, fs_type, crypt_type, offset, length)
					self.partitions.append(p)
		else:
			self.signature = unhexlify("6CF52F89F378120BFA4E1061D7361634D9A254A4F57AA5BD9F2C30934F0E68CBE6611D90D74CAAACB6A995565647333DC17092D320131089CCCD6331CB3A595D1BA299A32FF4D8E5DD1EB46A2A57935F6FE637322D3BC4F67CFED6C2254C089C62FA11D0824A844C79EE5A4F273D46C23BBBF0A2AF6ACADBE646F46B86D1289C7FF7E816CFDA4BC33DFF9D175AC69F72406C071B51F45A1ACB87F168C177CB9BE6C392F0341849AE5D510D26EEC1097BEBFB9D144A1647301BEAF9520D22C55AF46D49284CC7F9FBBA371A6D6E4C55F1E536D6237FFF54B3E9C11A20CFCCAC0C6B06F695766ACEB18BE33299A94CFCA7E258818652F7526B306B52E0AED04218")
			if partitions != None:
				self.partitions = partitions
	
	def pack(self):
		fs_types = [0] * 8
		crypt_types = [0] * 8
		off_len = [0] * 16
		twl = None
		for i, p in enumerate(self.partitions):
			fs_types[i] = p.fs_type
			crypt_types[i] = p.crypt_type
			off_len[i*2] = p.offset // 0x200
			off_len[i*2 + 1] = p.length // 0x200
			if p.keyslot == 3:
				twl = p

		return self.signature + b'NCSD' + struct.pack("<IQ16b16I", self.size // 0x200, 0, *fs_types, *crypt_types, *off_len) + b'\x00' * 160

class MBRPartition:
	def __init__(self, upper, type, offset, length):
		self.upper = upper
		self.type = type
		self.offset = offset
		self.length = length

	def seek(self, off, where=SEEK_SET):
		if off > self.length:
			raise ValueError("Offset outside partition!")

		self.upper.seek(off + self.offset, where)

	def read(self, count):
		return self.upper.read(count)

	def write(self, data):
		self.upper.write(data)

	def __str__(self):
		return "type {} at {:x}-{:x}".format(self.type, self.offset, self.offset + self.length)

class MBR:
	def __init__(self, nand, offset, partitions = None):
		self.partitions = []

		if nand.real:
			nand.seek(offset)
			data = nand.read(0x42)
			for i in range(0, 64, 16):
				p_type, p_start, p_len = struct.unpack("xxxxBxxxII",data[i:i+16])
				if p_type != 0:
					self.partitions.append(MBRPartition(nand, p_type, p_start * 0x200, p_len * 0x200))
		else:
			if partitions != None:
				self.partitions = partitions
	
	def pack(self):
		partition_infos = [0] * 16
		for i, p in enumerate(self.partitions):
			off = p.offset // 0x200
			length = p.length // 0x200
			# TODO: chs.
			partition_infos[i * 4]     = 0
			partition_infos[i * 4 + 1] = p.type
			partition_infos[i * 4 + 2] = off
			partition_infos[i * 4 + 3] = length

		return struct.pack("<16I", *partition_infos) + b'\x55\xaa'

class NANDImage:
	def __init__(self, filename = None, cid = None, partitions = None):
		self.twl_ctr = None
		self.ctr_ctr = None
		if cid != None:
			self.twl_ctr = hashlib.sha1(cid).digest()[0:16][::-1]
			self.ctr_ctr = hashlib.sha256(cid).digest()[0:16]

		if filename != None:
			self.f = open(filename, "rb")
			self.real = True
		else:
			self.real = False

		self.ncsd = NCSD(self, partitions=partitions)

		self.firm = []
		for p in self.ncsd.partitions:
			if p.type == 'firm':
				self.firm.append(p)
			elif p.type == 'normal':
				if p.keyslot == 3:
					self.twln_raw = p
					p.mbr = MBR(p, offset = 0x1be)
					self.twlnand = p.mbr.partitions[0]
					self.twlphoto = p.mbr.partitions[1]
				else:
					self.ctrn_raw = p
					p.mbr = MBR(p, offset = 0x1be)
					self.ctrnand = p.mbr.partitions[0]
			elif p.type == 'agbsave':
				self.agbsave = p

	def seek(self, off, what=SEEK_SET):
		self.f.seek(off, what)

	def read(self, len):
		return self.f.read(len)

	def write(self, dat):
		self.f.write(dat)