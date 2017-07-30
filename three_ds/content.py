from .aesengine import AESEngine
from .crypt_file import CryptFile
import hashlib
import re
from binascii import hexlify

cmac_types = {
	# name			keyslot, file off, cmac data
	"sd-extdata": (0x30, 0, b"CTR-EXT0"),
	"nand-extdata": (0x30, 0, b"CTR-EXT0"),
	"nand-save": (0x30, 0, b"CTR-SYS0"),
	"card-save": (0x33, 0, b"CTR-NOR0"),
	"sd-save": (0x30, 0, b"CTR-SIGN"),
	"savedata": (0x30, 0, b"CTR-SAV0"),
	"nand-db": (0x0b, 0, b"CTR-9DB0"),
	"sd-db": (0x30, 0, b"CTR-9DB0"),
	"nand-movable": (0x0b, 0x130),
	"nand-agbsave": (0x24, 0x10)
}

db_sids = {
	"ticket": 0,
	"certs": 1,
	"title": 2,
	"import": 3,
	"tmp_t": 4,
	"tmp_i": 5
}

class ContentFile:
	def __init__(self, path, sd = False):
		if sd:
			self.keyslot = 0x34
			self.mode = 'ctr'
			path_enc = path.lower().encode('UTF-16LE') + b"\x00\x00"
			path_hash = hashlib.sha256(path_enc).digest()
			self.iv = b''
			for i in range(0, 16):
				self.iv += (path_hash[i] ^ path_hash[i+16]).to_bytes(1, 'big')
		else:
			self.mode = 'none'

		global db_sids
		if sd:
			# SD extdata
			# xid_high, xid_low, fid_high, fid_low
			#"/extdata/%08lx/%08lx/%08lx/%08lx"
			match = re.match("/extdata/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})", path)
			if match:
				self.cmac_type = "sd-extdata"
				self.xid_high = int(match[1], 16).to_bytes(4, 'little')
				self.xid_low = int(match[2], 16).to_bytes(4, 'little')
				self.fid_high = int(match[3], 16).to_bytes(4, 'little')
				self.fid_low = int(match[4], 16).to_bytes(4, 'little')
				self.sid = b'\x01\x00\x00\x00'
				return

			# SD save
			# tid_high, tid_low, sid
			#"/title/%08lx/%08lx/data/%08lx.sav"
			match = re.match("/title/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/data/([0-9a-fA-F]{8,}).sav", path)
			if match:
				self.cmac_type = "sd-save"
				self.tid_high = int(match[1], 16).to_bytes(4, 'little')
				self.tid_low = int(match[2], 16).to_bytes(4, 'little')
				self.sid = int(match[3], 16).to_bytes(4, 'little')
				return

			match = re.match("/dbs/([a-z_]+).db", path)
			if match:
				self.cmac_type = "sd-db"
				self.sid = db_sids[match[1]].to_bytes(4, 'little')
				return

			self.cmac_type = None
		else:
			# NAND extdata
			# id0_high, id0_low, xid_high, xid_low, fid_high, fid_low
			# sid = 1
			#"/data/%016llx%016llx/extdata/%08lx/%08lx/%08lx/%08lx"
			match = re.match("/data/([0-9a-fA-F]{32,})/extdata/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})", path)
			if match:
				self.id0_high = int(match[1][0:16], 16).to_bytes(16, 'little')
				self.id0_low = int(match[1][16:32], 16).to_bytes(16, 'little')
				self.xid_high = int(match[2], 16).to_bytes(4, 'little')
				self.xid_low = int(match[3], 16).to_bytes(4, 'little')
				self.fid_high = int(match[4], 16).to_bytes(4, 'little')
				self.fid_low = int(match[5], 16).to_bytes(4, 'little')
				self.sid = b'\x01\x00\x00\x00'
				self.cmac_type = 'nand-extdata'
				return

			# Quota.dat:
			# same, but sid = 0 fid_low = 0; fid_high = 0;
			#"/data/%016llx%016llx/extdata/%08lx/%08lx/Quota.dat"

			match = re.match("/data/([0-9a-fA-F]{32,})/extdata/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})/Quota.dat", path)
			if match:
				self.id0_high = int(match[1][0:16], 16).to_bytes(16, 'little')
				self.id0_low = int(match[1][16:32], 16).to_bytes(16, 'little')
				self.xid_high = int(match[2], 16).to_bytes(4, 'little')
				self.xid_low = int(match[3], 16).to_bytes(4, 'little')
				self.fid_high = b'\x00\x00\x00\x00'
				self.fid_low = b'\x00\x00\x00\x00'
				self.sid = b'\x00\x00\x00\x00'
				self.cmac_type = 'nand-extdata'
				return

			# NAND savedata
			#id0_high, id0_low, fid_low, fid_high
			#"/data/%016llx%016llx/sysdata/%08lx/%08lx"
			match = re.match("/data/([0-9a-fA-F]{32,})/sysdata/([0-9a-fA-F]{8,})/([0-9a-fA-F]{8,})", path)
			if match:
				self.id0_high = int(match[1][0:16], 16).to_bytes(16, 'little')
				self.id0_low = int(match[1][16:32], 16).to_bytes(16, 'little')
				self.fid_low = int(match[2], 16).to_bytes(4, 'little')
				self.fid_high = int(match[3], 16).to_bytes(4, 'little')
				self.cmac_type = 'nand-save'
				return

			match = re.match("/dbs/([a-z_]+).db", path)
			if match:
				self.cmac_type = "nand-db"
				self.sid = db_sids[match[1]].to_bytes(4, 'little')
				return

			self.cmac_type = None

	def get_cmac(self):
		global cmac_types

		if self.cmac_type == "agbsave":
			pass
		elif self.cmac_type == "movable":
			pass
		else:
			hashdata = cmac_types[self.cmac_type][2]
			self.seek(0x100)
			disa = self.read(0x100)
			if self.cmac_type == "sd-extdata" or self.cmac_type == "nand-extdata":
				hashdata += self.xid_low
				hashdata += self.xid_high
				hashdata += self.sid
				hashdata += self.fid_low
				hashdata += self.fid_high
				hashdata += disa
			elif self.cmac_type == "sd-save":
				subhash = cmac_types["savedata"][2] + disa
				hashdata += self.tid_low
				hashdata += self.tid_high
				hashdata += hashlib.sha256(subhash).digest()
			elif self.cmac_type == "nand-save":
				hashdata += self.fid_low
				hashdata += self.fid_high
				hashdata += disa
			elif self.cmac_type == "sd-db" or self.cmac_type == "nand-db":
				hashdata += self.sid
				hashdata += disa

			cmac = AESEngine.cmac(cmac_types[self.cmac_type][0], hashlib.sha256(hashdata).digest())
			return cmac

class SDFile(CryptFile, ContentFile):
	def __init__(self, upper, relpath):
		CryptFile.__init__(self, upper)
		ContentFile.__init__(self, relpath, sd=True)

		self.keyslot = 0x34
		self.mode = 'ctr'
		path_enc = relpath.lower().encode('UTF-16LE') + b"\x00\x00"
		path_hash = hashlib.sha256(path_enc).digest()
		self.iv = b''
		for i in range(0, 16):
			self.iv += (path_hash[i] ^ path_hash[i+16]).to_bytes(1, 'big')

class NANDFile(CryptFile, ContentFile):
	def __init__(self, upper, relpath):
		CryptFile.__init__(self, upper)
		ContentFile.__init__(self, relpath, sd=False)