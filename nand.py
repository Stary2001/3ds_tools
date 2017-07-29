import argparse
from three_ds.nand import NANDImage, NCSD, NCSDPartition, MBR, MBRPartition
from three_ds.aesengine import AESEngine
from binascii import unhexlify
import progressbar
import os

def extract(name, p, off=0, len=None):
	bar = progressbar.ProgressBar()

	p.seek(off)
	if len == None:
		blk = 0x10000
		num = p.length // blk
	else:
		blk = len
		num = 1

	with open(name, 'wb') as f:
		i = 0
		
		last = 0
		for i in bar(range(0, num)):
			f.write(p.read(blk))

parser = argparse.ArgumentParser(description='3DS NAND backup extraction/packing tool.')
parser.add_argument('action', metavar='action', type=str, help='extract')
parser.add_argument('file', metavar='file', type=str, help='NAND filename')
parser.add_argument('--cid', metavar='cid', type=str, help='NAND CID in hex')
parser.add_argument('--otp', metavar='otp', type=str, help='OTP path')
parser.add_argument('--ctr', action='store_true', help='extract ctrnand')
parser.add_argument('--twln', action='store_true', help='extract twln')
parser.add_argument('--twlp', action='store_true', help='extract twlp')
parser.add_argument('--twlmbr', action='store_true', help='extract twl mbr')
parser.add_argument('--firm', type=str, default=None, help='extract firms')
parser.add_argument('--agb', action='store_true', help='extract agbsave')
parser.add_argument('--new3ds', action='store_true', help='is new3ds?')
parser.add_argument('--boot9', metavar='boot9', type=str, default=None, help='boot9 path')

args = parser.parse_args()

if args.otp == None:
	print("No OTP! It is required!")
	exit()
if args.cid == None:
	print("No NAND CID! It is required!")
	exit()

AESEngine.init_keys(otp_path = args.otp, b9_path=args.boot9)
if args.action == 'extract':
	n = NANDImage(args.file, cid=unhexlify(args.cid))
	if args.ctr:
		print("Extracting CTRNAND...")
		extract('ctrnand_dec.fat', n.ctrnand)
	if args.twln:
		print("Extracting TWLNAND...")
		extract('twlnand_dec.fat', n.twlnand)
	if args.twlp:
		print("Extracting TWLPHOTO...")
		extract('twlphoto_dec.fat', n.twlphoto)
	if args.twlmbr:
		print("Extracting TWL MBR...")
		extract('twl_mbr.bin', n.ncsd.partitions[0], off=0x1be, len=0x42)
	if args.firm:
		f = args.firm.split(',')
		for firm in f:
			firm = int(firm)
			print("Extracting FIRM{}...".format(firm))
			extract('firm{}_dec.bin'.format(firm), n.firm[firm])
	if args.agb:
		extract('agbsave_dec.bin', n.agbsave)
elif args.action == 'list':
	n = NANDImage(args.file, cid=unhexlify(args.cid))
	for p in n.ncsd.partitions:
		print(p)
		if p.mbr:
			for pp in p.mbr.partitions:
				print("    " + str(pp))
elif args.action == 'create':
	n = NANDImage(cid=unhexlify(args.cid))

	def round_sector(s):
		if s % 0x200 != 0:
			s = s + 0x200 - s % 0x200
		return s
	twln_inject_file = 'new/twlnand_dec.fat'
	twlp_inject_file = 'new/twlphoto_dec.fat'
	ctrn_inject_file = 'new/ctrnand_dec.fat'

	twln_fat_sz = round_sector(os.stat(twln_inject_file).st_size)
	twlp_fat_sz = round_sector(os.stat(twlp_inject_file).st_size)
	ctrn_fat_sz = round_sector(os.stat(ctrn_inject_file).st_size)
	
	twln = NCSDPartition(n, fs_type=1, crypt_type=1, offset=0, length=twln_fat_sz + twlp_fat_sz + 0x200)
	twln.mbr = MBR(twln, offset=0x1be)
	twln_fat = MBRPartition(twln, type=6, offset=0x200, length=twln_fat_sz)
	twlp = MBRPartition(twln, type=6, offset=twln_fat_sz+0x200, length=twlp_fat_sz)
	twln.mbr.partitions.append(twln_fat)
	twln.mbr.partitions.append(twlp)

	curr = twln_fat_sz + twlp_fat_sz + 0x200
	agb = NCSDPartition(n, fs_type=4, crypt_type=2, offset=curr, length=0x30000)
	curr += 0x30000
	firm0 = NCSDPartition(n, fs_type=3, crypt_type=2, offset=curr, length=0x400000)
	curr += 0x400000
	firm1 = NCSDPartition(n, fs_type=3, crypt_type=2, offset=curr, length=0x400000)
	curr += 0x400000
	ctrn = NCSDPartition(n, fs_type=1, crypt_type=2, offset=curr, length=ctrn_fat_sz + 0x200)
	curr += ctrn_fat_sz + 0x200
	ctrn.mbr = MBR(ctrn, offset=0x1be)
	ctrnand = MBRPartition(ctrn, type=6, offset=0x200, length=ctrn_fat_sz)
	ctrn.mbr.partitions.append(ctrnand)

	n.ncsd.size = curr

	n.ncsd.partitions.append(twln)
	n.ncsd.partitions.append(agb)
	n.ncsd.partitions.append(firm0)
	n.ncsd.partitions.append(firm1)
	n.ncsd.partitions.append(ctrn)

	for p in n.ncsd.partitions:
		print(p)
		if p.mbr:
			for pp in p.mbr.partitions:
				print("    " + str(pp))

	# Write MBRs and NCSD header out...
	n.f = open('new_nand.bin', 'wb')
	n.f.seek(0)
	n.f.write(n.ncsd.pack())
	twln.seek(0x1be)
	twln.write(twln.mbr.pack())
	ctrn.seek(0x1be)
	ctrn.write(ctrn.mbr.pack())

	def copy(fn, p, sz):
		import os
		print("Writing ", fn)
		p.seek(0)
		blk = 0x10000
		bar = progressbar.ProgressBar()

		with open(fn, 'rb') as f:
			f.seek(0, os.SEEK_END)
			f_len = f.tell()
			f.seek(0)
			n = f_len // blk
			for i in bar(range(0, n)):
				p.write(f.read(blk))

	copy(twln_inject_file, twln_fat, twln_fat_sz)
	copy(twlp_inject_file, twlp, twlp_fat_sz)
	copy(ctrn_inject_file, ctrnand, ctrn_fat_sz)
	copy('new/firm0_dec.bin', firm0, 0x400000)
	copy('new/firm1_dec.bin', firm1, 0x400000)
	copy('new/agbsave_dec.bin', agb, 0x30000)