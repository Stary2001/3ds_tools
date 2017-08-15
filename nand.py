import argparse
from three_ds.nand import NANDImage, NCSD, NCSDPartition, MBR, MBRPartition
from three_ds.aesengine import AESEngine
from binascii import unhexlify
import progressbar
import os
import math

def extract(name, p, off=0, len=None):
	bar = progressbar.ProgressBar()

	p.seek(off)
	if len == None:
		blk = 0x10000
		num = math.ceil(p.length / blk)
	else:
		blk = len
		num = 1

	with open(name, 'wb') as f:
		i = 0
		
		last = 0
		for i in bar(range(0, num)):
			f.write(p.read(blk))

def inject(fn, p):
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

parser = argparse.ArgumentParser(description='3DS NAND backup extraction/packing tool.')
parser.add_argument('--boot9', metavar='boot9', type=str, default=None, help='boot9 path')
parser.add_argument('--cid', metavar='cid', type=str, help='NAND CID in hex')
parser.add_argument('--otp', metavar='otp', type=str, help='OTP path')

subparsers = parser.add_subparsers(help='actions')
extract_options = subparsers.add_parser("extract")
extract_options.add_argument('--ctr', action='store_true', help='extract ctrnand')
extract_options.add_argument('--twln', action='store_true', help='extract twln')
extract_options.add_argument('--twlp', action='store_true', help='extract twlp')
extract_options.add_argument('--twlmbr', action='store_true', help='extract twl mbr')
extract_options.add_argument('--firm', type=str, default=None, help='extract firms')
extract_options.add_argument('--agb', action='store_true', help='extract agbsave')
extract_options.add_argument('file', metavar='file', type=str, help='NAND filename')
extract_options.set_defaults(action='extract')

inject_options = subparsers.add_parser("inject")
inject_options.add_argument('--ctr', type=str, default=None, help='ctrnand to inject')
inject_options.add_argument('--twln', type=str, default=None, help='twln to inject')
inject_options.add_argument('--twlp', type=str, default=None, help='twlp to inject')
inject_options.add_argument('--twlmbr',type=str, default=None, help='twl mbr to inject')
inject_options.add_argument('--firm', type=str, default=None, help='firms to inject')
inject_options.add_argument('--agb', type=str, default=None, help='agbsave to inject')
inject_options.add_argument('file', metavar='file', type=str, help='NAND filename')
inject_options.set_defaults(action='inject')

create_options = subparsers.add_parser("create")
create_options.add_argument('--ctr', type=str, default=None, help='ctrnand to use')
create_options.add_argument('--twln', type=str, default=None, help='twln to use')
create_options.add_argument('--twlp', type=str, default=None, help='twlp to use')
create_options.add_argument('--twlmbr',type=str, default=None, help='twl mbr to use')
create_options.add_argument('--firm', type=str, help='firms to use', required=True)
create_options.add_argument('--agb', type=str, default=None, help='agbsave to use')
create_options.add_argument('file', metavar='file', type=str, help='NAND filename')
create_options.set_defaults(action='create')

list_options = subparsers.add_parser("list")
list_options.set_defaults(action='list')
list_options.add_argument('file', metavar='file', type=str, help='NAND filename')

args = parser.parse_args()

if args.cid == None:
	print("No NAND CID! It is required!")
	exit()

success, what = AESEngine.init_keys(otp_path = args.otp, b9_path=args.boot9, required = ('otp'))
if not success:
	print("Missing " + what + "!")
	exit()

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
elif args.action == 'inject':
	n = NANDImage(args.file, cid=unhexlify(args.cid))
elif args.action == 'create':
	n = NANDImage(cid=unhexlify(args.cid))

	def round_sector(s):
		if s % 0x200 != 0:
			s = s + 0x200 - s % 0x200
		return s

	twln_fat_sz = 0
	twlp_fat_sz = 0
	ctrn_fat_sz = 0
	curr = 0

	if args.twln:
		twln_fat_sz = round_sector(os.stat(args.twln).st_size)
	if args.twlp:
		twlp_fat_sz = round_sector(os.stat(args.twlp).st_size)
	if args.ctr:
		ctrn_fat_sz = round_sector(os.stat(args.ctr).st_size)

	curr = 0x200
	if args.twln or args.twlp:
		n.twln_raw = NCSDPartition(n, fs_type=1, crypt_type=1, offset=0, length=twln_fat_sz + twlp_fat_sz + 0x200)
		n.twln_raw.mbr = MBR(n.twln_raw, offset=0x1be)
		n.ncsd.partitions.append(n.twln_raw)

	if args.twln:
		n.twlnand = MBRPartition(n.twln_raw, type=6, offset=0x200, length=twln_fat_sz)
		n.twln_raw.mbr.partitions.append(n.twlnand)
		curr += twln_fat_sz
	if args.twlp:
		n.twlphoto = MBRPartition(n.twln_raw, type=6, offset=twln_fat_sz+0x200, length=twlp_fat_sz)
		n.twln_raw.mbr.partitions.append(n.twlphoto)
		curr += twlp_fat_sz

	if args.agb:
		n.agbsave = NCSDPartition(n, fs_type=4, crypt_type=2, offset=curr, length=0x30000)
		curr += 0x30000
		n.ncsd.partitions.append(n.agbsave)

	num_firms = len(args.firm.split(','))
	for i in range(0, num_firms):
		f = NCSDPartition(n, fs_type=3, crypt_type=2, offset=curr, length=0x400000)
		n.firm.append(f)
		n.ncsd.partitions.append(f)
		curr += 0x400000

	if args.ctr:
		n.ctrn_raw = NCSDPartition(n, fs_type=1, crypt_type=2, offset=curr, length=ctrn_fat_sz + 0x200)
		curr += ctrn_fat_sz + 0x200
		n.ctrn_raw.mbr = MBR(n.ctrn_raw, offset=0x1be)
		n.ctrnand = MBRPartition(n.ctrn_raw, type=6, offset=0x200, length=ctrn_fat_sz)
		n.ctrn_raw.mbr.partitions.append(n.ctrnand)
		n.ncsd.partitions.append(n.ctrn_raw)

	n.ncsd.size = curr
	for p in n.ncsd.partitions:
		print(p)
		if p.mbr:
			for pp in p.mbr.partitions:
				print("    " + str(pp))

	# Write MBRs and NCSD header out...
	n.f = open(args.file, 'wb')
	n.f.seek(0)
	n.f.write(n.ncsd.pack())
	if args.twln or args.twlp:
		n.twln_raw.seek(0x1be)
		n.twln_raw.write(n.twln_raw.mbr.pack())
	if args.ctr:
		n.ctrn_raw.seek(0x1be)
		n.ctrn_raw.write(n.ctrn_raw.mbr.pack())

if args.action == 'inject' or args.action == 'create':
	if args.ctr:
		print("Injecting CTRNAND...")
		inject(args.ctr, n.ctrnand)
	if args.twln:
		print("Injecting TWLNAND...")
		inject(args.twln, n.twlnand)
	if args.twlp:
		print("Injecting TWLPHOTO...")
		inject(args.twlp, n.twlphoto)
	if args.twlmbr:
		print("Injecting TWL MBR...")
		inject(args.twl_mbr, n.ncsd.partitions[0], off=0x1be, len=0x42)
	if args.firm:
		f = args.firm.split(',')
		i = 0
		for firm in f:
			print("Injecting FIRM{}...".format(i))
			inject(firm, n.firm[i])
			i += 1
	if args.agb:
		inject('agbsave_dec.bin', n.agbsave)
