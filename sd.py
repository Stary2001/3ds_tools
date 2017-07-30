#!/usr/bin/env python3

import argparse
import re
import os
from three_ds.aesengine import AESEngine
from three_ds.content import SDFile
import hashlib
from binascii import hexlify
import struct
import progressbar

parser = argparse.ArgumentParser(description='3DS SD card contents encryption/decryption tool')
parser.add_argument('action', metavar='action', type=str, help='encrypt/decrypt')
parser.add_argument('dir', metavar='dir', type=str, help='SD dir to encrypt/decrypt')
parser.add_argument('--movable', metavar='movable', type=str, help='movable.sed path')
parser.add_argument('--otp', metavar='otp', type=str, help='OTP path')
parser.add_argument('--out', metavar='out', type=str, help='output directory')
parser.add_argument('--inplace', action='store_true', help='encrypt/decrypt in place')
parser.add_argument('--boot9', metavar='boot9', type=str, default=None, help='boot9 path')

args = parser.parse_args()

if args.out == None:
	print("No output path! It is required!")
	exit()

success, what = AESEngine.init_keys(otp_path = args.otp, movable_path = args.movable, b9_path=args.boot9, required = ('otp', 'movable'))
if not success:
	print("Missing " + what + "!")
	exit()

def crypt_file(inbase, outbase, relpath):
	blk = 0x10000
	with open(inbase + "/" + relpath, 'rb') as f:
		f = SDFile(f, relpath)
		f_len = len(f)
		n = f_len // blk
		
		d = os.path.dirname(outbase + relpath)
		if not os.path.isdir(d):
			os.makedirs(d)

		bar = progressbar.ProgressBar()
		with open(outbase + relpath, 'wb') as f2:
			for i in bar(range(0, n)):
				f2.write(f.read(blk))

keyy = None
with open(AESEngine.movable_path, 'rb') as f:
	keyy = f.read()[0x110:0x120]
id0_bin = hashlib.sha256(keyy).digest()[0:0x10]

id0 = "{:08x}{:08x}{:08x}{:08x}".format(*struct.unpack("<IIII", id0_bin))
base = args.dir + "/" + id0

if os.path.isdir(base):
	# TODO - can multiple id1's exist?
	id1 = os.listdir(args.dir + "/" + id0)[0]
	base += "/" + id1
	for (path, dirs, files) in os.walk(base):
		rel_path = path[len(base):]
		rel_path = rel_path.replace('\\', '/') # Important - the CTR uses forward slashes. Backslashes (ie on Windows) will result in an invalid CTR.
		for name in files:
			p = rel_path + "/" + name
			print(p)
			crypt_file(base, args.out, p)
else:
	print("Invalid ID0!")