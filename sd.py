#!/usr/bin/env python3

import argparse
import re
import os
from three_ds.aesengine import AESEngine
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

if args.otp == None:
	print("No OTP! It is required!")
	exit()

if args.movable == None:
	print("No movable.sed! It is required!")
	exit()

if args.out == None:
	print("No output path! It is required!")
	exit()

AESEngine.init_keys(otp_path = args.otp, movable_path = args.movable, b9_path=args.boot9)

def crypt_file(inbase, outbase, relpath):
	path_enc = relpath.lower().encode('UTF-16LE') + b"\x00\x00"
	path_hash = hashlib.sha256(path_enc).digest()
	ctr = b''
	for i in range(0, 16):
		ctr += (path_hash[i] ^ path_hash[i+16]).to_bytes(1, 'big')

	blk = 0x10000
	with open(inbase + "/" + relpath, 'rb') as f:
		f.seek(0, os.SEEK_END)
		f_len = f.tell()
		f.seek(0)
		n = f_len // blk
		
		d = os.path.dirname(outbase + relpath)
		if not os.path.isdir(d):
			os.makedirs(d)

		bar = progressbar.ProgressBar()
		with open(outbase + relpath, 'wb') as f2:
			for i in bar(range(0, n)):
				f2.write(AESEngine.encrypt('ctr', 0x34, f.read(blk), iv=ctr))
				ctr_i = int.from_bytes(ctr, 'big')
				ctr_i += blk // 0x10
				ctr = ctr_i.to_bytes(16, 'big')

keyy = None
with open(args.movable, 'rb') as f:
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