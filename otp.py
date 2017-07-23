import argparse
from three_ds.aesengine import AESEngine
from three_ds.otp import OTP

parser = argparse.ArgumentParser(description='OTP encryption / decryption tool.')
parser.add_argument('action', metavar='action', type=str, help='encrypt/decrypt')
parser.add_argument('file', metavar='file', type=str, help='OTP filename')
parser.add_argument('--dev', action='store_true', help='Use the development unit encryption keys.')
parser.add_argument('--force', action='store_true', help='Override the OTP hash check.')

args = parser.parse_args()

AESEngine.init_keys(otp_path=None, dev=args.dev)

otp_f = open(args.file, 'rb')
otp = otp_f.read()
otp_f.close()

otp = OTP(otp, dev=args.dev)

if args.action == 'encrypt':
	if otp.initial_type == 'decrypted':
		with open(args.file, 'wb') as f:
			f.write(otp.encrypted)
		print("Encryption successful.")
	else:
		print("Already encrypted!")
elif args.action == 'decrypt':
	if otp.initial_type == 'encrypted':
		with open(args.file, 'wb') as f:
			f.write(otp.decrypted)
		print("Decryption successful.")
	else:
		print("Already decrypted!")
else:
	print("Invalid action!")