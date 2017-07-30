import argparse
from three_ds.aesengine import AESEngine
from three_ds.otp import OTP

parser = argparse.ArgumentParser(description='OTP encryption / decryption tool.')
parser.add_argument('action', metavar='action', type=str, help='encrypt/decrypt')
parser.add_argument('file', metavar='file', type=str, help='OTP filename')
parser.add_argument('--dev', action='store_true', help='Use the development unit encryption keys.')
parser.add_argument('--force', action='store_true', help='Override the OTP hash check.')
parser.add_argument('--boot9', metavar='boot9', type=str, default=None, help='boot9 path')

args = parser.parse_args()

success, what = AESEngine.init_keys(otp_path=None, b9_path=args.boot9, dev=args.dev)

if not success:
	print("Missing " + what + "!")
	exit()

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