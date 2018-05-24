# 3ds_tools
These tools require the python `cryptography` module, installed with
`pip install cryptography`

* three_ds/aesengine.py
	* 3DS AES engine implementation - includes the keyscrambler as well as methods to get the needed keys from boot9/OTP.
* three_ds/nand.py
	* NAND backup manipulation classes - for NAND image, NCSD header, MBRs.. etc
	* Also handles all crypto required via AESEngine.
* three_ds/crypto_wrappers.py
	* Just wrappers around `cryptography`.
* nand.py
	* Can list NCSD partitions, extract partitions (twln/twlp, ctrnand, firm0/1, agbsave) and create a NAND backup given those partitions.
	* Requires OTP and NAND CID.
* otp.py
	* Tool for OTP encryption and decryption.
* content.py
	* Tool for working with SD&NAND contents. Generally requires a full path for all the files.
	* Requires either full movable.sed or just the keyY (obtainable via seedminer?)

If no arguments are passed, these tools will look in either `%appdata%\3DS\` on Windows or `$HOME/.3ds/` on macOS/Linux for the files required.

# License
This project is covered under the MIT License - see the LICENSE file.
