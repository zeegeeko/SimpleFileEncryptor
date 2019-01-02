# Simple File Encryptor

A simple script to encrypt/decrypt contents of a file. Script is written in Python 3 using the
Cryptography module and utilized Fernet (AES-CBC + HMAC-SHA256) for symmetric encryption. Keys are generated
using Argon2 key derivation.

## Usage
```
Encrypt File:
enc_file.py -e <filename>
```
```
Decrypt File:
enc_file.py -d <filename>
```
