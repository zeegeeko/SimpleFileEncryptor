from cryptography.fernet import Fernet
import argon2
import sys
import getopt
import secrets
import getpass
import base64
import binascii

#Helper Function to open encrypted file and split salt and ciphertext
def open_file(filename):
    try:
        file = open(filename, "rb")
        content = file.read()
        salt = content[:32]
        ciphertext = content[32:]
        return salt, ciphertext
    except IOError:
        print('There is an issue opening the file')
        sys.exit(1)

#Helper that generates 32 bytes base64 encoded argon2 key
def generate_key(password, salt):
    return base64.urlsafe_b64encode(argon2.argon2_hash(password=password, salt=salt, t=1000, buflen=32))

#Helper that decrypts ciphertext and overwrites file with decrypted content
def decrypt_file(password, filename):
    salt, ciphertext = open_file(filename)
    key = generate_key(password, salt)
    f = Fernet(key)
    content = b""

    try:
        content = f.decrypt(ciphertext)
    except cryptography.fernet.InvalidToken:
        print('There is an issue decrypting the file')
        sys.exit(1)

    try:
        file = open(filename, "wb+")
        file.write(content)
        file.close()
        print('File Content Successfully Decrypted')
    except IOError:
        print('There is an issue writing to the file')
        sys.exit(1)

#Uses Fernet to Encrypt file contents
def encrypt_file(password, filename):
    salt = secrets.token_bytes(32)
    key = generate_key(password, salt)
    f = Fernet(key)
    ciphertext = ''

    try:
        file = open(filename, "r")
        ciphertext = f.encrypt(bytes(file.read(), 'utf-8'))
        file.close()
    except IOError:
        print('There is an issue opening the file')
        sys.exit(1)

    try:
        encfile = open(filename, "wb+")
        encfile.write(salt)
        encfile.write(ciphertext)
        encfile.close()
        print('File Content Successfully Encrypted')
    except IOError:
        print('There is an issue writing to the file')
        sys.exit(1)

def main(argv):
    try:
        opts, args = getopt.getopt(argv,'de',['encrypt', 'decrpyt'])

        if args[1] == '-d':
            print('Decrypt')
            pswd = getpass.getpass('Password:')
            decrypt_file(pswd, args[2])
        elif args[1] == '-e':
            print('Encrypt')
            pswd = getpass.getpass('Password:')
            encrypt_file(pswd, args[2])
        else:
            print('error')

    except getopt.GetoptError:
        print('enc_file.py <option> <file>')
        sys.exit(2)

main(sys.argv)
