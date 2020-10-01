from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import time
import glob


class Encryptor:
    def __init__(self, key=b"defaultkey16byte"):
        self.key = key  # Keys must be 16, 24 or 32 bytes in length

    def pad(self, s):
        # AES-CBC (Cipher Block Chaining) uses blocks of 16 bytes
        return s + (b"\0" * (AES.block_size - (len(s) % AES.block_size)))

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)

        """ Initialisation vector- arbitrary number
        prevents repetition of encrypted data so attempts to crack cipher 
        using dictionary methods are made more difficult
        """

        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, filename):
        # Open file, read file, encrypt text, create encrypted file, delete original file
        with open(filename, "rb") as f:
            plaintext = f.read()
        encrypted_text = self.encrypt(plaintext, self.key)
        with open(filename + ".enc", "wb") as f:  # .enc extension used to denote as encrypted
            f.write(encrypted_text)
        os.remove(filename)

    def decrypt(self, cipher_text, key):
        iv = cipher_text[
             :AES.block_size]  # Seperate the IV from ciphertext (when encrypting, the IV was placed at the start and was 16 bytes in length)
        cipher = AES.new(key, AES.MODE_CBC, iv)  # Recreate the original cipher object
        plaintext = cipher.decrypt(
            cipher_text[AES.block_size:])  # Using the original cipher object, decrypt the ciphertext only
        return plaintext.rstrip(b"\0")  # Remove padding

    def decrypt_file(self, filename):
        # Open encrypted file, read, decrypt, recreate original file, delete encrypted file
        if filename[-4:] != ".enc":
            print(f"{filename} is not encrypted!")
        else:
            with open(filename, "rb") as f:
                cipher_text = f.read()
            decrypted_text = self.decrypt(cipher_text, self.key)
            with open(filename[:-4], "wb") as f:
                f.write(decrypted_text)
            os.remove(filename)

    def encdec_ext(self, path, ext, encrypt=True):
        # Encrypt all files with a given file extension
        # Search entire drive: rf"C:\**\*.{ext}"
        if encrypt:
            for file in glob.glob(path + rf"\*.{ext}"):
                print(file)
                self.encrypt_file(file)
        else:
            for file in glob.glob(path + rf"\*.{ext}.enc"):
                print(file)
                self.decrypt_file(file)


key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)
clear = lambda: os.system('cls')
ext = ""
while ext == "":
    default_path = r"C:\Users\Domantas\Documents\@School Work\Sixth Form\Computer Science\NEA\Testing Extension Encryption"
    ext = input("Enter extension: .")
    option = input("Encrypt? (y/n) ")[0].upper()
    if option == "Y":
        enc.encdec_ext(default_path, ext)
    else:
        enc.encdec_ext(default_path, ext, encrypt=False)
