print("Text Encryption")

from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# AES
def aes_pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def aes_unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(aes_pad(plaintext).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(ciphertext, key):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = aes_unpad(cipher.decrypt(ct).decode())
    return pt

# DES
def des_pad(text):
    return text + (8 - len(text) % 8) * chr(8 - len(text) % 8)

def des_unpad(text):
    return text[:-ord(text[-1])]

def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(des_pad(plaintext).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def des_decrypt(ciphertext, key):
    raw = base64.b64decode(ciphertext)
    iv = raw[:8]
    ct = raw[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = des_unpad(cipher.decrypt(ct).decode())
    return pt

# RSA
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ct_bytes = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct_bytes).decode()

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode()

# Main Program
def main():
    while True:
        text = input("\nEnter text to encrypt (type 'exit' to quit): ")

        if text.lower() == "exit":
            print("Program terminated.")
            break

        choice = input("Choose algorithm (AES/DES/RSA): ").upper()

        if choice == "AES":
            key = get_random_bytes(16)
            encrypted = aes_encrypt(text, key)
            decrypted = aes_decrypt(encrypted, key)

            print("\nAES Results")
            print("Encrypted:", encrypted)
            print("Decrypted:", decrypted)

        elif choice == "DES":
            key = get_random_bytes(8)
            encrypted = des_encrypt(text, key)
            decrypted = des_decrypt(encrypted, key)

            print("\nDES Results")
            print("Encrypted:", encrypted)
            print("Decrypted:", decrypted)

        elif choice == "RSA":
            private_key, public_key = rsa_generate_keys()
            encrypted = rsa_encrypt(text, public_key)
            decrypted = rsa_decrypt(encrypted, private_key)

            print("\nRSA Results")
            print("Encrypted:", encrypted)
            print("Decrypted:", decrypted)

        else:
            print("Invalid choice! Please enter AES, DES, or RSA.")

if __name__ == "__main__":
    main()
