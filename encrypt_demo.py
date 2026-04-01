#!/usr/bin/env python3
"""
Encrypt/Decrypt Demo with Role-Based Access Control
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# -------------------------------
# Hardcoded users (username: (password, role))
# In a real application, passwords would be hashed and stored securely.
# -------------------------------
USERS = {
    "alice": ("alice123", "user"),
    "bob":   ("bob123",   "admin"),
    "admin": ("admin123", "admin")
}

# -------------------------------
# Login function
# -------------------------------
def login():
    print("\n=== Login ===")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    if username in USERS and USERS[username][0] == password:
        role = USERS[username][1]
        print(f"Login successful! Welcome, {username} (role: {role})")
        return username, role
    else:
        print("Invalid username or password.")
        return None, None

# -------------------------------
# Symmetric Encryption (AES-256-CBC)
# -------------------------------
def symmetric_encrypt():
    print("\n--- Symmetric Encryption (AES-256-CBC) ---")
    plaintext = input("Enter the message to encrypt: ").encode('utf-8')

    # Generate a random 32-byte key and a 16-byte IV
    key = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to multiple of block size (16 bytes)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    print("\n[SYMMETRIC KEYS]")
    print(f"Key (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")
    print("\n[INPUT]")
    print(f"Plaintext: {plaintext.decode('utf-8')}")
    print("\n[OUTPUT]")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    return key, iv, ciphertext

def symmetric_decrypt(key, iv, ciphertext):
    print("\n--- Symmetric Decryption (AES-256-CBC) ---")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]

    print("\n[SYMMETRIC KEYS]")
    print(f"Key (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")
    print("\n[INPUT]")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print("\n[OUTPUT]")
    print(f"Plaintext: {plaintext.decode('utf-8')}")

# -------------------------------
# Asymmetric Encryption (RSA)
# -------------------------------
def asymmetric_encrypt():
    print("\n--- Asymmetric Encryption (RSA) ---")
    plaintext = input("Enter the message to encrypt: ").encode('utf-8')

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Encrypt with public key using OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Serialize keys for display (PEM format)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print("\n[ASYMMETRIC KEYS]")
    print(f"Public Key:\n{pem_public}")
    print(f"Private Key:\n{pem_private}")
    print("\n[INPUT]")
    print(f"Plaintext: {plaintext.decode('utf-8')}")
    print("\n[OUTPUT]")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    return private_key, ciphertext

def asymmetric_decrypt(private_key, ciphertext):
    print("\n--- Asymmetric Decryption (RSA) ---")
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\n[ASYMMETRIC KEYS]")
    # Display private key again (for demo)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    print(f"Private Key:\n{pem_private}")
    print("\n[INPUT]")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print("\n[OUTPUT]")
    print(f"Plaintext: {plaintext.decode('utf-8')}")

# -------------------------------
# Main menu with role-based access
# -------------------------------
def main_menu(role):
    # For simplicity, we store the last symmetric key/IV/ciphertext
    # and last asymmetric private key/ciphertext so that decryption
    # can reuse them.
    sym_key = None
    sym_iv = None
    sym_cipher = None
    asym_priv_key = None
    asym_cipher = None

    while True:
        print("\n" + "="*40)
        print(" ENCRYPT/DECRYPT DEMO")
        print("="*40)
        print("1. Symmetric Encryption")
        print("2. Symmetric Decryption")
        if role == "admin":
            print("3. Asymmetric Encryption")
            print("4. Asymmetric Decryption")
            print("5. Exit")
            choice = input("Choose an option (1-5): ").strip()
        else:
            print("3. Exit")
            choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            sym_key, sym_iv, sym_cipher = symmetric_encrypt()
        elif choice == "2":
            if sym_key is None or sym_iv is None or sym_cipher is None:
                print("No symmetric encryption performed yet. Please encrypt a message first.")
            else:
                symmetric_decrypt(sym_key, sym_iv, sym_cipher)
        elif role == "admin" and choice == "3":
            asym_priv_key, asym_cipher = asymmetric_encrypt()
        elif role == "admin" and choice == "4":
            if asym_priv_key is None or asym_cipher is None:
                print("No asymmetric encryption performed yet. Please encrypt a message first.")
            else:
                asymmetric_decrypt(asym_priv_key, asym_cipher)
        elif (role == "admin" and choice == "5") or (role != "admin" and choice == "3"):
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# -------------------------------
# Main entry point
# -------------------------------
def main():
    print("Welcome to the Encrypt/Decrypt Demo")
    username, role = login()
    if role:
        main_menu(role)

if __name__ == "__main__":
    main()