"""
Encryption Module - AES-256 File Encryption

Provides password-based AES encryption for files using PyCryptodome.
Uses CBC mode with a random IV for each encryption operation.
Key is derived from the user password using SHA-256 hashing.
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


BLOCK_SIZE = 16  # AES block size in bytes


def derive_key(password: str) -> bytes:
    """Derive a 256-bit AES key from a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Encrypt a file using AES-256-CBC.

    Args:
        input_path: Path to the file to encrypt.
        output_path: Path to save the encrypted file.
        password: User password for key derivation.

    Returns:
        dict with 'success', 'message', and 'hash' keys.
    """
    if not os.path.isfile(input_path):
        return {"success": False, "message": f"File not found: {input_path}"}

    try:
        key = derive_key(password)
        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(input_path, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))

        # Prepend IV to ciphertext so it can be extracted during decryption
        with open(output_path, "wb") as f:
            f.write(iv + ciphertext)

        file_hash = hashlib.sha256(ciphertext).hexdigest()

        return {
            "success": True,
            "message": f"File encrypted successfully -> {output_path}",
            "hash": file_hash,
        }
    except Exception as e:
        return {"success": False, "message": f"Encryption failed: {str(e)}"}


def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypt raw bytes using AES-256-CBC.

    Args:
        data: Raw bytes to encrypt.
        password: User password for key derivation.

    Returns:
        Encrypted bytes (IV + ciphertext).
    """
    key = derive_key(password)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))
    return iv + ciphertext
