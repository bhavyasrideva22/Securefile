"""
Decryption Module - AES-256 File Decryption

Decrypts files that were encrypted by the encryption module.
Extracts the IV from the first 16 bytes, then decrypts the remainder.
Verifies the password by attempting decryption (wrong key produces padding errors).
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


BLOCK_SIZE = 16


def derive_key(password: str) -> bytes:
    """Derive a 256-bit AES key from a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).digest()


def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Decrypt a file that was encrypted with AES-256-CBC.

    Args:
        input_path: Path to the encrypted file.
        output_path: Path to save the decrypted file.
        password: Password used during encryption.

    Returns:
        dict with 'success', 'message', and 'hash' keys.
    """
    if not os.path.isfile(input_path):
        return {"success": False, "message": f"File not found: {input_path}"}

    try:
        key = derive_key(password)

        with open(input_path, "rb") as f:
            raw = f.read()

        # First 16 bytes are the IV
        iv = raw[:BLOCK_SIZE]
        ciphertext = raw[BLOCK_SIZE:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        file_hash = hashlib.sha256(plaintext).hexdigest()

        return {
            "success": True,
            "message": f"File decrypted successfully -> {output_path}",
            "hash": file_hash,
        }
    except ValueError:
        # unpad fails when the password is wrong (corrupted padding)
        return {"success": False, "message": "Decryption failed: wrong password or corrupted file"}
    except Exception as e:
        return {"success": False, "message": f"Decryption failed: {str(e)}"}


def decrypt_data(data: bytes, password: str) -> bytes:
    """
    Decrypt raw bytes that were encrypted with AES-256-CBC.

    Args:
        data: Encrypted bytes (IV + ciphertext).
        password: Password used during encryption.

    Returns:
        Decrypted plaintext bytes.
    """
    key = derive_key(password)
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
