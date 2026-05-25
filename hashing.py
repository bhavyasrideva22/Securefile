"""
Hashing Module - SHA-256 and MD5 Hash Generation

Generates cryptographic hashes for files and text strings.
Supports both SHA-256 and MD5 algorithms for integrity verification.
"""

import hashlib


def hash_file(file_path: str, algorithm: str = "sha256") -> dict:
    """
    Generate a hash of a file's contents.

    Args:
        file_path: Path to the file.
        algorithm: 'sha256' or 'md5'.

    Returns:
        dict with 'success', 'hash', and 'algorithm' keys.
    """
    try:
        if algorithm not in ("sha256", "md5"):
            return {"success": False, "hash": "", "algorithm": algorithm,
                    "message": f"Unsupported algorithm: {algorithm}"}

        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)

        return {
            "success": True,
            "hash": h.hexdigest(),
            "algorithm": algorithm,
            "message": f"{algorithm.upper()} hash generated successfully",
        }
    except FileNotFoundError:
        return {"success": False, "hash": "", "algorithm": algorithm,
                "message": f"File not found: {file_path}"}
    except Exception as e:
        return {"success": False, "hash": "", "algorithm": algorithm,
                "message": f"Hashing failed: {str(e)}"}


def hash_text(text: str, algorithm: str = "sha256") -> dict:
    """
    Generate a hash of a text string.

    Args:
        text: Input text string.
        algorithm: 'sha256' or 'md5'.

    Returns:
        dict with 'success', 'hash', and 'algorithm' keys.
    """
    if algorithm not in ("sha256", "md5"):
        return {"success": False, "hash": "", "algorithm": algorithm,
                "message": f"Unsupported algorithm: {algorithm}"}

    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))

    return {
        "success": True,
        "hash": h.hexdigest(),
        "algorithm": algorithm,
        "message": f"{algorithm.upper()} hash generated successfully",
    }
