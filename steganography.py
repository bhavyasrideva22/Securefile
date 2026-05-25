"""
Steganography Module - Hide and Extract Messages in Images

Uses LSB (Least Significant Bit) encoding via OpenCV to embed
secret text messages inside PNG/JPG images. The message length
is stored in the first 32 pixels so the decoder knows how many
bits to read.
"""

import cv2
import numpy as np


def _text_to_bits(text: str) -> list[int]:
    """Convert a text string to a list of bits."""
    data = text.encode("utf-8")
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_text(bits: list[int]) -> str:
    """Convert a list of bits back to a text string."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i : i + 8]
        if len(byte) < 8:
            break
        char = 0
        for bit in byte:
            char = (char << 1) | bit
        chars.append(char)
    return bytes(chars).decode("utf-8", errors="ignore")


def hide_message(image_path: str, message: str, output_path: str) -> dict:
    """
    Hide a text message inside an image using LSB steganography.

    Args:
        image_path: Path to the source image (PNG preferred).
        message: Secret text to hide.
        output_path: Path to save the image with the hidden message.

    Returns:
        dict with 'success' and 'message' keys.
    """
    try:
        img = cv2.imread(image_path)
        if img is None:
            return {"success": False, "message": f"Cannot read image: {image_path}"}

        bits = _text_to_bits(message)
        bit_len = len(bits)

        # We need 32 pixels for the length header + bit_len pixels for data
        max_capacity = img.shape[0] * img.shape[1] * 3 - 32
        if bit_len > max_capacity:
            return {
                "success": False,
                "message": f"Message too long ({bit_len} bits). Image capacity: {max_capacity} bits.",
            }

        # Encode message length as 32 bits in the first 32 LSBs
        length_bits = [(bit_len >> i) & 1 for i in range(31, -1, -1)]

        flat = img.flatten().copy()
        idx = 0

        # Write length header
        for bit in length_bits:
            flat[idx] = (int(flat[idx]) & 0xFE) | bit
            idx += 1

        # Write message bits
        for bit in bits:
            flat[idx] = (int(flat[idx]) & 0xFE) | bit
            idx += 1

        img_out = flat.reshape(img.shape)
        cv2.imwrite(output_path, img_out)

        return {"success": True, "message": f"Message hidden successfully -> {output_path}"}
    except Exception as e:
        return {"success": False, "message": f"Steganography failed: {str(e)}"}


def extract_message(image_path: str) -> dict:
    """
    Extract a hidden message from an image.

    Args:
        image_path: Path to the image containing a hidden message.

    Returns:
        dict with 'success', 'message', and 'hidden_text' keys.
    """
    try:
        img = cv2.imread(image_path)
        if img is None:
            return {"success": False, "message": f"Cannot read image: {image_path}"}

        flat = img.flatten()

        # Read 32-bit length header
        bit_len = 0
        for i in range(32):
            bit_len = (bit_len << 1) | (int(flat[i]) & 1)

        if bit_len <= 0 or bit_len > (flat.size - 32):
            return {"success": False, "message": "No hidden message found or image is corrupted"}

        # Read message bits
        bits = []
        for i in range(32, 32 + bit_len):
            bits.append(int(flat[i]) & 1)

        hidden_text = _bits_to_text(bits)

        return {
            "success": True,
            "message": "Hidden message extracted successfully",
            "hidden_text": hidden_text,
        }
    except Exception as e:
        return {"success": False, "message": f"Extraction failed: {str(e)}"}
