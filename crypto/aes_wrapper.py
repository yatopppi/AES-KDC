"""
aes_wrapper.py
--------------
Helper wrapper around the existing manual AES implementation.
Provides simple encrypt/decrypt functions for ASCII plaintext/keys,
using CTR mode from the underlying aes.py module.
"""

import os
import sys

# Ensure the crypto directory is in path for direct import of aes.py
sys.path.insert(0, os.path.dirname(__file__))
from aes import ctr_aes


def pad_key(key_bytes: bytes) -> bytes:
    """Pad or truncate key_bytes to the nearest valid AES key size (16, 24, or 32 bytes).
    
    If key is shorter than 16 bytes  → pad with null bytes to 16
    If key is between 17-24 bytes    → pad with null bytes to 24
    If key is between 25-32 bytes    → pad with null bytes to 32
    If key is longer than 32 bytes   → truncate to 32
    """
    for size in (16, 24, 32):
        if len(key_bytes) <= size:
            return key_bytes.ljust(size, b'\x00')
    return key_bytes[:32]


def encrypt(plaintext: str, key: str) -> tuple:
    """Encrypt ASCII plaintext with an ASCII key using AES-CTR.

    Args:
        plaintext: The message to encrypt (ASCII string).
        key:       The encryption key (ASCII string). Will be padded/truncated
                   to the nearest valid AES key size.

    Returns:
        A tuple of (hex_ciphertext, hex_nonce) where both are hex strings.
    """
    key_bytes = pad_key(key.encode('ascii'))
    nonce = os.urandom(12)  # 96-bit nonce for CTR mode
    ct = ctr_aes(plaintext.encode('ascii'), key_bytes, nonce)
    return ct.hex(), nonce.hex()


def decrypt(hex_ciphertext: str, key: str, hex_nonce: str) -> str:
    """Decrypt hex-encoded ciphertext with an ASCII key and hex nonce.

    Args:
        hex_ciphertext: The ciphertext as a hex string.
        key:            The encryption key (ASCII string). Will be padded/truncated
                        to the nearest valid AES key size.
        hex_nonce:      The nonce as a hex string (must decode to 12 bytes).

    Returns:
        The decrypted plaintext as an ASCII string.
    """
    key_bytes = pad_key(key.encode('ascii'))
    nonce = bytes.fromhex(hex_nonce)
    ct = bytes.fromhex(hex_ciphertext)
    pt = ctr_aes(ct, key_bytes, nonce)
    return pt.decode('ascii')
