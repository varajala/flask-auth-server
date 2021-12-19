"""
Simple interface for AES encryption/decryption.

Main dependency is pycryptodome:

- https://github.com/Legrandin/pycryptodome
- https://www.pycryptodome.org/en/latest/

Author: Valtteri Rajalainen
"""

from Crypto.Cipher import AES
import os
import base64


BLOCK_SIZE = AES.block_size #bytes
INT_SIZE = 4 #bytes
PADDING = b'\xFF'


def _prepare(data: bytes) -> bytes:
    """
    AES has a fixed cipher block size of 16 bytes, so the data needs to be padded.
    
    The length of the actual data is inserted before the data. This is an 32-bit
    integer in big endian byteorder. After this the data follows with additional
    b'\xFF' bytes for padding.
    """
    data_len = len(data)
    length = ((data_len + INT_SIZE) // BLOCK_SIZE + 1) * BLOCK_SIZE

    buffer = bytearray(length)
    buffer[:INT_SIZE] = data_len.to_bytes(INT_SIZE, byteorder='big')
    buffer[INT_SIZE:data_len] = data
    buffer[INT_SIZE + data_len:] = (length - INT_SIZE - data_len) * PADDING
    return bytes(buffer)


def _restore(data: bytes) -> bytes:
    """
    Reverse the preparing process.
    """
    data_len = int.from_bytes(data[:INT_SIZE], byteorder='big')
    return data[INT_SIZE:data_len + INT_SIZE]


def encrypt(input_: bytes, key: bytes) -> bytes:
    """
    Encrypt the data provided with the AES block cipher.
    The output is in the following format:

        BASE64_ENCODE(initialization_vector + AES(PREPARE(input)))

    The key is expected to be 256 bits long.
    """
    data = _prepare(input_)
    init_vector = os.urandom(BLOCK_SIZE)
    aes = AES.new(key, AES.MODE_CFB, init_vector)
    return base64.b64encode(init_vector + aes.encrypt(data))


def decrypt(raw_data: bytes, key: bytes) -> bytes:
    """
    Decrypt the raw data provided.
    Decryption fails silently, this function will still return a bytestring normally.
    It may contain unprintable/non-utf-8 bytes.
    
    The key is expected to be 256 bits long.
    """
    encrypted_data = base64.b64decode(raw_data)
    init_vector = encrypted_data[:BLOCK_SIZE]
    data = encrypted_data[BLOCK_SIZE:]
    aes = AES.new(key, AES.MODE_CFB, init_vector)
    decrypted_data = aes.decrypt(data)
    return _restore(decrypted_data)
