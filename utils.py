import os
import math
import numpy as np
from Crypto.Cipher import AES


def aes_cipherkey(key: bytes, nonce=None):
    """
    Generate AES cipherkey object from key.
    Parameters:
        key: str, user input key.
        nonce: None | bytes, Generated during encryption by the AES module. Required during decryption.

    Returns: cipherkey and nonce
    """

    if nonce:
        cipherkey = AES.new(key, AES.MODE_EAX, nonce=nonce)
    else:
        cipherkey = AES.new(key, AES.MODE_EAX)
        nonce = cipherkey.nonce
    return cipherkey, nonce


def encrypt_aes(data: bytes, cipher):
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag


def decrypt_aes(ciphertext: bytes, cipher):
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def verify_data(cipher, tag):
    try:
        cipher.verify(tag)
        print("The message is authentic.")
    except ValueError:
        print("Key incorrect or message corrupted.")


class FileReaderWriter:
    def __init__(self, direc: str):
        self.dir = direc

    def read_file(self, file_path: str, mode: str = "r"):
        with open(os.path.join(self.dir, file_path), mode) as f:
            data = f.read()
        return data

    def write_file(self, data, file_path: str, mode: str = "w"):
        with open(os.path.join(self.dir, file_path), mode) as f:
            f.write(data)


def generate_mask(n: int, k: int):
    bin_arr = []
    max_val = 2**n - 1
    for i in range(max_val, 0, -1):
        bin_value = list(bin(i))[2:]
        bin_value = ["0"] * (n - len(bin_value)) + bin_value
        if np.sum(np.array(bin_value) == "0") == k - 1:
            bin_arr.append(bin_value)
    return np.array(bin_arr, dtype=int).T
