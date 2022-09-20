import os
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


def distinct_permutations(iterable, r=None):
    def _full(A):
        while True:
            yield tuple(A)

            for i in range(size - 2, -1, -1):
                if A[i] < A[i + 1]:
                    break
            else:
                return

            for j in range(size - 1, i, -1):
                if A[i] < A[j]:
                    break

            A[i], A[j] = A[j], A[i]
            A[i + 1 :] = A[: i - size : -1]

    def _partial(A, r):
        head, tail = A[:r], A[r:]
        right_head_indexes = range(r - 1, -1, -1)
        left_tail_indexes = range(len(tail))

        while True:
            yield tuple(head)
            pivot = tail[-1]
            for i in right_head_indexes:
                if head[i] < pivot:
                    break
                pivot = head[i]
            else:
                return

            for j in left_tail_indexes:
                if tail[j] > head[i]:
                    head[i], tail[j] = tail[j], head[i]
                    break
            else:
                for j in right_head_indexes:
                    if head[j] > head[i]:
                        head[i], head[j] = head[j], head[i]
                        break

            tail += head[: i - r : -1]
            i += 1
            head[i:], tail[:] = tail[: r - i], tail[r - i :]

    items = sorted(iterable)

    size = len(items)
    if r is None:
        r = size

    if 0 < r <= size:
        return _full(items) if (r == size) else _partial(items, r)

    return iter(() if r else ((),))


def generate_masks(n: int, k: int):
    bin_arr = list(distinct_permutations([1] * (n - k + 1) + [0] * (k - 1)))
    return np.array(bin_arr, dtype=int).T


def nk_shares(img, n, k):
    masks = generate_masks(n, k)
    shares = []
    for mask in masks:
        new_img = []
        mask_ = np.concatenate([np.tile(mask, int(len(img[0]) / len(mask))), mask[: int(len(img[0]) % len(mask))]])
        new_img = img[:, np.argwhere(mask_), :].reshape(img.shape[0], -1, *img.shape[2:])
        shares.append(new_img)
    return shares


def shares_to_img(shares, n: int, k: int, w: int):
    masks = generate_masks(n, k)
    orig_shares_img = []
    for share, mask in zip(shares[:k], masks[:k]):
        orig_img = np.zeros((share.shape[0], w, *share.shape[2:]), dtype=np.uint8)
        zero_count = 0
        for i in range(w):
            if mask[i % len(mask)]:
                orig_img[:, i, :] = share[:, i - zero_count, :]
            else:
                zero_count += 1
                orig_img[:, i, :] = np.zeros_like(share[:, 0, :])
        orig_shares_img.append(np.array(orig_img))
    for i in range(1, len(orig_shares_img)):
        np.bitwise_or(orig_shares_img[0], orig_shares_img[i], orig_shares_img[0])
    return orig_shares_img[0]
