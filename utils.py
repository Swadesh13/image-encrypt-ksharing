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
