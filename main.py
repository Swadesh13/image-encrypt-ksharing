import numpy as np
from skimage.io import imread, imsave
import argparse
import utils

parser = argparse.ArgumentParser()
parser.add_argument("--img", type=str, default="img.jpg", help="Path to image file")
parser.add_argument("--task", type=str, choices=["encrypt", "decrypt"], default="encrypt", help="Specify encrypt/decrypt task")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--key", type=str, help="Key for encrypting image to aes")
group.add_argument("--key_file", type=str, help="Key file to read key")
parser.add_argument("--nonce_file", type=str, default="nonce.dat", help="Used for writing and reading the nonce.")
parser.add_argument("--enc_img", type=str, default="img_encrypt.jpg", help="File to read/write encrypted image.")
parser.add_argument("--dec_img", type=str, default="img_decrypt.jpg", help="File to read/write decrypted image.")
parser.add_argument("--tag_file", type=str, default="tag.dat", help="Tag (signature) generated after encryption.")

args = parser.parse_args()

if args.key_file:
    with open(args.key_file, "r") as f:
        key = f.read()
else:
    key = args.key.encode()


if args.task == "encrypt":
    # Generate cipher object and nonce
    cipherkey, nonce = utils.aes_cipherkey(key)

    # Very important. Required during decryption
    with open(args.nonce_file, "wb") as f:
        f.write(nonce)

    data = imread(args.img)
    shape = data.shape
    data = bytes(data.flatten().tolist())

    # Encrypt image file using AES
    ciphertext, tag = utils.encrypt_aes(data, cipherkey)

    img = np.array(list(ciphertext), dtype=np.uint8).reshape(shape)
    imsave(args.enc_img, img)
    with open(args.enc_img.split(".")[0] + ".dat", "wb") as f:
        f.write(ciphertext)

    with open(args.tag_file, "wb") as f:
        f.write(tag)

elif args.task == "decrypt":
    with open(args.nonce_file, "rb") as f:
        nonce = f.read()

    # Generate cipher object and nonce
    cipherkey, _ = utils.aes_cipherkey(key, nonce)

    data = imread(args.enc_img)
    shape = data.shape
    with open(args.enc_img.split(".")[0] + ".dat", "rb") as f:
        ciphertext = f.read()

    with open(args.tag_file, "rb") as f:
        tag = f.read()

    # Decrypt image file using AES
    img_data = utils.decrypt_aes(ciphertext, cipherkey)

    img = np.array(list(img_data), dtype=np.uint8).reshape(shape)
    imsave(args.dec_img, img)

    utils.verify_data(cipherkey, tag)
