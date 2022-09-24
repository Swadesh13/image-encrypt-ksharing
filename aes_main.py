import os
import numpy as np
from skimage.io import imread, imsave
import argparse
import utils

parser = argparse.ArgumentParser()
parser.add_argument("--img", type=str, default="img.jpg", help="Path to image file")
parser.add_argument("--task", type=str, choices=["encrypt", "decrypt"], default="encrypt", help="Specify encrypt/decrypt task")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--key", type=str, help="Key for encrypting image using aes")
group.add_argument("--key_file", type=str, help="Key file to read key")
parser.add_argument("--nonce_file", type=str, default="nonce.dat", help="Used for writing and reading the nonce.")
parser.add_argument("--enc_img", type=str, default="img_encrypt.jpg", help="File to read/write encrypted image.")
parser.add_argument("--dec_img", type=str, default="img_decrypt.jpg", help="File to read/write decrypted image.")
parser.add_argument("--tag_file", type=str, default="tag.dat", help="Tag (signature) generated after encryption.")
parser.add_argument("--dir", type=str, default="data", help="Directory to store all data.")

args = parser.parse_args()
file_handler = utils.FileReaderWriter(args.dir)
key = file_handler.read_file(args.key_file, "r") if args.key_file else args.key.encode()

if args.task == "encrypt":
    # Generate cipher object and nonce
    cipherkey, nonce = utils.aes_cipherkey(key)

    # Very important. Required during decryption
    file_handler.write_file(nonce, args.nonce_file, "wb")

    data = imread(os.path.join(args.dir, args.img))
    shape = data.shape
    data = bytes(data.flatten().tolist())

    # Encrypt image file using AES
    ciphertext, tag = utils.encrypt_aes(data, cipherkey)

    img = np.array(list(ciphertext), dtype=np.uint8).reshape(shape)
    imsave(os.path.join(args.dir, args.enc_img), img)
    file_handler.write_file(ciphertext, args.enc_img.split(".")[0] + ".dat", "wb")

    file_handler.write_file(tag, args.tag_file, "wb")

elif args.task == "decrypt":
    nonce = file_handler.read_file(args.nonce_file, "rb")

    # Generate cipher object and nonce
    cipherkey, _ = utils.aes_cipherkey(key, nonce)

    data = imread(os.path.join(args.dir, args.enc_img))
    shape = data.shape
    ciphertext = file_handler.read_file(args.enc_img.split(".")[0] + ".dat", "rb")

    tag = file_handler.read_file(args.tag_file, "rb")

    # Decrypt image file using AES
    img_data = utils.decrypt_aes(ciphertext, cipherkey)

    img = np.array(list(img_data), dtype=np.uint8).reshape(shape)
    imsave(os.path.join(args.dir, args.dec_img), img)

    utils.verify_data(cipherkey, tag)
