import os
import numpy as np
from skimage.io import imread, imsave
import argparse
import utils


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--img", type=str, default="img.jpg", help="Path to image file")
    parser.add_argument("--task", type=str, choices=["encrypt", "decrypt"], default="encrypt", help="Specify encrypt/decrypt task")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--key", type=str, help="Key for encrypting image (min size = 2*n + 1)")
    group.add_argument("--key_file", type=str, help="Key file")
    parser.add_argument("--dec_img", type=str, default="img_decrypt.png", help="File to read/write decrypted image.")
    parser.add_argument("--dir", type=str, default="data", help="Directory to store all data.")
    parser.add_argument("-n", type=int, default=5, help="Value of n in (n, k) sharing method.")
    parser.add_argument("-k", type=int, default=3, help="Value of n in (n, k) sharing method.")
    parser.add_argument("-w", "--width", type=int, default=0, help="Width of the original image. Required for decrypting image")

    args = parser.parse_args()
    if len(args.key) < 2 * args.n + 1:
        parser.error("Key length should be at least equal to 2n")
    elif not args.key.isnumeric():
        parser.error("Key should be integer")
    if args.task == "decrypt" and args.width == 0:
        parser.error("Require width of original image.")

    file_handler = utils.FileReaderWriter(args.dir)
    key = file_handler.read_file(args.key_file, "r") if args.key_file else args.key

    if args.task == "encrypt":
        img_data = imread(os.path.join(args.dir, args.img))
        shape = img_data.shape

        key1 = int(args.key[2 * args.n :])
        generator = np.random.RandomState(np.random.PCG64(np.random.SeedSequence(key1)))
        mask = generator.randint(0, 255, shape)
        img = ((img_data + mask) % 256).astype(np.uint8)
        imsave(os.path.join(args.dir, "img_encrypt.png"), img)

        key2 = int(args.key[: 2 * args.n])
        shares = utils.nk_shares(img, args.n, args.k)
        n_keys = utils.randomize_key2(key2, args.n, generator)
        encrypted_shares = []
        for key, share in zip(n_keys, shares):
            encrypted_shares.append(((share + utils.random_mask_generator(key, share.shape)) % 256).astype(np.uint8))

        for i, share in enumerate(encrypted_shares):
            imsave(os.path.join(args.dir, f"share-{i}.png"), share)

    elif args.task == "decrypt":
        share_files = [f"share-{i}.png" for i in range(args.n)]
        shares = [imread(os.path.join(args.dir, f)) for f in share_files]
        key1 = int(args.key[2 * args.n :])
        key2 = int(args.key[: 2 * args.n])
        generator = np.random.RandomState(np.random.PCG64(np.random.SeedSequence(key1)))
        mask = generator.randint(0, 255, (shares[0].shape[0], args.width, *shares[0].shape[2:]))
        n_keys = utils.randomize_key2(key2, args.n, generator)

        decrypted_shares = []
        for key, share in zip(n_keys, shares):
            decrypted_shares.append(((share - utils.random_mask_generator(key, share.shape)) % 256).astype(np.uint8))

        encrypted_img = utils.shares_to_img(decrypted_shares, args.n, args.k, args.width)
        decrypted_img = ((encrypted_img - mask) % 256).astype(np.uint8)

        imsave(os.path.join(args.dir, args.dec_img), decrypted_img)


if __name__ == "__main__":
    main()
