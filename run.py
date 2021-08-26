from src.args_parser import ArgParser
from loguru import logger
import sys

from src.aes import AES
from src.ocb import OCB
from src.keygen import Keygen

LOGS_PATH = "logs/ocb.log"
ocb = OCB(AES())


def encrypt_mess(plaintext, header, nonce, key):
    ocb.set_params(key, nonce)
    tag, ciphertext = ocb.encrypt(plaintext, header)
    return tag, ciphertext


def decrypt_mess(header, ciphertext, tag, nonce, key):
    ocb.set_params(key, nonce)
    auth, decrypted_text = ocb.decrypt(ciphertext, header, tag)
    return auth, decrypted_text


@logger.catch
def main():
    args_parser = ArgParser()
    args = args_parser.get_args()
    args_parser.validate_args(args)
    if args.mode == "encrypt":
        logger.info("Encryption mode has been chosen")
        tag, ciphertext = encrypt_mess(
            bytearray(str(args.plaintext), "utf-8"),
            bytearray(str(args.header), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Ciphertext: " + str(bytes(ciphertext)))
        logger.info("Tag: " + str(bytes(tag)))
    elif args.mode == "decrypt":
        logger.info("Decryption mode has been chosen")
        auth, decrypted_text = decrypt_mess(
            bytearray(str(args.header), "utf-8"),
            bytearray(str(args.ciphertext), "utf-8"),
            bytearray(str(args.tag), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Decrypted text: " + str(bytes(decrypted_text)))
    else:
        logger.info("Demo mode has been chosen")
        logger.info("Plaintext passed by user is: " + str(args.plaintext))
        logger.info("Header is: " + str(args.header))
        tag, ciphertext = encrypt_mess(
            bytearray(str(args.plaintext), "utf-8"),
            bytearray(str(args.header), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )

        logger.info("Case 1: Message was not manipulated")
        logger.info("Ciphertext: " + str(bytes(ciphertext)))
        logger.info("Tag: " + str(bytes(tag)))
        auth, decrypted_text = decrypt_mess(
            bytearray(str(args.header), "utf-8"),
            bytearray(str(args.ciphertext), "utf-8"),
            bytearray(str(args.tag), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Decrypted data: " + str(bytes(decrypted_text)))

        logger.info("Case 2: Header was manipulated")
        manipulated_header = str(args.header) + "o"
        logger.info("Manipulated header: " + str(manipulated_header))
        tag, ciphertext = encrypt_mess(
            bytearray(str(args.plaintext), "utf-8"),
            bytearray(manipulated_header, "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Ciphertext: " + str(bytes(ciphertext)))
        auth, decrypted_text = decrypt_mess(
            bytearray(manipulated_header, "utf-8"),
            bytearray(str(args.ciphertext), "utf-8"),
            bytearray(str(args.tag), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Message auth is: " + str(auth))

        logger.info("Case 3: Ciphertext was manipulated")
        manipulated_ciphertext = ciphertext
        manipulated_ciphertext[0] = 7
        logger.info("Manipulated ciphertext: " + str(bytes(manipulated_ciphertext)))
        auth, decrypted_text = decrypt_mess(
            bytearray(args.header, "utf-8"),
            bytearray(str(manipulated_ciphertext), "utf-8"),
            bytearray(str(args.tag), "utf-8"),
            bytearray().fromhex(args.nonce),
            bytearray().fromhex(args.key),
        )
        logger.info("Message auth is: " + str(auth))


if __name__ == "__main__":
    logger.add(
        sys.stderr,
        colorize=True,
        format="{time} {level} {message}",
        filter="my_module",
        level="INFO",
    )
    logger.add(LOGS_PATH)
    main()
