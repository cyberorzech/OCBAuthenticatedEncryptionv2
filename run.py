from loguru import logger
import sys

from src.aes import AES
from src.ocb import OCB
from src.keygen import Keygen

LOGS_PATH = "logs/ocb.log"
aes = AES()
ocb = OCB(aes)

def encrypt_mess(plaintext, header, nonce, key):
    ocb.set_params(key, nonce)
    tag, ciphertext = ocb.encrypt(plaintext, header)
    return tag, ciphertext

def decrypt_mess(header, ciphertext, tag, nonce):
    ocb.set_nonce(nonce)
    auth, decrypted_text = ocb.decrypt(ciphertext, header, tag)
    return auth, decrypted_text

@logger.catch
def main():
    # Input data
    plaintext = bytearray(b"Testowa wiadomosc")
    header = bytearray(b"Nadawca: ja teraz chce dodac wiecej znakow")
    key = bytearray().fromhex(Keygen().get_key())
    nonce = bytearray(range(16))
    # Encrypt
    tag, ciphertext = encrypt_mess(plaintext, header, nonce, key)
    # Decrypt
    auth, decrypted_text = decrypt_mess(header, ciphertext, tag, nonce)
    
    print(auth, decrypted_text)


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
