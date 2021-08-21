from loguru import logger
import math

class OCB:
    @logger.catch
    def __init__(cls, cipher) -> None:
        assert(cipher)
        cls.cipher = cipher
        cls.cipher_key_size = cipher.getKeySize()
        cls.cipher_rounds = cipher.getRounds()
        cls.cipher_block_size = cipher.getBlockSize()
        cls.nonce = None

    @logger.catch
    def set_params(cls, key, nonce):
        assert len(key) == cls.cipher_key_size
        assert len(nonce) == cls.cipher_block_size
        cls.nonce = nonce
        cls.cipher.setKey(key)

    @logger.catch
    def set_nonce(cls, nonce):
        assert len(nonce) == cls.cipher_block_size
        cls.nonce = nonce

    @logger.catch
    def encrypt(cls):
        pass

    @logger.catch
    def decrypt(cls):
        pass

    @logger.catch
    def _get_pmac(cls):
        pass

def main():
    pass

if __name__ == "__main__":
    main()