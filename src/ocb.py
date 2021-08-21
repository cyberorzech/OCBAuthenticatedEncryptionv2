from loguru import logger
import math

from src.bytes_operations import *

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
    def _get_pmac(cls, header):
        if len(header) == 0 or cls.cipher_block_size == None:
            raise ValueError("Unable to perform pmac. Header or cipher block size incorrect")
        m = int(max(1, math.ceil(len(header) / float(cls.cipher_block_size))))
        offset = cls.cipher.encrypt(bytearray([0] * cls.cipher_block_size))
        offset = times_three(offset)
        offset = times_three(offset)
        checksum = bytearray(cls.cipher_block_size)
        for i in range(m - 1):
            offset = times_two(offset)
            H_i = header[(i * cls.cipher_block_size):(i * cls.cipher_block_size) + cls.cipher_block_size]
            assert len(H_i) == cls.cipher_block_size
            xoffset = xor_block(H_i, offset)
            encrypted = cls.cipher.encrypt(xoffset)
            checksum = xor_block(checksum, encrypted)
        offset = times_two(offset)
        H_m = header[((m - 1) * cls.cipher_block_size):]
        assert len(H_m) <= cls.cipher_block_size
        if len(H_m) == cls.cipher_block_size:
            offset = times_three(offset)
            checksum = xor_block(checksum, H_m)
        else:
            H_m.append(int('10000000', 2))
            while len(H_m) < cls.cipher_block_size:
                H_m.append(0)
            assert len(H_m) == cls.cipher_block_size
            checksum = xor_block(checksum, H_m)
            offset = times_three(offset)
            offset = times_three(offset)
        final_xor = xor_block(offset, checksum)
        auth = cls.cipher.encrypt(final_xor)
        return auth

def main():
    pass

if __name__ == "__main__":
    main()