from loguru import logger
import math
from tqdm import tqdm

from src.bytes_operations import *


class OCB:
    @logger.catch
    def __init__(cls, cipher) -> None:
        assert cipher
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
    def encrypt(cls, plaintext, header):
        if cls.cipher_block_size == None or cls.nonce == None:
            raise ValueError(
                "Parameters of encryption method non initialized (ciper block size or nonce)"
            )
        m = int(max(1, math.ceil(len(plaintext) / float(cls.cipher_block_size))))
        offset = cls.cipher.encrypt(cls.nonce)
        checksum = bytearray(cls.cipher_block_size)
        ciphertext = bytearray()

        for i in range(m - 1):
            offset = times_two(offset, cls.cipher_block_size)
            M_i = plaintext[
                (i * cls.cipher_block_size) : (i * cls.cipher_block_size)
                + cls.cipher_block_size
            ]
            assert len(M_i) == cls.cipher_block_size
            checksum = xor_block(checksum, M_i)
            xoffset = cls.cipher.encrypt(xor_block(M_i, offset))
            ciphertext += xor_block(offset, xoffset)
            assert len(ciphertext) % cls.cipher_block_size == 0
        M_m = plaintext[((m - 1) * cls.cipher_block_size) :]
        offset = times_two(offset, cls.cipher_block_size)
        bitlength = len(M_m) * 8
        assert bitlength <= cls.cipher_block_size * 8
        tmp = bytearray(cls.cipher_block_size)
        tmp[-1] = bitlength
        pad = cls.cipher.encrypt(xor_block(tmp, offset))
        tmp = bytearray()
        C_m = xor_block(M_m, pad[: len(M_m)])
        ciphertext += C_m
        tmp = M_m + pad[len(M_m) :]
        assert len(tmp) == cls.cipher_block_size
        checksum = xor_block(tmp, checksum)
        offset = times_three(offset, cls.cipher_block_size)
        tag = cls.cipher.encrypt(xor_block(checksum, offset))
        if len(header) > 0:
            tag = xor_block(tag, cls._get_pmac(header))
        cls.nonce = None
        return (tag, ciphertext)

    @logger.catch
    def decrypt(cls, ciphertext, header, tag):
        if cls.cipher_block_size % 8 != 0:
            raise ValueError("Cipher block size is not 8-multiple")
        m = int(max(1, math.ceil(len(ciphertext) / float(cls.cipher_block_size))))
        offset = cls.cipher.encrypt(cls.nonce)
        checksum = bytearray(cls.cipher_block_size)
        plaintext = bytearray()
        for i in range(m - 1):
            offset = times_two(offset, cls.cipher_block_size)
            C_i = ciphertext[
                (i * cls.cipher_block_size) : (i * cls.cipher_block_size)
                + cls.cipher_block_size
            ]
            assert len(C_i) == cls.cipher_block_size
            tmp = cls.cipher.decrypt(xor_block(C_i, offset))
            M_i = xor_block(offset, tmp)
            checksum = xor_block(checksum, M_i)
            plaintext += M_i
            assert len(plaintext) % cls.cipher_block_size == 0
        offset = times_two(offset, cls.cipher_block_size)
        C_m = ciphertext[((m - 1) * cls.cipher_block_size) :]
        bitlength = len(C_m) * 8
        assert bitlength <= cls.cipher_block_size * 8
        tmp = bytearray(cls.cipher_block_size)
        tmp[-1] = bitlength
        pad = cls.cipher.encrypt(xor_block(tmp, offset))
        tmp = []
        M_m = xor_block(C_m, pad[: len(C_m)])
        plaintext += M_m
        tmp = M_m + pad[len(M_m) :]
        assert len(tmp) == cls.cipher_block_size
        checksum = xor_block(tmp, checksum)
        offset = times_three(offset, cls.cipher_block_size)
        full_valid_tag = cls.cipher.encrypt(xor_block(offset, checksum))
        if len(header) > 0:
            full_valid_tag = xor_block(full_valid_tag, cls._get_pmac(header))
        if tag == full_valid_tag:
            return (True, plaintext)
        else:
            return (False, [])

    @logger.catch
    def _get_pmac(cls, header):
        if len(header) == 0 or cls.cipher_block_size == None:
            raise ValueError(
                "Unable to perform pmac. Header or cipher block size incorrect"
            )
        m = int(max(1, math.ceil(len(header) / float(cls.cipher_block_size))))
        offset = cls.cipher.encrypt(bytearray([0] * cls.cipher_block_size))
        offset = times_three(offset, cls.cipher_block_size)
        offset = times_three(offset, cls.cipher_block_size)
        checksum = bytearray(cls.cipher_block_size)
        for i in range(m - 1):
            offset = times_two(offset, cls.cipher_block_size)
            H_i = header[
                (i * cls.cipher_block_size) : (i * cls.cipher_block_size)
                + cls.cipher_block_size
            ]
            assert len(H_i) == cls.cipher_block_size
            xoffset = xor_block(H_i, offset)
            encrypted = cls.cipher.encrypt(xoffset)
            checksum = xor_block(checksum, encrypted)
        offset = times_two(offset, cls.cipher_block_size)
        H_m = header[((m - 1) * cls.cipher_block_size) :]
        assert len(H_m) <= cls.cipher_block_size
        if len(H_m) == cls.cipher_block_size:
            offset = times_three(offset, cls.cipher_block_size)
            checksum = xor_block(checksum, H_m)
        else:
            H_m.append(int("10000000", 2))
            while len(H_m) < cls.cipher_block_size:
                H_m.append(0)
            assert len(H_m) == cls.cipher_block_size
            checksum = xor_block(checksum, H_m)
            offset = times_three(offset, cls.cipher_block_size)
            offset = times_three(offset, cls.cipher_block_size)
        final_xor = xor_block(offset, checksum)
        auth = cls.cipher.encrypt(final_xor)
        return auth


def main():
    raise NotImplementedError("Use as package")


if __name__ == "__main__":
    main()
