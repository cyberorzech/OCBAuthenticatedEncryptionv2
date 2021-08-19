import pytest

from src.keygen import Keygen
from src.aes import AES


class Test_AES:
    @pytest.fixture
    def plaintext(self):
        return bytearray(b"To jest test1234")

    @pytest.fixture
    def key(self):
        return bytearray().fromhex(Keygen().get_key())

    @pytest.fixture
    def aes(self):
        return AES()

    def test_if_ciphertext_differ_from_plain(self, plaintext, key, aes):
        aes.setKey(key)
        ciphertext = aes.encrypt(plaintext)
        assert ciphertext != plaintext

    def test_multiple_encryptions(self, plaintext, aes):
        TESTS_AMOUNT = 10
        ciphers_list = list()
        for x in range(0, TESTS_AMOUNT):
            key = bytearray().fromhex(Keygen().get_key())
            aes.setKey(key)
            ciphertext = aes.encrypt(plaintext)
            assert ciphertext not in ciphers_list
            ciphers_list.append(ciphertext) 

    def test_decipher(self, plaintext, key, aes):
        aes.setKey(key)
        ciphertext = aes.encrypt(plaintext)
        plaintext2 = aes.decrypt(ciphertext)
        assert plaintext == plaintext2



class Test_KeyGen:
    @pytest.fixture
    def keygen(self):
        return Keygen()

    def test_single_keygen(self, keygen):
        KEYLEN = 16  # key length in bytes
        key = keygen.get_key()
        assert len(key) == KEYLEN * 2
        assert isinstance(key, str)

    def test_multiple_keygen(self, keygen):
        TESTS_AMOUNT = 10
        key_list = list()
        for x in range(0, TESTS_AMOUNT):
            key = keygen.get_key()
            assert key not in key_list
            key_list.append(key)
