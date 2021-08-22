import pytest
from src.bytes_operations import *

from src.keygen import Keygen
from src.aes import AES
from src.ocb import OCB


class Test_OCB:
    @pytest.fixture
    def aes(self):
        return AES()

    @pytest.fixture
    def ocb(self, aes):
        return OCB(aes)

    @pytest.fixture
    def key(self):
        return bytearray().fromhex(Keygen().get_key())

    @pytest.fixture
    def const_key(self):
        return bytearray(b"r\xb6\xfd\xe8\x9e%\xae_\x02y\x83\xbbC\xad\xb5\xf5")

    @pytest.fixture
    def nonce(self):
        return bytearray(range(16))

    @pytest.fixture
    def header(self):
        return bytearray(b"Nadawca: Natan")

    @pytest.fixture
    def plaintext(self):
        return bytearray(b"Test")

    @pytest.fixture
    def ciphertext(self):
        return bytearray(b'\x08)X\xcb')

    @pytest.fixture
    def tag(self):
        return bytearray(b'\x13\x8a\xe6x&\x11,\xde\xf4\x80\xf8\xc3\x0c\x1ed\xc5')

    def test_set_params(self, ocb, key, nonce):
        ocb.set_params(key, nonce)
        assert len(ocb.nonce) == 16
        ocb.set_nonce(nonce)
        assert len(ocb.nonce) == 16

    def test_pmac(self, ocb, const_key, nonce):
        ocb.set_params(const_key, nonce)
        header = bytearray(b"Nadawca: Natan")
        assert ocb._get_pmac(header) == bytearray(
            b'\x8f0\xd9\x00\xa2\xf9Z\x980\x11\xdf\xaa\xc4\xf6\xc7}'
        )

    def test_encrypt(self, ocb, plaintext, const_key, nonce, header):
        ocb.set_params(const_key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert tag == bytearray(b'\x13\x8a\xe6x&\x11,\xde\xf4\x80\xf8\xc3\x0c\x1ed\xc5')
        assert ciphertext == bytearray(b'\x08)X\xcb')

    def test_decrypt(self, nonce, key, ocb, header, plaintext):
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        ocb.set_nonce(nonce)
        auth, decrypted_text = ocb.decrypt(ciphertext, header, tag)
        assert auth == True
        assert decrypted_text == bytearray(b"Test")


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


class Test_Bytes_Operations:
    @pytest.fixture
    def input(self):
        return bytearray(b"abcdefgh")

    @pytest.fixture
    def block_size(self):
        return 8

    @pytest.fixture
    def xor_input(self):
        return bytearray(b"\xa3\xa6\xa5\xac\xaf\xaa\xa9\xb8")

    @pytest.fixture
    def xor_invalid_input(self):
        return bytearray(b"\xa3\xa6\xa5\xac\xaf\xaa\xa9\xb8\xb8")

    def test_times_two_valid_data(self, input, block_size):
        assert times_two(input, block_size) == bytearray(
            b"\xc2\xc4\xc6\xc8\xca\xcc\xce\xd0"
        )

    def test_times_two_invalid_data(self, input, block_size):
        with pytest.raises(ValueError) as excinfo:
            times_two(input, block_size + 1)
        assert "Input must have same length as cipher's block size" in str(
            excinfo.value
        )

    def test_times_three_valid_data(self, input, block_size):
        assert times_three(input, block_size) == bytearray(
            b"\xa3\xa6\xa5\xac\xaf\xaa\xa9\xb8"
        )

    def test_times_three_invalid_data(self, input, block_size):
        with pytest.raises(ValueError) as excinfo:
            times_three(input, block_size + 1)
        assert "Input must have same length as cipher's block size" in str(
            excinfo.value
        )

    def test_xor_block_valid_data(self, xor_input):
        assert xor_block(xor_input, xor_input) == bytearray(
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    def test_xor_block_invalid_data(self, xor_input, xor_invalid_input):
        with pytest.raises(ValueError) as excinfo:
            xor_block(xor_input, xor_invalid_input)
        assert "Inputs must have same length" in str(excinfo)
