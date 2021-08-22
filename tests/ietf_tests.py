import pytest
from src.bytes_operations import *
from src.keygen import Keygen
from src.aes import AES
from src.ocb import OCB


class Test:
    @pytest.fixture
    def ocb(self):
        return OCB(AES())

    @pytest.fixture
    def key(self):
        return bytearray().fromhex("000102030405060708090A0B0C0D0E0F")

    @pytest.fixture
    def nonce(self):
        return bytearray().fromhex("000102030405060708090A0B0C0D0E0F")

    def test1(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray(b"")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray(b"")
        assert tag == bytearray().fromhex("BF3108130773AD5EC70EC69E7875A7B0")

    def test2(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray().fromhex("0001020304050607")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("C636B3A868F429BB")
        assert tag == bytearray().fromhex("A45F5FDEA5C088D1D7C8BE37CABC8C5C")

    def test3(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("52E48F5D19FE2D9869F0C4A4B3D2BE57")
        assert tag == bytearray().fromhex("F7EE49AE7AA5B5E6645DB6B3966136F9")

    def test4(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F1011121314151617")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB")
        assert tag == bytearray().fromhex("A1A50F822819D6E0A216784AC24AC84C")

    def test5(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27")
        assert tag == bytearray().fromhex("09CA6C73F0B5C6C5FD587122D75F2AA3")

    def test6(self, ocb, key, nonce):
        header = bytearray(b"")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C")
        assert tag == bytearray().fromhex("9DB0CDF880F73E3E10D4EB3217766688")

    def test7(self, ocb, key, nonce):
        header = bytearray().fromhex("0001020304050607")
        plaintext = bytearray().fromhex("0001020304050607")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("C636B3A868F429BB")
        assert tag == bytearray().fromhex("8D059589EC3B6AC00CA31624BC3AF2C6")

    def test8(self, ocb, key, nonce):
        header = bytearray().fromhex("000102030405060708090A0B0C0D0E0F")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("52E48F5D19FE2D9869F0C4A4B3D2BE57")
        assert tag == bytearray().fromhex("4DA4391BCAC39D278C7A3F1FD39041E6")

    def test9(self, ocb, key, nonce):
        header = bytearray().fromhex("000102030405060708090A0B0C0D0E0F1011121314151617")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F1011121314151617")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB")
        assert tag == bytearray().fromhex("24B9AC3B9574D2202678E439D150F633")

    def test10(self, ocb, key, nonce):
        header = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27")
        assert tag == bytearray().fromhex("41A977C91D66F62C1E1FC30BC93823CA") 

    def test11(self, ocb, key, nonce):
        header = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
        plaintext = bytearray().fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
        ocb.set_params(key, nonce)
        tag, ciphertext = ocb.encrypt(plaintext, header)
        assert ciphertext == bytearray().fromhex("F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C")
        assert tag == bytearray().fromhex("65A92715A028ACD4AE6AFF4BFAA0D396") 






