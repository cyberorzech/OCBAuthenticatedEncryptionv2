import pytest

from src.keygen import Keygen


class Test_AES:
    @pytest.fixture
    def plaintext(self):
        return bytearray(b"To jest test1234")

    @pytest.fixture
    def key(self):
        return 1

    def test_dummy(self):
        assert 1 == 1


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
        TESTS_AMOUNT = 100
        key_list = list()
        for x in range(0, TESTS_AMOUNT):
            key = keygen.get_key()
            assert key not in key_list
            key_list.append(key)
