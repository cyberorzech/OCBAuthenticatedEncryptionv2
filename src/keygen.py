import secrets


class Keygen:
    def __init__(cls, keylen=16) -> None:
        cls._keylen = keylen

    def get_key(cls):
        return secrets.token_hex(cls._keylen).upper()
