import secrets


class Keygen:
    def __init__(cls, keylen=16) -> None:
        cls._keylen = keylen

    def get_key(cls):
        return secrets.token_hex(cls._keylen).upper()

def main():
    raise NotImplementedError("Use as package")

if __name__ == "__main__":
    main()