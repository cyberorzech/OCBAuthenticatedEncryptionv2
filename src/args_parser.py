import argparse


class ArgParser:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Ubuntu-vulns data downloader")
        parser.add_argument(
            "-m",
            "--mode",
            metavar="mode",
            required=True,
            help="Choose encrypt or decrypt",
            choices=("encrypt", "decrypt", "demo"),
        )
        parser.add_argument(
            "-p",
            "--plaintext",
            metavar="plaintext",
            required=False,
            help="Enter plaintext to encrypt",
            default="Test message",
        )
        parser.add_argument(
            "-c",
            "--ciphertext",
            metavar="ciphertext",
            required=False,
            help="Enter ciphertext to decrypt",
            default="\xbc\x94\xf2\xd4",
        )
        parser.add_argument(
            "-a",
            "--header",
            metavar="header",
            required=False,
            help="Enter message's header",
            default="",
        )
        parser.add_argument(
            "-n",
            "--nonce",
            metavar="nonce",
            required=False,
            help="Enter nonce",
            default="000102030405060708090A0B0C0D0E0F",
        )
        parser.add_argument(
            "-k",
            "--key",
            metavar="key",
            required=False,
            help="Enter key",
            default="1B4C45B66B164D0DB6C62E4614038F70",
        )
        parser.add_argument(
            "-t",
            "--tag",
            metavar="tag",
            required=False,
            help="Enter tag",
            default=")\xec\xf4\xecp\xee\xd0\xf6\x02G\xb3\x1edK\xc1\xb7",
        )
        self.args = parser.parse_args()

    def get_args(self):
        return self.args

    def validate_args(self, args):
        if args.mode == "encrypt" or args.mode == "demo":
            if not isinstance(args.plaintext, str):
                raise TypeError("Plaintext must be string")
            if not isinstance(args.header, str):
                raise TypeError("Header must be string")
            if not isinstance(args.nonce, str):
                raise TypeError("Nonce must be string")
            if not isinstance(args.key, str):
                raise TypeError("Key must be string")
            if len(args.nonce) != 32:
                raise ValueError("Nonce must be string of length 32")
            if len(args.key) != 32:
                raise ValueError("Key must be string of length 32")
        elif args.mode == "decrypt":
            if not isinstance(args.header, str):
                raise TypeError("Header must be string")
            if not isinstance(args.ciphertext, str):
                raise TypeError("Ciphertext must be string")
            if not isinstance(args.tag, str):
                raise TypeError("Tag must be string")
            if not isinstance(args.nonce, str):
                raise TypeError("Nonce must be string")
            if not isinstance(args.key, str):
                raise TypeError("Key must be string")
            if len(args.nonce) != 32:
                raise ValueError("Nonce must be string of length 32")
            if len(args.key) != 32:
                raise ValueError("Key must be string of length 32")
