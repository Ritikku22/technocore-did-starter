
import unittest

from did_validator import validate_did


def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded

    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + (encoded or "")


class TestDIDValidator(unittest.TestCase):

    def test_valid_ed25519_did(self):
        did = "did:key:z6MkjjNTn77WXWo7B2Nu6hXPTD18TfmQNiuYxGM8aMxHC4Vn"
        self.assertTrue(validate_did(did)[0])

    def test_invalid_prefix(self):
        self.assertFalse(validate_did("did:web:example.com")[0])

    def test_invalid_base58_character(self):
        self.assertFalse(validate_did("did:key:z0invalid")[0])

    def test_incorrect_key_length(self):
        encoded = base58_encode(bytes([0xED, 0x01, 0x01]))
        self.assertFalse(validate_did("did:key:z" + encoded)[0])

    def test_unsupported_key_type(self):
        key = bytes([0x12, 0x20]) + bytes(32)
        encoded = base58_encode(key)
        self.assertFalse(validate_did("did:key:z" + encoded)[0])


if __name__ == "__main__":
    unittest.main()
