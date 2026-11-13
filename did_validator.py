"""Validate the format of an Ed25519 did:key identifier."""
import sys
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_PREFIX = bytes([0xED, 0x01])
def base58_decode(value):
    number = 0
    for char in value:
        if char not in ALPHABET:
            raise ValueError("Invalid Base58 character")
        number = number * 58 + ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + decoded
def validate_did(did):
    if not did.startswith("did:key:z"):
        return False, "Expected an Ed25519 did:key identifier"
    try:
        decoded = base58_decode(did[len("did:key:z"):])
    except ValueError:
        return False, "Invalid Base58BTC encoding"
    if len(decoded) != 34:
        return False, "Incorrect public key length"
    if decoded[:2] != ED25519_PREFIX:
        return False, "Unsupported key type; expected Ed25519"
    return True, "Valid Ed25519 DID format"
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python did_validator.py "did:key:z..."')
        sys.exit(1)
    valid, message = validate_did(sys.argv[1])
    print("VALID" if valid else "INVALID")
    print(message)
    sys.exit(0 if valid else 1)
