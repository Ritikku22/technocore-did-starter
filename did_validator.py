
"""Validate the format of an Ed25519 did:key identifier."""

import argparse
import sys

__version__ = "1.1.0"

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_PREFIX = bytes([0xED, 0x01])


def base58_decode(value):
    """Decode a Base58BTC string into bytes."""
    number = 0

    for char in value:
        if char not in ALPHABET:
            raise ValueError("Invalid Base58 character")
        number = number * 58 + ALPHABET.index(char)

    decoded = (
        number.to_bytes((number.bit_length() + 7) // 8, "big")
        if number else b""
    )

    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + decoded


def validate_did(did):
    """Check the format of an Ed25519 did:key identifier."""

    if not did.startswith("did:key:z"):
        return False, "Expected an Ed25519 did:key identifier"

    encoded_key = did[len("did:key:z"):]

    if not encoded_key:
        return False, "Missing public key"

    try:
        decoded = base58_decode(encoded_key)
    except ValueError:
        return False, "Invalid Base58BTC encoding"

    if len(decoded) != 34:
        return False, "Incorrect public key length"

    if decoded[:2] != ED25519_PREFIX:
        return False, "Unsupported key type; expected Ed25519"

    return True, "Valid Ed25519 DID format"


def main():
    parser = argparse.ArgumentParser(
        description="Validate an Ed25519 did:key identifier."
    )

    parser.add_argument(
        "did",
        nargs="?",
        help="DID identifier to validate"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed validation information"
    )

    args = parser.parse_args()

    if not args.did:
        parser.print_help()
        return 1

    valid, message = validate_did(args.did)

    print("VALID" if valid else "INVALID")
    print(message)

    if args.verbose:
        print(f"DID checked: {args.did}")
        print(f"Validator version: {__version__}")

    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
