"""Pure-Python ChaCha20 and Poly1305 (RFC 8439).

Sudaeon must not depend on PyCryptodome or cryptography being installed on the
target machine, but the master password container still deserves a real AEAD.
This module implements the RFC 8439 constructions directly - the test-suite
checks them against the official test vectors in ``tests/test_crypto.py``.

Only the pieces Sudaeon needs are here:

* :func:`chacha20_block`    - the 64 byte keystream block
* :func:`chacha20_xor`      - the stream cipher (counter starts at 1)
* :func:`poly1305_mac`      - the one time authenticator
* :func:`aead_encrypt`      - ChaCha20-Poly1305 AEAD, returns ciphertext + tag
* :func:`aead_decrypt`      - verification and decryption
"""

from __future__ import annotations

import struct

__all__ = [
    "InvalidTag",
    "aead_decrypt",
    "aead_encrypt",
    "chacha20_block",
    "chacha20_xor",
    "poly1305_mac",
]

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"
P1305 = (1 << 130) - 5
CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


class InvalidTag(Exception):
    """Raised when the Poly1305 tag does not match."""


# ---------------------------------------------------------------------------
# ChaCha20
# ---------------------------------------------------------------------------

def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & MASK32
    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & MASK32
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & MASK32
    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & MASK32


def _key_words(key: bytes) -> tuple[int, ...]:
    if len(key) != 32:
        raise ValueError("ChaCha20 needs a 32 byte key")
    return struct.unpack("<8I", key)


def _state(key_words, counter: int, nonce_words) -> list[int]:
    return [
        CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
        key_words[0], key_words[1], key_words[2], key_words[3],
        key_words[4], key_words[5], key_words[6], key_words[7],
        counter & MASK32, nonce_words[0], nonce_words[1], nonce_words[2],
    ]


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64 byte ChaCha20 keystream block (RFC 8439 section 2.3)."""
    if len(nonce) == 12:
        nonce_words = struct.unpack("<3I", nonce)
    elif len(nonce) == 8:
        nonce_words = (0, struct.unpack("<2I", nonce)[0], struct.unpack("<2I", nonce)[1])
    else:
        raise ValueError("the nonce must be 8 or 12 bytes")
    state = _state(_key_words(key), counter, nonce_words)
    working = list(state)
    for _ in range(10):                      # 20 rounds = 10 double rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def _keystream(key: bytes, nonce: bytes, length: int, counter: int = 1) -> bytes:
    blocks = []
    remaining = length
    index = counter
    while remaining > 0:
        block = chacha20_block(key, index, nonce)
        blocks.append(block[:remaining] if remaining < 64 else block)
        remaining -= 64
        index += 1
    return b"".join(blocks)


def chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    """Encrypt/decrypt ``data`` with the ChaCha20 stream cipher."""
    if not data:
        return b""
    stream = _keystream(key, nonce, len(data), counter)
    return bytes(a ^ b for a, b in zip(data, stream))


# ---------------------------------------------------------------------------
# Poly1305
# ---------------------------------------------------------------------------

def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """The Poly1305 one time authenticator (RFC 8439 section 2.5)."""
    if len(key) != 32:
        raise ValueError("Poly1305 needs a 32 byte key")
    r = int.from_bytes(key[:16], "little") & CLAMP
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        number = int.from_bytes(chunk + b"\x01", "little")
        accumulator = ((accumulator + number) * r) % P1305
    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------

def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def _poly_key(key: bytes, nonce: bytes) -> bytes:
    return chacha20_block(key, 0, nonce)[:32]


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
            + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """ChaCha20-Poly1305: returns ``ciphertext || tag``."""
    if len(nonce) != 12:
        raise ValueError("the nonce must be 12 bytes")
    ciphertext = chacha20_xor(plaintext, key, nonce, counter=1)
    tag = poly1305_mac(_mac_data(aad, ciphertext), _poly_key(key, nonce))
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Verify and decrypt ``ciphertext || tag``.  Raises :class:`InvalidTag`."""
    if len(nonce) != 12:
        raise ValueError("the nonce must be 12 bytes")
    if len(blob) < 16:
        raise InvalidTag("the encrypted container is too short")
    ciphertext, tag = blob[:-16], blob[-16:]
    expected = poly1305_mac(_mac_data(aad, ciphertext), _poly_key(key, nonce))
    if not constant_time_compare(tag, expected):
        raise InvalidTag("the container was modified or the password is wrong")
    return chacha20_xor(ciphertext, key, nonce, counter=1)


def constant_time_compare(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    difference = 0
    for a, b in zip(left, right):
        difference |= a ^ b
    return difference == 0
