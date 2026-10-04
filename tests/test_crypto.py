"""Crypto tests: the RFC 8439 vectors, the verifier records and the vault.

Run with::

    python3 -m unittest tests.test_crypto -v

The ChaCha20-Poly1305 vectors are the official ones from RFC 8439 sections
2.1.1, 2.3.2, 2.4.2, 2.5.2 and 2.8.2 - if they pass, the pure Python
implementation is correct.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sudaeon import _chacha, crypto  # noqa: E402


def unhex(text: str) -> bytes:
    return bytes.fromhex("".join(text.split()))


class QuarterRoundTests(unittest.TestCase):
    def test_rfc8439_2_1_1(self) -> None:
        state = [0] * 16
        state[0], state[1], state[2], state[3] = (0x11111111, 0x01020304,
                                                  0x9B8D6F43, 0x01234567)
        _chacha._quarter_round(state, 0, 1, 2, 3)
        self.assertEqual(state[:4], [0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB])

    def test_rfc8439_2_2_1_state(self) -> None:
        state = [0x879531E0, 0xC5ECF37D, 0x516461B1, 0xC9A62F8A,
                 0x44C20EF3, 0x3390AF7F, 0xD9FC690B, 0x2A5F714C,
                 0x53372767, 0xB00A5631, 0x974C541A, 0x359E9963,
                 0x5C971061, 0x3D631689, 0x2098D9D6, 0x91DBD320]
        _chacha._quarter_round(state, 2, 7, 8, 13)
        self.assertEqual(state, [0x879531E0, 0xC5ECF37D, 0xBDB886DC, 0xC9A62F8A,
                                 0x44C20EF3, 0x3390AF7F, 0xD9FC690B, 0xCFACAFD2,
                                 0xE46BEA80, 0xB00A5631, 0x974C541A, 0x359E9963,
                                 0x5C971061, 0xCCC07C79, 0x2098D9D6, 0x91DBD320])


class ChaCha20Tests(unittest.TestCase):
    KEY = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    def test_rfc8439_2_3_2_block(self) -> None:
        nonce = unhex("000000090000004a00000000")
        expected = unhex("""
            10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
            c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
            d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
            b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
        """)
        self.assertEqual(_chacha.chacha20_block(self.KEY, 1, nonce), expected)

    def test_rfc8439_2_3_2_keystream_second_block(self) -> None:
        nonce = unhex("000000000000004a00000000")
        self.assertEqual(_chacha.chacha20_block(self.KEY, 1, nonce)[:4], unhex("224f51f3"))
        self.assertEqual(_chacha.chacha20_block(self.KEY, 2, nonce)[:4], unhex("69a6749f"))

    def test_rfc8439_2_4_2_encryption(self) -> None:
        nonce = unhex("000000000000004a00000000")
        plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                     b"only one tip for the future, sunscreen would be it.")
        expected = unhex("""
            6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
            e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
            f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
            16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
            07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
            52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
            5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
            87 4d
        """)
        self.assertEqual(_chacha.chacha20_xor(plaintext, self.KEY, nonce, counter=1), expected)
        # and back again
        self.assertEqual(_chacha.chacha20_xor(expected, self.KEY, nonce, counter=1), plaintext)

    def test_stream_continues_over_blocks(self) -> None:
        nonce = unhex("000000090000004a00000000")
        first = _chacha.chacha20_block(self.KEY, 1, nonce)
        self.assertEqual(_chacha._keystream(self.KEY, nonce, 64, 1), first)
        self.assertEqual(_chacha._keystream(self.KEY, nonce, 128, 1),
                         first + _chacha.chacha20_block(self.KEY, 2, nonce))

    def test_key_length_is_checked(self) -> None:
        with self.assertRaises(ValueError):
            _chacha.chacha20_block(b"short", 0, b"\x00" * 12)


class Poly1305Tests(unittest.TestCase):
    def test_rfc8439_2_5_2(self) -> None:
        key = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        message = b"Cryptographic Forum Research Group"
        self.assertEqual(_chacha.poly1305_mac(message, key),
                         unhex("a8061dc1305136c6c22b8baf0c0127a9"))

    def test_empty_message(self) -> None:
        key = bytes(range(32))
        tag = _chacha.poly1305_mac(b"", key)
        self.assertEqual(len(tag), 16)
        self.assertEqual(tag, _chacha.poly1305_mac(b"", key))


class AeadTests(unittest.TestCase):
    KEY = unhex("""
        808182838485868788898a8b8c8d8e8f
        909192939495969798999a9b9c9d9e9f
    """)
    NONCE = unhex("070000004041424344454647")
    AAD = unhex("50515253c0c1c2c3c4c5c6c7")
    PLAINTEXT = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                 b"only one tip for the future, sunscreen would be it.")
    CIPHERTEXT = unhex("""
        d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
        a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
        3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
        1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
        92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
        fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
        3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
        61 16
    """)
    TAG = unhex("1ae10b594f09e26a7e902ecbd0600691")

    def test_rfc8439_2_8_2(self) -> None:
        blob = _chacha.aead_encrypt(self.KEY, self.NONCE, self.PLAINTEXT, self.AAD)
        self.assertEqual(blob, self.CIPHERTEXT + self.TAG)
        self.assertEqual(_chacha.aead_decrypt(self.KEY, self.NONCE, blob, self.AAD),
                         self.PLAINTEXT)

    def test_round_trip_without_aad(self) -> None:
        nonce = crypto.new_nonce()
        key = os.urandom(32)
        blob = _chacha.aead_encrypt(key, nonce, b"hello sudaeon", b"")
        self.assertEqual(_chacha.aead_decrypt(key, nonce, blob, b""), b"hello sudaeon")

    def test_tampered_tag_is_rejected(self) -> None:
        nonce = crypto.new_nonce()
        key = os.urandom(32)
        blob = bytearray(_chacha.aead_encrypt(key, nonce, b"payload", b""))
        blob[-1] ^= 0x01
        with self.assertRaises(_chacha.InvalidTag):
            _chacha.aead_decrypt(key, nonce, bytes(blob), b"")

    def test_tampered_ciphertext_is_rejected(self) -> None:
        nonce = crypto.new_nonce()
        key = os.urandom(32)
        blob = bytearray(_chacha.aead_encrypt(key, nonce, b"payload", b""))
        blob[0] ^= 0x80
        with self.assertRaises(_chacha.InvalidTag):
            _chacha.aead_decrypt(key, nonce, bytes(blob), b"")

    def test_wrong_aad_is_rejected(self) -> None:
        nonce = crypto.new_nonce()
        key = os.urandom(32)
        blob = _chacha.aead_encrypt(key, nonce, b"payload", b"one")
        with self.assertRaises(_chacha.InvalidTag):
            _chacha.aead_decrypt(key, nonce, blob, b"two")

    def test_short_blob_is_rejected(self) -> None:
        with self.assertRaises(_chacha.InvalidTag):
            _chacha.aead_decrypt(os.urandom(32), crypto.new_nonce(), b"tiny", b"")


class VerifierTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        record = crypto.make_verifier("correct horse battery staple", params={"n": 1024})
        self.assertTrue(crypto.verify_password("correct horse battery staple", record))
        self.assertFalse(crypto.verify_password("Correct horse battery staple", record))
        self.assertFalse(crypto.verify_password("", record))
        self.assertNotIn("correct horse battery staple", str(record))

    def test_salt_is_random(self) -> None:
        first = crypto.make_verifier("same-password", params={"n": 1024})
        second = crypto.make_verifier("same-password", params={"n": 1024})
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["hash"], second["hash"])

    def test_broken_record_is_refused(self) -> None:
        self.assertFalse(crypto.verify_password("x", {}))
        self.assertFalse(crypto.verify_password("x", {"salt": "zz", "hash": "zz"}))
        self.assertFalse(crypto.verify_password("x", {"salt": "00", "hash": "00"}))

    def test_vault_key_matches_verifier(self) -> None:
        record = crypto.make_verifier("hunter2-hunter2", params={"n": 1024})
        key = crypto.vault_key("hunter2-hunter2", record)
        self.assertEqual(crypto.verifier_digest(key),
                         bytes.fromhex(record["hash"]))


class VaultContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = crypto.make_verifier("a-strong-master-password", params={"n": 1024})
        self.key = crypto.vault_key("a-strong-master-password", self.record)

    def test_seal_and_unseal(self) -> None:
        blob = crypto.seal(self.key, b"top secret")
        self.assertTrue(blob.startswith(crypto.VAULT_MAGIC))
        self.assertEqual(crypto.unseal(self.key, blob), b"top secret")

    def test_json_round_trip(self) -> None:
        payload = {"policy": {"enabled": True}, "recovery_key": "ABCDE-FGHJK"}
        blob = crypto.encrypt_json(self.key, payload)
        self.assertEqual(crypto.decrypt_json(self.key, blob), payload)

    def test_wrong_key_fails(self) -> None:
        blob = crypto.seal(self.key, b"top secret")
        wrong = crypto.vault_key("not-the-password", self.record)
        with self.assertRaises(_chacha.InvalidTag):
            crypto.unseal(wrong, blob)

    def test_foreign_container_fails(self) -> None:
        with self.assertRaises(_chacha.InvalidTag):
            crypto.unseal(self.key, b"NOTSUDAEON" + b"\x00" * 40)


class RecoveryKeyTests(unittest.TestCase):
    def test_shape(self) -> None:
        key = crypto.new_recovery_key()
        self.assertEqual(len(key), crypto.RECOVERY_LENGTH)
        for character in key:
            self.assertIn(character, crypto.CROCKFORD)
        self.assertNotIn("I", key)
        self.assertNotIn("O", key)
        self.assertNotIn("U", key)

    def test_formatting(self) -> None:
        key = crypto.new_recovery_key()
        pretty = crypto.format_recovery_key(key)
        self.assertEqual(pretty.replace("-", ""), key)
        self.assertEqual(len(pretty.split("-")), 4)
        self.assertEqual(crypto.normalize_recovery_key(pretty.lower()), key)

    def test_confusable_characters(self) -> None:
        self.assertEqual(crypto.normalize_recovery_key("il0o-1"), "11001")
        key = "ABCDE-FGHJK-MNPQR-STVWX"
        digest = crypto.recovery_digest(key)
        self.assertTrue(crypto.verify_recovery_key("abcde fghjk mnpqr stvwx", digest))
        self.assertFalse(crypto.verify_recovery_key("ABCDE-FGHJK-MNPQR-STVWY", digest))

    def test_digest_is_stable(self) -> None:
        key = crypto.new_recovery_key()
        self.assertEqual(crypto.recovery_digest(key), crypto.recovery_digest(key))


class PasswordQualityTests(unittest.TestCase):
    def test_short_passwords_are_rejected(self) -> None:
        problems = crypto.password_problems("abc")
        self.assertTrue(any("8 characters" in problem for problem in problems))

    def test_common_passwords_are_flagged(self) -> None:
        problems = crypto.password_problems("password")
        self.assertTrue(any("too often" in problem for problem in problems))

    def test_repeated_characters_are_flagged(self) -> None:
        problems = crypto.password_problems("aaaaaaaaaaaa")
        self.assertTrue(problems)

    def test_good_password_has_no_problems(self) -> None:
        self.assertEqual(crypto.password_problems("Cedar-Basil-Quartz-77"), [])

    def test_username_check(self) -> None:
        self.assertTrue(crypto.password_problems("alexander-the-great",
                                                 username="alexander"))

    def test_score_and_suggestion(self) -> None:
        self.assertEqual(crypto.password_score(""), 0)
        self.assertGreaterEqual(crypto.password_score("Cedar-Basil-Quartz-77"), 3)
        suggestion = crypto.suggest_passphrase()
        self.assertGreaterEqual(len(suggestion.split("-")), 3)
        self.assertEqual(crypto.password_problems(suggestion), [])


class ScryptVectorTests(unittest.TestCase):
    """The published scrypt and PBKDF2 vectors.

    RFC 7914 section 12 gives four scrypt examples; the last one needs about
    a gigabyte of memory, so it only runs when ``SUDAEON_SLOW_TESTS`` is set.
    Section 11 gives the PBKDF2-HMAC-SHA-256 examples.

    They pin the derivation down independently of :mod:`hashlib`, which is
    what protects the verifier records of existing installations during a
    refactor.
    """

    def _derived(self, password: str, salt: str, n: int, r: int, p: int) -> bytes:
        params = {"kdf": "scrypt", "n": n, "r": r, "p": p, "dklen": 64}
        return crypto.derive_key(password, salt.encode("utf-8"), params=params, dklen=64)

    def test_rfc7914_12_empty_password(self) -> None:
        # scrypt ("", "", N=16, r=1, p=1, dkLen=64)
        expected = unhex("""
            77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
            f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
            fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
            e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
        """)
        self.assertEqual(self._derived("", "", 16, 1, 1), expected)

    def test_rfc7914_12_password_nacl(self) -> None:
        # scrypt ("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
        expected = unhex("""
            fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
            7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
            2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
            c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
        """)
        self.assertEqual(self._derived("password", "NaCl", 1024, 8, 16), expected)

    def test_rfc7914_12_pleaseletmein(self) -> None:
        # scrypt ("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
        expected = unhex("""
            70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
            fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
            d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
            e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
        """)
        self.assertEqual(self._derived("pleaseletmein", "SodiumChloride", 16384, 8, 1),
                         expected)

    @unittest.skipUnless(os.environ.get("SUDAEON_SLOW_TESTS"),
                         "needs about 1 GiB of memory; set SUDAEON_SLOW_TESTS=1")
    def test_rfc7914_12_sodium_chloride_slow(self) -> None:
        # scrypt ("pleaseletmein", "SodiumChloride", N=1048576, r=8, p=1, dkLen=64)
        expected = unhex("""
            21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
            ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
            8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
            37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
        """)
        self.assertEqual(self._derived("pleaseletmein", "SodiumChloride", 1 << 20, 8, 1),
                         expected)

    def test_pbkdf2_hmac_sha256_rfc7914_11(self) -> None:
        import hashlib
        self.assertEqual(
            hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 1, dklen=64),
            unhex("""
                55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
                f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
                49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
                7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
            """))
        self.assertEqual(
            hashlib.pbkdf2_hmac("sha256", b"Password", b"NaCl", 80000, dklen=64),
            unhex("""
                4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9
                64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56
                a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17
                6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d
            """))


class KdfGuardTests(unittest.TestCase):
    """check_kdf() must never make an existing vault unreadable."""

    def test_defaults_are_used_for_garbage(self) -> None:
        self.assertEqual(crypto.check_kdf(None), crypto.DEFAULT_KDF)
        self.assertEqual(crypto.check_kdf("scrypt"), crypto.DEFAULT_KDF)
        self.assertEqual(crypto.check_kdf({"kdf": "bcrypt", "n": 4}), crypto.DEFAULT_KDF)

    def test_out_of_range_values_fall_back(self) -> None:
        settings = crypto.check_kdf({"n": 1, "r": 0, "p": 10 ** 6, "dklen": 4})
        self.assertEqual(settings, crypto.DEFAULT_KDF)

    def test_valid_values_are_kept(self) -> None:
        settings = crypto.check_kdf({"kdf": "scrypt", "n": 1024, "r": 2, "p": 3, "dklen": 64})
        self.assertEqual(settings, {"kdf": "scrypt", "n": 1024, "r": 2, "p": 3, "dklen": 64})

    def test_weak_parameter_detection(self) -> None:
        self.assertTrue(crypto.kdf_is_weak({"n": 16, "r": 1, "p": 1}))
        self.assertFalse(crypto.kdf_is_weak(crypto.default_params()))

    def test_recovery_key_aliases(self) -> None:
        key = crypto.generate_recovery_key()
        self.assertEqual(crypto.normalize_recovery_key(key), key)
        self.assertEqual(crypto.recovery_key_digest(key), crypto.recovery_digest(key))

if __name__ == "__main__":
    unittest.main(verbosity=2)
