"""Cryptography for the master password.

What is stored, and where
-------------------------
The master password itself is *never* stored, in clear or encrypted form.  Two
derived values are kept in ``/var/lib/sudaeon`` (both mode 0600, root):

``master.verifier``
    A JSON record with the scrypt parameters, a random salt and
    ``sha256("SUDAEON-VERIFIER-V1" || scrypt(password, salt))``.  Checking a
    password means re-deriving the key and comparing digests in constant time.

``vault.enc``
    The encrypted container requested by the design: it holds a copy of the
    verifier, the recovery key, the policy and the change history, sealed with
    ChaCha20-Poly1305 under the scrypt key.  It is a *backup* of the settings, so
    a forgotten master password does not lose the recovery key as long as the
    recovery key is available.

``recovery.verifier``
    ``sha256("SUDAEON-RECOVERY-V1" || recovery-key)``.  The recovery key is 20
    characters of Crockford base32 (100 bits); it is only used to set a new
    master password from the GUI or the command line.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import unicodedata
from typing import Any, Iterable

from . import _chacha

# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

KDF_NAME = "scrypt"
KDF_N = 1 << 15            # 32768
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32
SALT_BYTES = 16
NONCE_BYTES = 12
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 1024

VAULT_MAGIC = b"SUDAEONVAULT1"
VAULT_FORMAT = 1

VERIFIER_PREFIX = b"SUDAEON-VERIFIER-V1"
RECOVERY_PREFIX = b"SUDAEON-RECOVERY-V1"

#: Characters that cannot be confused in a handwritten recovery key.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CONFUSABLE = str.maketrans({"I": "1", "L": "1", "O": "0", "U": "V"})

RECOVERY_LENGTH = 20
RECOVERY_GROUP = 5


#: The parameters new installations use.
DEFAULT_KDF: dict[str, Any] = {"kdf": KDF_NAME, "n": KDF_N, "r": KDF_R, "p": KDF_P,
                               "dklen": KDF_DKLEN}

#: Refuse absurd values coming from a hand edited policy file.
MIN_N = 2
MAX_N = 1 << 22
MIN_N_RECOMMENDED = 1 << 14
MAX_R = 32
MAX_P = 16


def default_params() -> dict[str, Any]:
    return dict(DEFAULT_KDF)


def check_kdf(params: Any) -> dict[str, Any]:
    """Validate KDF parameters and return a usable dictionary.

    Bad values fall back to the defaults instead of raising: the policy file
    must never make the vault unreadable.
    """
    settings = default_params()
    if not isinstance(params, dict):
        return settings
    if str(params.get("kdf") or KDF_NAME) not in ("scrypt",):
        return settings
    for key, low, high in (("n", MIN_N, MAX_N), ("r", 1, MAX_R), ("p", 1, MAX_P),
                           ("dklen", 16, 64)):
        try:
            value = int(params.get(key, settings[key]))
        except (TypeError, ValueError):
            continue
        if low <= value <= high:
            settings[key] = value
    return settings


def kdf_is_weak(params: Any) -> bool:
    settings = check_kdf(params)
    return int(settings["n"]) < MIN_N_RECOMMENDED


def generate_recovery_key() -> str:
    """Backwards compatible name for :func:`new_recovery_key`."""
    return new_recovery_key()


def recovery_key_digest(key: str) -> str:
    """Backwards compatible name for :func:`recovery_digest`."""
    return recovery_digest(key)


def params_from(record: dict[str, Any] | None) -> dict[str, Any]:
    params = default_params()
    if not record:
        return params
    for key in ("kdf", "n", "r", "p", "dklen"):
        if record.get(key) not in (None, ""):
            params[key] = record[key]
    params["n"] = int(params["n"])
    params["r"] = int(params["r"])
    params["p"] = int(params["p"])
    params["dklen"] = int(params.get("dklen") or KDF_DKLEN)
    return params


def derive_key(password: str, salt: bytes, *, params: dict[str, Any] | None = None,
               n: int | None = None, r: int | None = None, p: int | None = None,
               dklen: int = KDF_DKLEN) -> bytes:
    """Derive the vault key from the master password."""
    settings = params_from(params)
    if n is not None:
        settings["n"] = n
    if r is not None:
        settings["r"] = r
    if p is not None:
        settings["p"] = p
    settings["dklen"] = dklen or int(settings.get("dklen") or KDF_DKLEN)
    secret = password.encode("utf-8")
    if len(secret) > MAX_PASSWORD_BYTES:
        raise ValueError("the password is too long")
    return hashlib.scrypt(secret, salt=salt, n=int(settings["n"]), r=int(settings["r"]),
                          p=int(settings["p"]), dklen=int(settings["dklen"]),
                          maxmem=_maxmem(int(settings["n"]), int(settings["r"])))


def _maxmem(n: int, r: int) -> int:
    needed = 128 * n * r * 2
    return max(needed, 64 * 1024 * 1024)


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def new_nonce() -> bytes:
    return os.urandom(NONCE_BYTES)


# ---------------------------------------------------------------------------
# password verification records
# ---------------------------------------------------------------------------

def verifier_digest(key: bytes) -> bytes:
    return hashlib.sha256(VERIFIER_PREFIX + key).digest()


def make_verifier(password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = params_from(params)
    salt = new_salt()
    key = derive_key(password, salt, params=settings)
    return {
        "version": 1,
        "kdf": settings["kdf"],
        "n": int(settings["n"]),
        "r": int(settings["r"]),
        "p": int(settings["p"]),
        "dklen": int(settings["dklen"]),
        "salt": salt.hex(),
        "hash": verifier_digest(key).hex(),
        "created": _now(),
    }


def verify_password(password: str, record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or not record.get("salt") or not record.get("hash"):
        return False
    try:
        salt = bytes.fromhex(str(record["salt"]))
        expected = bytes.fromhex(str(record["hash"]))
    except ValueError:
        return False
    try:
        key = derive_key(password, salt, params=params_from(record))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(verifier_digest(key), expected)


def vault_key(password: str, record: dict[str, Any]) -> bytes:
    """Derive the key that opens the vault for a verified password."""
    salt = bytes.fromhex(str(record["salt"]))
    return derive_key(password, salt, params=params_from(record))


# ---------------------------------------------------------------------------
# recovery keys
# ---------------------------------------------------------------------------

def new_recovery_key() -> str:
    """A fresh 20 character recovery key (100 bits of entropy)."""
    return "".join(secrets.choice(CROCKFORD) for _ in range(RECOVERY_LENGTH))


def normalize_recovery_key(text: str) -> str:
    cleaned = unicodedata.normalize("NFKD", str(text or "")).upper()
    cleaned = cleaned.replace("-", "").replace(" ", "").replace("_", "")
    cleaned = cleaned.translate(CONFUSABLE)
    return "".join(character for character in cleaned if character in CROCKFORD)


def format_recovery_key(key: str) -> str:
    normalized = normalize_recovery_key(key)
    groups = [normalized[index:index + RECOVERY_GROUP]
              for index in range(0, len(normalized), RECOVERY_GROUP)]
    return "-".join(group for group in groups if group)


def recovery_digest(key: str) -> str:
    normalized = normalize_recovery_key(key)
    return hashlib.sha256(RECOVERY_PREFIX + normalized.encode("ascii")).hexdigest()


def verify_recovery_key(key: str, digest: str) -> bool:
    return hmac.compare_digest(recovery_digest(key), str(digest or ""))


def recovery_key_display(key: str) -> str:
    """Human readable recovery key, grouped for copying."""
    return format_recovery_key(key)


# ---------------------------------------------------------------------------
# vault container
# ---------------------------------------------------------------------------

def seal(key: bytes, plaintext: bytes, *, aad: bytes = b"", magic: bytes = VAULT_MAGIC) -> bytes:
    nonce = new_nonce()
    body = _chacha.aead_encrypt(key, nonce, plaintext, aad)
    return magic + nonce + body


def unseal(key: bytes, blob: bytes, *, aad: bytes = b"", magic: bytes = VAULT_MAGIC) -> bytes:
    if not blob.startswith(magic):
        raise _chacha.InvalidTag("this is not a Sudaeon container")
    body = blob[len(magic):]
    if len(body) < NONCE_BYTES + 16:
        raise _chacha.InvalidTag("the container is truncated")
    nonce, ciphertext = body[:NONCE_BYTES], body[NONCE_BYTES:]
    return _chacha.aead_decrypt(key, nonce, ciphertext, aad)


def encrypt_json(key: bytes, payload: Any, *, aad: bytes = b"",
                 magic: bytes = VAULT_MAGIC) -> bytes:
    import json
    return seal(key, json.dumps(payload, sort_keys=True).encode("utf-8"), aad=aad, magic=magic)


def decrypt_json(key: bytes, blob: bytes, *, aad: bytes = b"",
                 magic: bytes = VAULT_MAGIC) -> Any:
    import json
    return json.loads(unseal(key, blob, aad=aad, magic=magic).decode("utf-8"))


# ---------------------------------------------------------------------------
# self describing vault container
#
# The header carries the KDF parameters, the salt and the nonce, and is used as
# associated data, so an attacker cannot weaken the parameters or swap salts
# without the tag check failing.
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Raised when a container cannot be decrypted or a parameter is invalid."""


def _put32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _get32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def vault_header(salt: bytes, nonce: bytes, params: dict[str, Any]) -> bytes:
    settings = params_from(params)
    return (VAULT_MAGIC + bytes([VAULT_FORMAT, 1]) + _put32(int(settings["n"]))
            + _put32(int(settings["r"])) + _put32(int(settings["p"]))
            + _put32(int(settings["dklen"])) + bytes([len(salt)]) + salt
            + bytes([len(nonce)]) + nonce)


def parse_vault_header(blob: bytes) -> dict[str, Any]:
    """Split a container into header, salt, nonce and KDF parameters."""
    if not blob.startswith(VAULT_MAGIC):
        raise CryptoError("this is not a Sudaeon vault")
    position = len(VAULT_MAGIC)
    if len(blob) < position + 2:
        raise CryptoError("the vault is truncated")
    version, kdf_id = blob[position], blob[position + 1]
    if version != VAULT_FORMAT or kdf_id != 1:
        raise CryptoError(f"unsupported vault version {version}")
    position += 2
    if len(blob) < position + 16:
        raise CryptoError("the vault is truncated")
    params = {"kdf": KDF_NAME, "n": _get32(blob, position),
              "r": _get32(blob, position + 4), "p": _get32(blob, position + 8),
              "dklen": _get32(blob, position + 12)}
    position += 16
    salt_length = blob[position]
    position += 1
    if len(blob) < position + salt_length + 1:
        raise CryptoError("the vault is truncated")
    salt = blob[position:position + salt_length]
    position += salt_length
    nonce_length = blob[position]
    position += 1
    if len(blob) < position + nonce_length + 16:
        raise CryptoError("the vault is truncated")
    nonce = blob[position:position + nonce_length]
    position += nonce_length
    if int(params["n"]) < 2 or int(params["r"]) < 1 or int(params["p"]) < 1:
        raise CryptoError("the vault parameters are invalid")
    return {"header": blob[:position], "salt": salt, "nonce": nonce,
            "params": params, "payload": blob[position:], "version": version}


def encrypt_vault(password: str, payload: Any, *, params: dict[str, Any] | None = None,
                  magic: bytes = VAULT_MAGIC) -> bytes:
    """Seal ``payload`` (JSON) with a key derived from ``password``."""
    del magic
    settings = params_from(params)
    salt = new_salt()
    nonce = new_nonce()
    header = vault_header(salt, nonce, settings)
    key = derive_key(password, salt, params=settings)
    body = _chacha.aead_encrypt(key, nonce, _json_bytes(payload), header)
    return header + body


def decrypt_vault(password: str, blob: bytes) -> Any:
    """Open a container produced by :func:`encrypt_vault`."""
    parts = parse_vault_header(blob)
    key = derive_key(password, parts["salt"], params=parts["params"])
    try:
        plaintext = _chacha.aead_decrypt(key, parts["nonce"], parts["payload"],
                                        parts["header"])
    except _chacha.InvalidTag as exc:
        raise CryptoError(str(exc)) from exc
    return _json_loads(plaintext)


def vault_parameters(blob: bytes) -> dict[str, Any]:
    """The KDF parameters of a container, for display in the interface."""
    parts = parse_vault_header(blob)
    return dict(parts["params"], version=parts["version"])


def _json_bytes(payload: Any) -> bytes:
    import json
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


def _json_loads(data: bytes) -> Any:
    import json
    return json.loads(data.decode("utf-8"))


# ---------------------------------------------------------------------------
# password quality
# ---------------------------------------------------------------------------

COMMON_WORDS = {
    "password", "passwort", "123456", "12345678", "123456789", "qwerty", "qwertyuiop",
    "letmein", "welcome", "admin", "administrator", "root", "sudaeon", "master",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
    "abc123", "111111", "000000", "password1", "p@ssw0rd", "changeme", "secret",
}

WORDLIST = (
    "amber", "anchor", "apple", "april", "arrow", "atlas", "autumn", "baker", "bamboo",
    "basil", "beacon", "berry", "birch", "bison", "blossom", "breeze", "bridge", "bronze",
    "brook", "cabin", "cactus", "candle", "canyon", "castle", "cedar", "cherry", "cinnamon",
    "cloud", "clover", "cobalt", "comet", "copper", "coral", "cotton", "crater", "cricket",
    "crystal", "daisy", "dawn", "delta", "diamond", "dolphin", "dragonfly", "eagle",
    "ember", "falcon", "feather", "fern", "fjord", "forest", "fountain", "garden", "ginger",
    "glacier", "granite", "harbor", "hazel", "heron", "hickory", "honey", "indigo", "iris",
    "island", "ivory", "jasmine", "juniper", "kestrel", "lantern", "larkspur", "lavender",
    "lemon", "lilac", "linden", "lotus", "mango", "maple", "marble", "meadow", "meteor",
    "mint", "mist", "mulberry", "nebula", "nectar", "oasis", "ocean", "olive", "onyx",
    "orchid", "otter", "pebble", "pepper", "petal", "pine", "plum", "pond", "poppy",
    "quartz", "quince", "raven", "reef", "river", "robin", "saffron", "sage", "sail",
    "sequoia", "shadow", "silver", "sparrow", "spruce", "star", "stone", "storm",
    "summit", "sunset", "thistle", "thunder", "tiger", "topaz", "tulip", "valley",
    "velvet", "violet", "walnut", "willow", "winter", "wren", "zephyr",
)


def suggest_passphrase(words: int = 4) -> str:
    """A memorable master password, for the setup wizard's suggestion button."""
    chosen = [secrets.choice(WORDLIST) for _ in range(max(3, words))]
    return "-".join(chosen)


def password_problems(password: str, *, minimum: int = MIN_PASSWORD_LENGTH,
                      username: str = "") -> list[str]:
    problems: list[str] = []
    if len(password) < minimum:
        problems.append(f"Use at least {minimum} characters.")
    if password.strip() != password or not password:
        problems.append("Do not start or end with a space.")
    lowered = password.lower()
    if lowered in COMMON_WORDS:
        problems.append("This password is used far too often.")
    if password.isdigit():
        problems.append("Do not use only digits.")
    if username and username.lower() in lowered and len(username) > 2:
        problems.append("Do not put your user name in the password.")
    if len(set(password)) == 1 and len(password) > 1:
        problems.append("Do not repeat a single character.")
    return problems


def password_score(password: str) -> int:
    """0 (very weak) to 4 (strong).  Used for the strength bar in setup."""
    if not password:
        return 0
    score = 0
    length = len(password)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    variety = 0
    if any(character.islower() for character in password):
        variety += 1
    if any(character.isupper() for character in password):
        variety += 1
    if any(character.isdigit() for character in password):
        variety += 1
    if any(not character.isalnum() for character in password):
        variety += 1
    if variety >= 3 and length >= 10:
        score += 1
    if variety >= 4 or length >= 16:
        score += 1
    if password.lower() in COMMON_WORDS:
        score = min(score, 1)
    return max(0, min(score, 4))


def strength_label(score: int) -> str:
    return ("Very weak", "Weak", "Fair", "Good", "Strong")[max(0, min(score, 4))]


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

def _now() -> str:
    from .util import now_iso
    return now_iso()


def constant_time_compare(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


def random_token(bytes_count: int = 16) -> str:
    return secrets.token_hex(bytes_count)


def digest_of(*parts: Iterable[bytes]) -> str:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part)
    return hasher.hexdigest()
