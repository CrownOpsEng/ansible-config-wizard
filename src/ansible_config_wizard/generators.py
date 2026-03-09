from __future__ import annotations

import base64
import hashlib
import secrets
import string
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


PASSWORD_ALPHABET = string.ascii_letters + string.digits + "-_"
PASSPHRASE_WORDS = (
    "anchor", "amber", "apple", "apron", "atlas", "aurora", "autumn", "bamboo",
    "beacon", "berry", "birch", "breeze", "brook", "cabin", "cactus", "canary",
    "cedar", "chisel", "cinder", "citrus", "clover", "cobalt", "comet", "copper",
    "coral", "crown", "dawn", "delta", "ember", "falcon", "field", "forest",
    "frost", "garden", "glacier", "granite", "harbor", "harvest", "hazel", "helium",
    "horizon", "indigo", "iris", "island", "juniper", "lagoon", "lantern", "laurel",
    "maple", "meadow", "mercury", "meteor", "minnow", "mist", "moss", "nectar",
    "north", "oasis", "ocean", "onyx", "orchid", "otter", "pepper", "pine",
    "prairie", "quartz", "quill", "rain", "raven", "reef", "ridge", "river",
    "sage", "saffron", "sierra", "silver", "solstice", "spruce", "stone", "summit",
    "sunrise", "thicket", "timber", "topaz", "trail", "valley", "velvet", "willow",
)


def generate_password(length: int = 32) -> str:
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def generate_passphrase(words: int = 8) -> str:
    return "-".join(secrets.choice(PASSPHRASE_WORDS) for _ in range(words))


def generate_ed25519_keypair(comment: str | None = None) -> dict[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")
    if comment:
        public_bytes = f"{public_bytes} {comment}"
    return {
        "private_key": private_bytes,
        "public_key": public_bytes,
        "fingerprint": fingerprint(public_bytes),
    }


def load_ed25519_keypair(private_key_path: Path, public_key_path: Path | None = None) -> dict[str, str]:
    private_bytes = private_key_path.read_bytes()
    private_key = serialization.load_ssh_private_key(private_bytes, password=None)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")

    if public_key_path and public_key_path.exists():
        public_text = public_key_path.read_text(encoding="utf-8").strip()
        if public_text:
            public_bytes = public_text

    return {
        "private_key": private_bytes.decode("utf-8"),
        "public_key": public_bytes,
        "fingerprint": fingerprint(public_bytes),
    }


def fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "SHA256:" + base64.b64encode(digest).decode("utf-8").rstrip("=")


def generate_value(generator: str, params: dict[str, Any] | None = None) -> Any:
    params = params or {}
    if generator == "password":
        return generate_password(length=int(params.get("length", 32)))
    if generator == "passphrase":
        return generate_passphrase(words=int(params.get("words", 8)))
    if generator == "ed25519_keypair":
        return generate_ed25519_keypair(comment=params.get("comment"))
    raise ValueError(f"Unsupported generator: {generator}")
