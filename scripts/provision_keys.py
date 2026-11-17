"""Provision local Ed25519 key pairs for Flower clients outside version control."""
from __future__ import annotations

from pathlib import Path
from backend.crypto.security_layer import generate_ed25519_keypair

DEFAULT_CLIENTS = [
    "client-hospital",
    "client-fintech",
    "client-campus",
    "client-cloud",
    "client-telecom",
]

if __name__ == "__main__":
    key_dir = Path(".local_keys")
    key_dir.mkdir(exist_ok=True)
    for cid in DEFAULT_CLIENTS:
        info, _ = generate_ed25519_keypair(cid, key_dir=key_dir, persist_private=True)
        (key_dir / f"{cid}.pub.pem").write_text(info.public_key_pem, encoding="utf-8")
        print(f"{cid}: key_id={info.key_id}, fingerprint={info.fingerprint}")
