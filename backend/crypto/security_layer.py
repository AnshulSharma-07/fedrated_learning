from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _master_aes_key() -> bytes:
    secret = os.getenv(
        "FL_IDS_PAYLOAD_MASTER_KEY",
        "fl-ids-local-dev-aes-master-key-change-prod",
    )
    return hashlib.sha256(secret.encode("utf-8")).digest()


def canonicalize_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


@dataclass
class KeyPairInfo:
    key_id: str
    fingerprint: str
    public_key_pem: str
    private_key_path: Optional[str]


def generate_ed25519_keypair(
    client_id: str,
    key_dir: Optional[Path] = None,
    persist_private: bool = True,
) -> Tuple[KeyPairInfo, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    fingerprint = sha256_hex(pub_pem)[:32]
    key_id = f"ed25519-{fingerprint[:12]}"
    priv_path: Optional[str] = None

    if persist_private:
        target_dir = key_dir or Path(os.getenv("FL_IDS_KEY_DIR", ".local_keys"))
        target_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(target_dir, 0o700)
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in client_id)
        file_path = target_dir / f"{safe_name}.key.pem"
        file_path.write_bytes(priv_pem)
        os.chmod(file_path, 0o600)
        priv_path = str(file_path)

    return (
        KeyPairInfo(
            key_id=key_id,
            fingerprint=fingerprint,
            public_key_pem=pub_pem,
            private_key_path=priv_path,
        ),
        private_key,
    )


class ReplayGuard:
    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def is_replayed(self, client_id: str, nonce: str) -> bool:
        return f"{client_id}:{nonce}" in self._seen

    def mark_seen(self, client_id: str, nonce: str) -> None:
        self._seen.add(f"{client_id}:{nonce}")


def build_signed_encrypted_envelope(
    client_id: str,
    round_number: int,
    model_version: str,
    sample_count: int,
    payload: Dict[str, Any],
    private_key: Ed25519PrivateKey,
    aes_key: Optional[bytes] = None,
    forced_nonce: Optional[str] = None,
) -> Dict[str, Any]:
    canonical_payload = canonicalize_json(payload)
    payload_sha256 = sha256_hex(canonical_payload)
    nonce = forced_nonce or secrets.token_hex(12)
    timestamp = datetime.now(timezone.utc).isoformat()

    key = aes_key or _master_aes_key()
    iv = secrets.token_bytes(12)
    aad = canonicalize_json(
        {
            "client_id": client_id,
            "model_version": model_version,
            "nonce": nonce,
            "round": round_number,
        }
    ).encode("utf-8")

    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, canonical_payload.encode("utf-8"), aad)
    ciphertext = ct_and_tag[:-16]
    auth_tag = ct_and_tag[-16:]

    metadata_to_sign = canonicalize_json(
        {
            "client_id": client_id,
            "model_version": model_version,
            "nonce": nonce,
            "payload_sha256": payload_sha256,
            "round": round_number,
            "sample_count": sample_count,
            "timestamp": timestamp,
        }
    ).encode("utf-8")
    signature = private_key.sign(metadata_to_sign)

    return {
        "client_id": client_id,
        "round": round_number,
        "model_version": model_version,
        "sample_count": sample_count,
        "nonce": nonce,
        "timestamp": timestamp,
        "payload_sha256": payload_sha256,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "auth_tag_b64": base64.b64encode(auth_tag).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def verify_and_decrypt_envelope(
    envelope: Dict[str, Any],
    public_key_pem: Optional[str],
    client_active: bool,
    key_revoked: bool,
    replay_guard: ReplayGuard,
    aes_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    if not client_active or key_revoked or not public_key_pem:
        return {
            "ok": False,
            "code": "UNAUTHORIZED_CLIENT",
            "reason": "Client is inactive, unregistered, or has a revoked key",
        }

    client_id = str(envelope["client_id"])
    nonce = str(envelope["nonce"])
    if replay_guard.is_replayed(client_id, nonce):
        return {
            "ok": False,
            "code": "REPLAY_DETECTED",
            "reason": f"Duplicate nonce {nonce} rejected for {client_id}",
        }

    pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(pub_key, Ed25519PublicKey):
        return {"ok": False, "code": "SIGNATURE_INVALID", "reason": "Expected Ed25519 public key"}

    metadata_to_verify = canonicalize_json(
        {
            "client_id": client_id,
            "model_version": envelope["model_version"],
            "nonce": nonce,
            "payload_sha256": envelope["payload_sha256"],
            "round": envelope["round"],
            "sample_count": envelope["sample_count"],
            "timestamp": envelope["timestamp"],
        }
    ).encode("utf-8")

    try:
        pub_key.verify(base64.b64decode(envelope["signature_b64"]), metadata_to_verify)
    except InvalidSignature:
        return {"ok": False, "code": "SIGNATURE_INVALID", "reason": "Ed25519 signature verification failed"}

    key = aes_key or _master_aes_key()
    iv = base64.b64decode(envelope["iv_b64"])
    auth_tag = base64.b64decode(envelope["auth_tag_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    aad = canonicalize_json(
        {
            "client_id": client_id,
            "model_version": envelope["model_version"],
            "nonce": nonce,
            "round": envelope["round"],
        }
    ).encode("utf-8")

    try:
        plaintext = AESGCM(key).decrypt(iv, ciphertext + auth_tag, aad).decode("utf-8")
    except InvalidTag:
        return {
            "ok": False,
            "code": "DECRYPTION_FAILED",
            "reason": "AES-256-GCM authentication tag verification failed",
        }

    computed_hash = sha256_hex(plaintext)
    if computed_hash != envelope["payload_sha256"]:
        return {
            "ok": False,
            "code": "INTEGRITY_MISMATCH",
            "reason": "SHA-256 canonical payload digest mismatch",
        }

    replay_guard.mark_seen(client_id, nonce)
    return {"ok": True, "payload": json.loads(plaintext)}
