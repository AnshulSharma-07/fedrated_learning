from __future__ import annotations

import secrets
import numpy as np
import pandas as pd
import torch

from backend.auth.security import create_access_token, hash_password, verify_password
from backend.crypto.security_layer import (
    ReplayGuard,
    build_signed_encrypted_envelope,
    generate_ed25519_keypair,
    verify_and_decrypt_envelope,
)
from backend.datasets.pipeline import clean_intrusion_dataframe, partition_non_iid_dirichlet, prepare_stratified_splits
from backend.federated.server import validate_parameter_tensors
from backend.ml.models import IDSNet, train_classical_baselines, train_pytorch_mlp


def _synthetic_df(n: int = 240) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    rows = []
    for i in range(n):
        is_attack = i % 3 == 0
        rows.append(
            {
                "Flow Duration": float(rng.normal(18000 if is_attack else 240000, 3000)),
                "Total Fwd Packets": float(rng.integers(25, 80) if is_attack else rng.integers(3, 12)),
                "Total Backward Packets": float(rng.integers(0, 3) if is_attack else rng.integers(3, 12)),
                "Fwd Packet Length Mean": float(rng.normal(48 if is_attack else 180, 10)),
                "Bwd Packet Length Mean": float(rng.normal(15 if is_attack else 390, 20)),
                "Flow Bytes/s": float(rng.normal(150000 if is_attack else 18000, 4000)),
                "Flow Packets/s": float(rng.normal(3200 if is_attack else 60, 150)),
                "SYN Flag Count": 5 if is_attack else 1,
                "ACK Flag Count": 1 if is_attack else 7,
                "RST Flag Count": 2 if is_attack else 0,
                "PSH Flag Count": 0 if is_attack else 2,
                "Flow IAT Mean": float(rng.normal(300 if is_attack else 14000, 100)),
                "Init_Win_bytes_forward": 512 if is_attack else 29200,
                "Subflow Fwd Bytes": float(rng.normal(2400 if is_attack else 1400, 200)),
                "Label": "DoS Hulk" if is_attack else "Benign",
            }
        )
    return pd.DataFrame(rows)


def test_dataset_cleaning_and_non_iid_partition():
    df = _synthetic_df(180)
    df.loc[0, "Flow Bytes/s"] = np.inf
    df["Source IP"] = "10.0.0.1"
    cleaned, report = clean_intrusion_dataframe(df)
    assert report["dropped_infinite"] == 1
    assert "Source IP" in report["removed_leakage_columns"]
    assert "Source IP" not in cleaned.columns

    prep = prepare_stratified_splits(cleaned, mode="binary")
    parts = partition_non_iid_dirichlet(prep.X_train, prep.y_train, num_clients=3)
    assert len(parts) == 3
    assert sum(len(p[0]) for p in parts) == len(prep.X_train)


def test_ml_baselines_and_pytorch_mlp():
    cleaned, _ = clean_intrusion_dataframe(_synthetic_df(240))
    prep = prepare_stratified_splits(cleaned, mode="binary")
    res = train_classical_baselines(prep.X_train, prep.y_train, prep.X_test, prep.y_test, prep.classes)
    assert res["random_forest"]["metrics"]["accuracy"] > 0.90

    net = IDSNet(input_dim=14, num_classes=2)
    loss = train_pytorch_mlp(net, prep.X_train, prep.y_train, epochs=8)
    assert loss >= 0.0


def test_crypto_envelope_security_rejections():
    info, priv = generate_ed25519_keypair("pytest-client", persist_private=False)
    guard = ReplayGuard()
    env = build_signed_encrypted_envelope(
        client_id="pytest-client",
        round_number=1,
        model_version="v1.0.0",
        sample_count=50,
        payload={"tensors": [[[1.0, 2.0]]]},
        private_key=priv,
    )
    ok = verify_and_decrypt_envelope(env, info.public_key_pem, True, False, guard)
    assert ok["ok"] is True

    # Replay rejection
    replay = verify_and_decrypt_envelope(env, info.public_key_pem, True, False, guard)
    assert replay["code"] == "REPLAY_DETECTED"

    # Tampered tag rejection
    env2 = build_signed_encrypted_envelope(
        client_id="pytest-client",
        round_number=1,
        model_version="v1.0.0",
        sample_count=50,
        payload={"tensors": [[[1.0, 2.0]]]},
        private_key=priv,
        forced_nonce=secrets.token_hex(12),
    )
    env2["auth_tag_b64"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    bad_tag = verify_and_decrypt_envelope(env2, info.public_key_pem, True, False, ReplayGuard())
    assert bad_tag["code"] == "DECRYPTION_FAILED"

    # Invalid NaN tensor rejection
    ok_tensor, _ = validate_parameter_tensors([np.array([np.nan], dtype=np.float32)], [(1,)])
    assert ok_tensor is False


def test_auth_password_and_jwt():
    pw_hash = hash_password("SecurePass2026!")
    assert verify_password("SecurePass2026!", pw_hash) is True
    assert verify_password("WrongPass", pw_hash) is False
    token = create_access_token("u1", "admin@fl-ids.local", "admin")
    assert isinstance(token, str) and len(token) > 20
