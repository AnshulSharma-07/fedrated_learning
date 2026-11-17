from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import flwr as fl
import numpy as np
import pandas as pd
import torch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.crypto.security_layer import build_signed_encrypted_envelope, generate_ed25519_keypair
from backend.datasets.pipeline import clean_intrusion_dataframe, partition_non_iid_dirichlet, prepare_stratified_splits
from backend.ml.models import IDSNet, evaluate_probabilities, train_pytorch_mlp


class SecureIDSClient(fl.client.NumPyClient):
    def __init__(
        self,
        client_id: str,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        classes: List[str],
        private_key: Ed25519PrivateKey,
        local_epochs: int = 4,
    ) -> None:
        self.client_id = client_id
        self.X_train = X_train
        self.y_train = y_train
        self.X_val = X_val
        self.y_val = y_val
        self.classes = classes
        self.private_key = private_key
        self.local_epochs = local_epochs
        self.model = IDSNet(input_dim=X_train.shape[1], num_classes=len(classes))

    def get_parameters(self, config):
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters):
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        self.set_parameters(parameters)
        loss = train_pytorch_mlp(self.model, self.X_train, self.y_train, epochs=self.local_epochs, lr=0.01)
        updated_tensors = [p.tolist() for p in self.get_parameters(config)]
        envelope = build_signed_encrypted_envelope(
            client_id=self.client_id,
            round_number=int(config.get("server_round", 1)),
            model_version="v1.0.0",
            sample_count=len(self.X_train),
            payload={"tensors": updated_tensors, "local_loss": loss},
            private_key=self.private_key,
        )
        return self.get_parameters(config), len(self.X_train), {
            "client_id": self.client_id,
            "local_loss": loss,
            "envelope_json": json.dumps(envelope),
        }

    def evaluate(self, parameters, config):
        self.set_parameters(parameters)
        self.model.eval()
        with torch.no_grad():
            logits = self.model(torch.tensor(self.X_val, dtype=torch.float32))
            probs = torch.softmax(logits, dim=1).numpy()
        metrics = evaluate_probabilities(self.y_val, probs, self.classes)
        return float(1.0 - metrics["accuracy"]), len(self.X_val), {"accuracy": metrics["accuracy"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a Flower FL-IDS Client")
    parser.add_argument("--client-id", type=str, required=True)
    parser.add_argument("--partition", type=int, default=0)
    parser.add_argument("--num-clients", type=int, default=3)
    parser.add_argument("--server", type=str, default="127.0.0.1:8080")
    parser.add_argument("--dataset", type=str, default="data/sample/synthetic_cicids2017_sample.csv")
    args = parser.parse_args()

    key_file = Path(".local_keys") / f"{args.client_id}.key.pem"
    if key_file.exists():
        priv = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    else:
        info, priv = generate_ed25519_keypair(args.client_id, persist_private=True)
        Path(".local_keys").mkdir(exist_ok=True)
        (Path(".local_keys") / f"{args.client_id}.pub.pem").write_text(info.public_key_pem, encoding="utf-8")

    df_raw = pd.read_csv(args.dataset)
    df_clean, _ = clean_intrusion_dataframe(df_raw)
    prep = prepare_stratified_splits(df_clean, mode="multiclass")
    parts = partition_non_iid_dirichlet(prep.X_train, prep.y_train, num_clients=args.num_clients, alpha=0.65)
    X_local, y_local = parts[args.partition % len(parts)]

    client = SecureIDSClient(
        client_id=args.client_id,
        X_train=X_local,
        y_train=y_local,
        X_val=prep.X_val,
        y_val=prep.y_val,
        classes=prep.classes,
        private_key=priv,
    )
    fl.client.start_client(server_address=args.server, client=client.to_client())
