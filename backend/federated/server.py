from __future__ import annotations

import argparse
import json
from typing import Dict, List, Optional, Tuple, Union

import flwr as fl
import numpy as np
from flwr.common import FitRes, Parameters, Scalar, ndarrays_to_parameters, parameters_to_ndarrays
from flwr.server.client_proxy import ClientProxy

from backend.crypto.security_layer import ReplayGuard, verify_and_decrypt_envelope


def validate_parameter_tensors(
    ndarrays: List[np.ndarray],
    expected_shapes: List[Tuple[int, ...]],
) -> Tuple[bool, Optional[str]]:
    if len(ndarrays) != len(expected_shapes):
        return False, f"Tensor count mismatch: expected {len(expected_shapes)}, got {len(ndarrays)}"
    total_norm_sq = 0.0
    for idx, (arr, shape) in enumerate(zip(ndarrays, expected_shapes)):
        if tuple(arr.shape) != shape:
            return False, f"Tensor {idx} shape mismatch: expected {shape}, got {arr.shape}"
        if not np.isfinite(arr).all():
            return False, f"Non-finite values (NaN/Inf) detected in tensor {idx}"
        total_norm_sq += float(np.sum(arr.astype(np.float64) ** 2))
    if np.sqrt(total_norm_sq) > 5000.0:
        return False, "Parameter L2 norm exceeds safe bound"
    return True, None


class SecureFedAvg(fl.server.strategy.FedAvg):
    """Flower FedAvg strategy enforcing Ed25519 signature, AES-256-GCM decryption, SHA-256 integrity, and tensor validation."""

    def __init__(
        self,
        public_keys_by_client: Dict[str, str],
        expected_shapes: List[Tuple[int, ...]],
        model_version: str = "v1.0.0",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.public_keys_by_client = public_keys_by_client
        self.expected_shapes = expected_shapes
        self.model_version = model_version
        self.replay_guard = ReplayGuard()

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        valid_results: List[Tuple[ClientProxy, FitRes]] = []
        rejected_count = 0

        for client_proxy, fit_res in results:
            metrics = fit_res.metrics or {}
            envelope_raw = metrics.get("envelope_json")
            client_id = str(metrics.get("client_id", client_proxy.cid))
            if not isinstance(envelope_raw, str):
                rejected_count += 1
                continue

            envelope = json.loads(envelope_raw)
            pub_pem = self.public_keys_by_client.get(client_id)
            crypto_res = verify_and_decrypt_envelope(
                envelope=envelope,
                public_key_pem=pub_pem,
                client_active=pub_pem is not None,
                key_revoked=False,
                replay_guard=self.replay_guard,
            )
            if not crypto_res.get("ok"):
                rejected_count += 1
                continue

            ndarrays = [np.array(w, dtype=np.float32) for w in crypto_res["payload"]["tensors"]]
            ok_tensor, _ = validate_parameter_tensors(ndarrays, self.expected_shapes)
            if not ok_tensor:
                rejected_count += 1
                continue

            verified_fit_res = FitRes(
                status=fit_res.status,
                parameters=ndarrays_to_parameters(ndarrays),
                num_examples=fit_res.num_examples,
                metrics={k: v for k, v in metrics.items() if k != "envelope_json"},
            )
            valid_results.append((client_proxy, verified_fit_res))

        if not valid_results:
            return None, {"accepted": 0, "rejected": rejected_count}

        aggregated, agg_metrics = super().aggregate_fit(server_round, valid_results, failures)
        agg_metrics["accepted"] = len(valid_results)
        agg_metrics["rejected"] = rejected_count
        return aggregated, agg_metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start Flower SecureFedAvg Server")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--min-clients", type=int, default=3)
    parser.add_argument("--address", type=str, default="0.0.0.0:8080")
    args = parser.parse_args()

    from pathlib import Path
    from backend.ml.models import IDSNet

    init_net = IDSNet(input_dim=14, num_classes=6)
    shapes = [tuple(p.detach().cpu().numpy().shape) for p in init_net.parameters()]
    key_dir = Path(".local_keys")
    pub_keys: Dict[str, str] = {}
    if key_dir.exists():
        for pub_file in key_dir.glob("*.pub.pem"):
            pub_keys[pub_file.stem.replace(".pub", "")] = pub_file.read_text(encoding="utf-8")

    strategy = SecureFedAvg(
        public_keys_by_client=pub_keys,
        expected_shapes=shapes,
        min_fit_clients=args.min_clients,
        min_available_clients=args.min_clients,
    )
    fl.server.start_server(
        server_address=args.address,
        config=fl.server.ServerConfig(num_rounds=args.rounds),
        strategy=strategy,
    )
