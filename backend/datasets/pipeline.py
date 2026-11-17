from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

CORE_FEATURES: List[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "iat_mean",
    "init_win_bytes_fwd",
    "subflow_fwd_bytes",
]

LEAKAGE_COLUMNS = {
    "flow id",
    "flow_id",
    "source ip",
    "src ip",
    "source_ip",
    "destination ip",
    "dst ip",
    "destination_ip",
    "timestamp",
    "source port",
    "src port",
    "src_port",
    "id",
}

COLUMN_ALIASES: Dict[str, str] = {
    "flow duration": "flow_duration",
    "dur": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "tot fwd pkts": "total_fwd_packets",
    "spkts": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "tot bwd pkts": "total_bwd_packets",
    "dpkts": "total_bwd_packets",
    "fwd packet length mean": "fwd_packet_length_mean",
    "bwd packet length mean": "bwd_packet_length_mean",
    "flow bytes/s": "flow_bytes_per_sec",
    "flow packets/s": "flow_packets_per_sec",
    "syn flag count": "syn_flag_count",
    "ack flag count": "ack_flag_count",
    "rst flag count": "rst_flag_count",
    "psh flag count": "psh_flag_count",
    "flow iat mean": "iat_mean",
    "init_win_bytes_forward": "init_win_bytes_fwd",
    "subflow fwd bytes": "subflow_fwd_bytes",
    "sbytes": "subflow_fwd_bytes",
    "label": "label",
    "attack_cat": "label",
}


def normalize_attack_label(raw: str) -> str:
    s = str(raw).strip().lower()
    if s in ("benign", "normal", "0"):
        return "Benign"
    if any(k in s for k in ("dos", "ddos", "hulk", "goldeneye", "slowloris")):
        return "DoS/DDoS"
    if any(k in s for k in ("port", "scan", "recon")):
        return "PortScan"
    if any(k in s for k in ("brute", "patator", "ssh", "ftp")):
        return "BruteForce"
    if any(k in s for k in ("bot", "backdoor", "c2")):
        return "Botnet"
    if any(k in s for k in ("web", "xss", "sql")):
        return "WebAttack"
    return "Botnet"


def clean_intrusion_dataframe(
    df: pd.DataFrame,
    column_mapping: Optional[Dict[str, str]] = None,
) -> Tuple[pd.DataFrame, Dict[str, object]]:
    raw_rows = len(df)
    renamed: Dict[str, str] = {}
    removed_leakage: List[str] = []

    for col in df.columns:
        norm = col.strip().lower()
        if column_mapping and col in column_mapping:
            renamed[col] = column_mapping[col]
        elif norm in LEAKAGE_COLUMNS:
            removed_leakage.append(col)
        elif norm in CORE_FEATURES:
            renamed[col] = norm
        elif norm in COLUMN_ALIASES:
            renamed[col] = COLUMN_ALIASES[norm]

    df_clean = df.drop(columns=removed_leakage, errors="ignore").rename(columns=renamed)
    for feat in CORE_FEATURES:
        if feat not in df_clean.columns:
            df_clean[feat] = 0.0
        df_clean[feat] = pd.to_numeric(df_clean[feat], errors="coerce")

    has_label = "label" in df_clean.columns
    cols_to_keep = CORE_FEATURES + (["label"] if has_label else [])
    df_clean = df_clean[cols_to_keep].copy()

    # Track infinite & missing values explicitly
    inf_mask = np.isinf(df_clean[CORE_FEATURES].to_numpy(dtype=float)).any(axis=1)
    dropped_infinite = int(inf_mask.sum())
    df_clean = df_clean.loc[~inf_mask].copy()

    before_na = len(df_clean)
    df_clean = df_clean.dropna().copy()
    dropped_missing = before_na - len(df_clean)

    before_dup = len(df_clean)
    df_clean = df_clean.drop_duplicates().copy()
    dropped_duplicates = before_dup - len(df_clean)

    if has_label:
        df_clean["label"] = df_clean["label"].map(normalize_attack_label)

    report = {
        "raw_rows": raw_rows,
        "clean_rows": len(df_clean),
        "dropped_missing": dropped_missing,
        "dropped_infinite": dropped_infinite,
        "dropped_duplicates": dropped_duplicates,
        "removed_leakage_columns": removed_leakage,
    }
    return df_clean.reset_index(drop=True), report


@dataclass
class PreparedDataset:
    X_train: np.ndarray
    y_train: np.ndarray
    X_val: np.ndarray
    y_val: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    classes: List[str]
    scaler: StandardScaler


def prepare_stratified_splits(
    df: pd.DataFrame,
    mode: str = "multiclass",
    seed: int = 42,
) -> PreparedDataset:
    labels_str = (
        df["label"].map(lambda x: "Benign" if x == "Benign" else "Malicious")
        if mode == "binary"
        else df["label"]
    )
    classes = sorted(labels_str.unique().tolist())
    cls_to_idx = {c: i for i, c in enumerate(classes)}
    y = labels_str.map(cls_to_idx).to_numpy(dtype=np.int64)
    X = df[CORE_FEATURES].to_numpy(dtype=np.float32)

    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=seed
    )
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(
        X_temp_raw, y_temp, test_size=0.50, stratify=y_temp, random_state=seed
    )

    # Fit StandardScaler strictly on training data to prevent preprocessing leakage
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    return PreparedDataset(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        X_test=X_test,
        y_test=y_test,
        classes=classes,
        scaler=scaler,
    )


def partition_non_iid_dirichlet(
    X_train: np.ndarray,
    y_train: np.ndarray,
    num_clients: int = 5,
    alpha: float = 0.65,
    seed: int = 42,
) -> List[Tuple[np.ndarray, np.ndarray]]:
    rng = np.random.default_rng(seed)
    client_indices: List[List[int]] = [[] for _ in range(num_clients)]
    classes = np.unique(y_train)

    for c in classes:
        idx = np.where(y_train == c)[0]
        rng.shuffle(idx)
        proportions = rng.dirichlet(np.repeat(alpha, num_clients))
        splits = (np.cumsum(proportions) * len(idx)).astype(int)[:-1]
        for k, shard in enumerate(np.split(idx, splits)):
            client_indices[k].extend(shard.tolist())

    partitions: List[Tuple[np.ndarray, np.ndarray]] = []
    for idxs in client_indices:
        arr = np.array(idxs, dtype=int)
        rng.shuffle(arr)
        partitions.append((X_train[arr], y_train[arr]))
    return partitions
