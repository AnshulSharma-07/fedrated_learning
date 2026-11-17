from __future__ import annotations

from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.utils.data import DataLoader, TensorDataset


class IDSNet(nn.Module):
    """PyTorch Multi-Layer Perceptron used for centralized and federated IDS."""

    def __init__(self, input_dim: int = 14, num_classes: int = 6) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def train_pytorch_mlp(
    model: IDSNet,
    X_train: np.ndarray,
    y_train: np.ndarray,
    epochs: int = 5,
    lr: float = 0.01,
    batch_size: int = 32,
    dp_clip_norm: Optional[float] = None,
    dp_noise_multiplier: Optional[float] = None,
) -> float:
    device = torch.device("cpu")
    model.to(device)
    model.train()
    dataset = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.long),
    )
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)

    last_loss = 0.0
    for _ in range(epochs):
        total_loss = 0.0
        batches = 0
        for xb, yb in loader:
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            if dp_clip_norm and dp_clip_norm > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), dp_clip_norm)
                if dp_noise_multiplier and dp_noise_multiplier > 0:
                    for p in model.parameters():
                        if p.grad is not None:
                            noise = torch.normal(
                                mean=0.0,
                                std=dp_clip_norm * dp_noise_multiplier / max(1, len(xb)),
                                size=p.grad.shape,
                            )
                            p.grad.add_(noise)
            optimizer.step()
            total_loss += float(loss.item())
            batches += 1
        last_loss = total_loss / max(1, batches)
    return round(last_loss, 4)


def evaluate_probabilities(
    y_true: np.ndarray,
    probs: np.ndarray,
    classes: List[str],
) -> Dict[str, Any]:
    y_pred = np.argmax(probs, axis=1)
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(classes))))
    benign_idx = classes.index("Benign") if "Benign" in classes else 0
    tn = int(cm[benign_idx, benign_idx])
    fp = int(cm[benign_idx].sum() - tn)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    y_bin = (y_true != benign_idx).astype(int)
    attack_scores = 1.0 - probs[:, benign_idx]
    roc_auc = (
        float(round(roc_auc_score(y_bin, attack_scores), 4))
        if len(np.unique(y_bin)) == 2
        else None
    )

    return {
        "accuracy": float(round(accuracy_score(y_true, y_pred), 4)),
        "precision": float(round(precision_score(y_true, y_pred, average="weighted", zero_division=0), 4)),
        "recall": float(round(recall_score(y_true, y_pred, average="weighted", zero_division=0), 4)),
        "f1_score": float(round(f1_score(y_true, y_pred, average="weighted", zero_division=0), 4)),
        "false_positive_rate": float(round(fpr, 4)),
        "roc_auc": roc_auc,
        "confusion_matrix": {"labels": classes, "matrix": cm.tolist()},
    }


def train_classical_baselines(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    classes: List[str],
    seed: int = 42,
) -> Dict[str, Any]:
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=seed,
    )
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)
    rf_metrics = evaluate_probabilities(y_test, rf_probs, classes)

    lr = LogisticRegression(
        max_iter=500,
        class_weight="balanced",
        random_state=seed,
    )
    lr.fit(X_train, y_train)
    lr_probs = lr.predict_proba(X_test)
    lr_metrics = evaluate_probabilities(y_test, lr_probs, classes)

    return {
        "random_forest": {"model": rf, "metrics": rf_metrics},
        "logistic_regression": {"model": lr, "metrics": lr_metrics},
    }


def save_classical_artifact(obj: Any, path: str) -> None:
    joblib.dump(obj, path)
