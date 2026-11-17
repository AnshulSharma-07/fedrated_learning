from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import torch
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from backend.auth.security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)
from backend.crypto.security_layer import generate_ed25519_keypair
from backend.database.models import (
    AlertRecord,
    AuditLogRecord,
    DatasetMetadata,
    FederatedClientRecord,
    FederatedRoundRecord,
    ModelRecord,
    PredictionRecord,
    PublicKeyRegistration,
    Role,
    SecurityEventRecord,
    User,
    init_engine_and_session,
)
from backend.datasets.pipeline import (
    CORE_FEATURES,
    clean_intrusion_dataframe,
    prepare_stratified_splits,
)
from backend.ml.models import IDSNet, evaluate_probabilities, save_classical_artifact, train_classical_baselines, train_pytorch_mlp
from backend.network_security.adapter import adapt_zeek_or_cicflow_record, classify_alert_severity

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="FL-IDS API", version="1.0.0")
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_, SessionLocal = init_engine_and_session()
FEDERATED_JOB_STATE: Dict[str, Any] = {"status": "idle", "current_round": 0, "total_rounds": 0}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class LoginRequest(BaseModel):
    email: str
    password: str


class TrainRequest(BaseModel):
    dataset_id: str
    architecture: str = "random_forest"
    mode: str = "multiclass"


class FederatedStartRequest(BaseModel):
    rounds: int = 5
    local_epochs: int = 4
    dp_enabled: bool = False


class ClientRegisterRequest(BaseModel):
    name: str
    organization: str


class InferenceRequest(BaseModel):
    record: Dict[str, Any]
    client_sensor: str = "Lab-Sensor-01"


@app.on_event("startup")
def seed_roles_and_users() -> None:
    with SessionLocal() as db:
        if db.query(Role).count() == 0:
            db.add_all(
                [
                    Role(id="role-admin", name="admin", permissions_json='["read","train","manage_keys","infer"]'),
                    Role(id="role-analyst", name="analyst", permissions_json='["read","infer"]'),
                ]
            )
            db.commit()
        if db.query(User).count() == 0:
            db.add_all(
                [
                    User(
                        id="user-admin",
                        email="admin@fl-ids.local",
                        name="Security Admin",
                        password_hash=hash_password("Admin@FLIDS2026!"),
                        role_id="role-admin",
                    ),
                    User(
                        id="user-analyst",
                        email="analyst@fl-ids.local",
                        name="SOC Analyst",
                        password_hash=hash_password("Analyst@FLIDS2026!"),
                        role_id="role-analyst",
                    ),
                ]
            )
            db.commit()


@app.post("/api/auth/login")
@limiter.limit("30/minute")
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user.id, user.email, user.role.name)
    return {"token": token, "user": {"id": user.id, "email": user.email, "name": user.name, "role": user.role.name}}


@app.post("/api/datasets/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    user: Dict[str, Any] = Depends(require_roles(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    df = pd.read_csv(file.file)
    df_clean, report = clean_intrusion_dataframe(df)
    if df_clean.empty:
        raise HTTPException(status_code=400, detail="No valid rows after cleaning")
    ds_id = f"ds-{uuid.uuid4().hex[:8]}"
    out_dir = Path("data/uploads")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{ds_id}.csv"
    df_clean.to_csv(csv_path, index=False)

    rec = DatasetMetadata(
        id=ds_id,
        name=file.filename or ds_id,
        source_type="uploaded_csv",
        is_synthetic=False,
        raw_rows=int(report["raw_rows"]),
        clean_rows=int(report["clean_rows"]),
        csv_path=str(csv_path),
    )
    db.add(rec)
    db.commit()
    return {"id": ds_id, "report": report}


@app.get("/api/datasets")
def list_datasets(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"datasets": db.query(DatasetMetadata).all()}


def _train_model_task(dataset_id: str, architecture: str, mode: str) -> None:
    with SessionLocal() as db:
        ds = db.query(DatasetMetadata).filter(DatasetMetadata.id == dataset_id).first()
        if not ds:
            return
        df = pd.read_csv(ds.csv_path)
        prepared = prepare_stratified_splits(df, mode=mode)
        Path("models").mkdir(exist_ok=True)

        if architecture in ("random_forest", "logistic_regression"):
            res = train_classical_baselines(
                prepared.X_train, prepared.y_train, prepared.X_test, prepared.y_test, prepared.classes
            )
            chosen = res[architecture]
            artifact_path = f"models/{architecture}_{uuid.uuid4().hex[:6]}.joblib"
            save_classical_artifact({"model": chosen["model"], "scaler": prepared.scaler, "classes": prepared.classes}, artifact_path)
            metrics = chosen["metrics"]
        else:
            net = IDSNet(input_dim=len(CORE_FEATURES), num_classes=len(prepared.classes))
            train_pytorch_mlp(net, prepared.X_train, prepared.y_train, epochs=15, lr=0.01)
            net.eval()
            with torch.no_grad():
                probs = torch.softmax(net(torch.tensor(prepared.X_test, dtype=torch.float32)), dim=1).numpy()
            metrics = evaluate_probabilities(prepared.y_test, probs, prepared.classes)
            artifact_path = f"models/centralized_mlp_{uuid.uuid4().hex[:6]}.pt"
            torch.save({"state_dict": net.state_dict(), "classes": prepared.classes}, artifact_path)
            joblib.dump(prepared.scaler, artifact_path + ".scaler.joblib")

        db.add(
            ModelRecord(
                id=f"model-{uuid.uuid4().hex[:8]}",
                name=architecture,
                architecture=architecture,
                training_paradigm="centralized",
                version="v1.0.0",
                accuracy=metrics["accuracy"],
                f1_score=metrics["f1_score"],
                false_positive_rate=metrics["false_positive_rate"],
                artifact_path=artifact_path,
            )
        )
        db.commit()


@app.post("/api/models/train", status_code=202)
def train_model(
    body: TrainRequest,
    background_tasks: BackgroundTasks,
    user: Dict[str, Any] = Depends(require_roles(["admin"])),
):
    background_tasks.add_task(_train_model_task, body.dataset_id, body.architecture, body.mode)
    return {"status": "queued", "architecture": body.architecture}


@app.post("/api/federated/start", status_code=202)
def start_federated(
    body: FederatedStartRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin"])),
):
    FEDERATED_JOB_STATE.update({"status": "queued", "total_rounds": body.rounds, "current_round": 0})
    return {"job": FEDERATED_JOB_STATE, "note": "Run Flower server + 3 clients via docker-compose or CLI."}


@app.get("/api/federated/status")
def federated_status(user: Dict[str, Any] = Depends(get_current_user)):
    return {"job": FEDERATED_JOB_STATE}


@app.get("/api/federated/rounds")
def federated_rounds(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"rounds": db.query(FederatedRoundRecord).order_by(FederatedRoundRecord.round_number.asc()).all()}


@app.get("/api/federated/clients")
def federated_clients(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"clients": db.query(FederatedClientRecord).all()}


@app.post("/api/federated/clients/register", status_code=201)
def register_client(
    body: ClientRegisterRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db),
):
    client_id = f"client-{uuid.uuid4().hex[:8]}"
    kp_info, _ = generate_ed25519_keypair(client_id, persist_private=True)
    db.add(FederatedClientRecord(id=client_id, name=body.name, organization=body.organization, active=True))
    db.add(
        PublicKeyRegistration(
            id=f"pk-{client_id}",
            client_id=client_id,
            key_id=kp_info.key_id,
            public_key_pem=kp_info.public_key_pem,
            fingerprint=kp_info.fingerprint,
            revoked=False,
        )
    )
    db.commit()
    return {"client_id": client_id, "key_id": kp_info.key_id, "fingerprint": kp_info.fingerprint}


@app.post("/api/inference/predict")
def predict_single(
    body: InferenceRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    adapted = adapt_zeek_or_cicflow_record(body.record)
    model_rec = db.query(ModelRecord).order_by(ModelRecord.created_at.desc()).first()
    if not model_rec:
        raise HTTPException(status_code=404, detail="No trained model registered")
    bundle = joblib.load(model_rec.artifact_path)
    x = np.array([[adapted[f] for f in CORE_FEATURES]], dtype=np.float32)
    x_scaled = bundle["scaler"].transform(x)
    probs = bundle["model"].predict_proba(x_scaled)[0]
    best = int(np.argmax(probs))
    label = bundle["classes"][best]
    conf = float(round(probs[best], 4))
    severity = classify_alert_severity(label, conf)
    pred_id = f"pred-{uuid.uuid4().hex[:8]}"
    db.add(
        PredictionRecord(
            id=pred_id,
            model_id=model_rec.id,
            client_sensor=body.client_sensor,
            predicted_label=label,
            confidence=conf,
            is_malicious=(label != "Benign"),
        )
    )
    if label != "Benign":
        db.add(
            AlertRecord(
                id=f"alert-{pred_id}",
                client_sensor=body.client_sensor,
                attack_category=label,
                severity=severity,
                confidence=conf,
                status="open",
            )
        )
    db.commit()
    return {"id": pred_id, "predicted_label": label, "confidence": conf, "severity": severity}


@app.post("/api/inference/batch")
async def predict_batch(
    file: UploadFile = File(...),
    user: Dict[str, Any] = Depends(require_roles(["admin", "analyst"])),
    db: Session = Depends(get_db),
):
    df = pd.read_csv(file.file)
    df_clean, _ = clean_intrusion_dataframe(df)
    model_rec = db.query(ModelRecord).order_by(ModelRecord.created_at.desc()).first()
    if not model_rec:
        raise HTTPException(status_code=404, detail="No trained model registered")
    bundle = joblib.load(model_rec.artifact_path)
    X_scaled = bundle["scaler"].transform(df_clean[CORE_FEATURES].to_numpy(dtype=np.float32))
    probs = bundle["model"].predict_proba(X_scaled)
    preds = [bundle["classes"][int(np.argmax(p))] for p in probs]
    return {"total": len(preds), "malicious": sum(1 for p in preds if p != "Benign"), "predictions": preds[:100]}


@app.get("/api/alerts")
def get_alerts(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"alerts": db.query(AlertRecord).order_by(AlertRecord.created_at.desc()).limit(100).all()}


@app.get("/api/metrics")
def get_metrics(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"models": db.query(ModelRecord).all()}


@app.get("/api/security/audit-logs")
def get_audit_logs(user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"logs": db.query(AuditLogRecord).order_by(AuditLogRecord.created_at.desc()).limit(100).all()}
