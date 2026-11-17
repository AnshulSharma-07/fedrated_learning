from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./data/fl_ids_py.db")


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    permissions_json = Column(Text, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role_id = Column(String, ForeignKey("roles.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    role = relationship("Role")


class DatasetMetadata(Base):
    __tablename__ = "datasets"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    source_type = Column(String, nullable=False)
    is_synthetic = Column(Boolean, default=False)
    raw_rows = Column(Integer, nullable=False)
    clean_rows = Column(Integer, nullable=False)
    csv_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ModelRecord(Base):
    __tablename__ = "models"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    architecture = Column(String, nullable=False)
    training_paradigm = Column(String, nullable=False)
    version = Column(String, nullable=False)
    accuracy = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    artifact_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FederatedClientRecord(Base):
    __tablename__ = "federated_clients"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    organization = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PublicKeyRegistration(Base):
    __tablename__ = "public_keys"
    id = Column(String, primary_key=True)
    client_id = Column(String, ForeignKey("federated_clients.id"), nullable=False)
    key_id = Column(String, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    fingerprint = Column(String, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FederatedRoundRecord(Base):
    __tablename__ = "federated_rounds"
    id = Column(String, primary_key=True)
    round_number = Column(Integer, nullable=False)
    model_version = Column(String, nullable=False)
    global_loss = Column(Float, nullable=False)
    global_accuracy = Column(Float, nullable=False)
    global_f1 = Column(Float, nullable=False)
    communication_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ClientMetricRecord(Base):
    __tablename__ = "client_metrics"
    id = Column(String, primary_key=True)
    round_id = Column(String, ForeignKey("federated_rounds.id"), nullable=False)
    client_id = Column(String, ForeignKey("federated_clients.id"), nullable=False)
    status = Column(String, nullable=False)
    sample_count = Column(Integer, nullable=False)
    local_loss = Column(Float, nullable=False)
    local_accuracy = Column(Float, nullable=False)


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    client_id = Column(String, nullable=True)
    description = Column(Text, nullable=False)
    blocked = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PredictionRecord(Base):
    __tablename__ = "predictions"
    id = Column(String, primary_key=True)
    model_id = Column(String, nullable=False)
    client_sensor = Column(String, nullable=False)
    predicted_label = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    is_malicious = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AlertRecord(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    client_sensor = Column(String, nullable=False)
    attack_category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    actor_email = Column(String, nullable=False)
    actor_role = Column(String, nullable=False)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    outcome = Column(String, nullable=False)
    details = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_engine_and_session():
    url = get_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal
