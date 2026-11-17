from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer()


def _jwt_secret() -> str:
    return os.getenv("FL_IDS_JWT_SECRET", "dev-change-this-jwt-secret-min-32-chars")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1)
    return f"scrypt:{salt}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    parts = stored_hash.split(":")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    _, salt, expected = parts
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1)
    return hmac.compare_digest(dk.hex(), expected)


def create_access_token(sub: str, email: str, role: str, ttl_hours: int = 24) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=ttl_hours),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Dict[str, Any]:
    try:
        return jwt.decode(credentials.credentials, _jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired JWT token",
        ) from exc


def require_roles(allowed: List[str]):
    def _dep(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if user.get("role") not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.get('role')}' is not authorized",
            )
        return user

    return _dep
