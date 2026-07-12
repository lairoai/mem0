import asyncio
import json
import logging
import os
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TypeAlias

import cachecontrol
import requests as http_requests
from db import get_db
from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from google.auth.exceptions import GoogleAuthError, TransportError
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from models import APIKey, RefreshTokenJti, User
from passlib.context import CryptContext
from sqlalchemy import select, update
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

AUTH_MODE_NATIVE = "native"
AUTH_MODE_CLOUD_RUN_OIDC = "cloud_run_oidc"
SUPPORTED_AUTH_MODES = {AUTH_MODE_NATIVE, AUTH_MODE_CLOUD_RUN_OIDC}

PERMISSION_ADMIN = "admin"
PERMISSION_MEMORY_ADD = "memory:add"
PERMISSION_MEMORY_SEARCH = "memory:search"
PERMISSION_MEMORY_READ = "memory:read"
PERMISSION_MEMORY_UPDATE = "memory:update"
PERMISSION_MEMORY_DELETE = "memory:delete"
KNOWN_SERVICE_PERMISSIONS = frozenset(
    {
        PERMISSION_ADMIN,
        PERMISSION_MEMORY_ADD,
        PERMISSION_MEMORY_SEARCH,
        PERMISSION_MEMORY_READ,
        PERMISSION_MEMORY_UPDATE,
        PERMISSION_MEMORY_DELETE,
    }
)


@dataclass(frozen=True)
class ServicePrincipal:
    """A Google service account authenticated with a Cloud Run ID token."""

    subject: str
    email: str
    permissions: frozenset[str]

    def has_permission(self, permission: str) -> bool:
        return PERMISSION_ADMIN in self.permissions or permission in self.permissions


AuthPrincipal: TypeAlias = User | ServicePrincipal | None


def parse_service_principals(raw: str) -> dict[str, frozenset[str]]:
    """Parse and validate the service-account permission map."""
    if not raw.strip():
        return {}

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("MEM0_SERVICE_PRINCIPALS_JSON must be valid JSON.") from exc

    if not isinstance(value, dict):
        raise RuntimeError("MEM0_SERVICE_PRINCIPALS_JSON must be a JSON object.")

    principals: dict[str, frozenset[str]] = {}
    for email, permissions in value.items():
        if not isinstance(email, str) or not email.strip():
            raise RuntimeError("Every service principal must have a non-empty email address.")
        if not isinstance(permissions, list) or not permissions:
            raise RuntimeError(f"Permissions for {email!r} must be a non-empty JSON array.")
        if not all(isinstance(permission, str) for permission in permissions):
            raise RuntimeError(f"Permissions for {email!r} must all be strings.")

        permission_set = frozenset(permissions)
        unknown = permission_set - KNOWN_SERVICE_PERMISSIONS
        if unknown:
            raise RuntimeError(f"Unknown permissions for {email!r}: {', '.join(sorted(unknown))}.")

        normalized_email = email.strip().casefold()
        if normalized_email in principals:
            raise RuntimeError(f"Duplicate service principal after normalization: {email!r}.")
        principals[normalized_email] = permission_set

    return principals


JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in {"1", "true", "yes", "on"}
AUTH_MODE = os.environ.get("MEM0_AUTH_MODE", AUTH_MODE_NATIVE).strip().lower()
CLOUD_RUN_EXPECTED_AUDIENCE = os.environ.get("CLOUD_RUN_EXPECTED_AUDIENCE", "").strip()
SERVICE_PRINCIPALS = parse_service_principals(os.environ.get("MEM0_SERVICE_PRINCIPALS_JSON", ""))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def validate_auth_configuration() -> None:
    """Fail startup when authentication configuration is unsafe or incomplete."""
    if AUTH_MODE not in SUPPORTED_AUTH_MODES:
        raise RuntimeError(
            f"Unsupported MEM0_AUTH_MODE {AUTH_MODE!r}. Expected one of: {', '.join(sorted(SUPPORTED_AUTH_MODES))}."
        )
    if AUTH_DISABLED and AUTH_MODE != AUTH_MODE_NATIVE:
        raise RuntimeError("AUTH_DISABLED cannot be combined with MEM0_AUTH_MODE=cloud_run_oidc.")
    if AUTH_MODE == AUTH_MODE_NATIVE:
        if not AUTH_DISABLED and not JWT_SECRET:
            raise RuntimeError(
                "JWT_SECRET is required in native auth mode. Generate one with `openssl rand -base64 48`, "
                "or set AUTH_DISABLED=true for local development only."
            )
        return
    if not CLOUD_RUN_EXPECTED_AUDIENCE:
        raise RuntimeError("CLOUD_RUN_EXPECTED_AUDIENCE is required in cloud_run_oidc auth mode.")
    if not SERVICE_PRINCIPALS:
        raise RuntimeError("MEM0_SERVICE_PRINCIPALS_JSON must authorize at least one caller in cloud_run_oidc mode.")


_google_auth_thread_local = threading.local()


def _get_google_auth_request() -> GoogleAuthRequest:
    # google-auth otherwise downloads Google's signing certificates for every
    # verification. CacheControl honors the endpoint's cache headers and keeps
    # verification off the network while the keys remain fresh. One session per
    # thread because requests.Session is not thread-safe and verification runs
    # on asyncio.to_thread workers.
    request = getattr(_google_auth_thread_local, "request", None)
    if request is None:
        session = cachecontrol.CacheControl(http_requests.Session())
        request = GoogleAuthRequest(session=session)
        _google_auth_thread_local.request = request
    return request


def _verify_google_identity_token(token: str) -> dict:
    return google_id_token.verify_oauth2_token(
        token,
        _get_google_auth_request(),
        audience=CLOUD_RUN_EXPECTED_AUDIENCE,
        clock_skew_in_seconds=30,
    )


async def _resolve_service_principal(token: str) -> ServicePrincipal:
    try:
        claims = await asyncio.to_thread(_verify_google_identity_token, token)
    except TransportError as exc:
        logger.warning("Could not reach Google's certificate endpoint to verify identity token")
        raise HTTPException(status_code=503, detail="Identity token verification is temporarily unavailable.") from exc
    except (GoogleAuthError, ValueError) as exc:
        logger.info("Rejected Cloud Run identity token", extra={"reason": type(exc).__name__})
        raise HTTPException(status_code=401, detail="Invalid or expired Cloud Run identity token.") from exc

    subject = claims.get("sub")
    email = claims.get("email")
    if not isinstance(subject, str) or not subject or not isinstance(email, str) or not email:
        raise HTTPException(status_code=401, detail="Cloud Run identity token is missing subject or email claims.")
    if claims.get("email_verified") is not True:
        raise HTTPException(status_code=401, detail="Cloud Run identity token email is not verified by Google.")

    normalized_email = email.casefold()
    permissions = SERVICE_PRINCIPALS.get(normalized_email)
    if permissions is None:
        logger.warning("Rejected unauthorized service principal", extra={"service_account": normalized_email})
        raise HTTPException(status_code=403, detail="Service account is not authorized for this Mem0 server.")

    return ServicePrincipal(subject=subject, email=normalized_email, permissions=permissions)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def dummy_verify_password() -> None:
    """Burn the same bcrypt cycles as a real verify so login timing doesn't leak whether an email exists."""
    pwd_context.dummy_verify()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash)."""
    raw = secrets.token_urlsafe(32)
    full_key = f"m0sk_{raw}"
    prefix = full_key[:12]
    key_hash = pwd_context.hash(full_key)
    return full_key, prefix, key_hash


def verify_api_key_hash(plain_key: str, hashed: str) -> bool:
    return pwd_context.verify(plain_key, hashed)


def _get_secret() -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured.")
    return JWT_SECRET


def create_access_token(user_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user_id, "role": role, "exp": expire, "type": "access"}
    return jwt.encode(payload, _get_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str, db: Session) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = uuid.uuid4()
    db.add(RefreshTokenJti(jti=jti, user_id=uuid.UUID(user_id), expires_at=expire))
    db.commit()
    payload = {"sub": user_id, "exp": expire, "jti": str(jti), "type": "refresh"}
    return jwt.encode(payload, _get_secret(), algorithm=JWT_ALGORITHM)


def consume_refresh_jti(jti: str, db: Session) -> None:
    """Atomically mark a refresh token's jti as used. Raises 401 if missing, already used, or expired.

    The conditional UPDATE closes the read-check-write race: concurrent replays of the same
    token race on a single row, so at most one update affects a row and the rest see rowcount 0.
    """
    try:
        jti_uuid = uuid.UUID(jti)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    now = datetime.now(timezone.utc)
    result = db.execute(
        update(RefreshTokenJti)
        .where(
            RefreshTokenJti.jti == jti_uuid,
            RefreshTokenJti.used_at.is_(None),
            RefreshTokenJti.expires_at > now,
        )
        .values(used_at=now)
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    db.commit()


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _get_secret(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _mark_auth_type(request: Request, auth_type: str) -> None:
    request.state.auth_type = auth_type


def _get_default_user(db: Session) -> User | None:
    return db.scalar(select(User).order_by(User.created_at.asc()))


def _resolve_user_from_jwt(token: str, db: Session) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type.")
    user = db.get(User, payload.get("sub"))
    if user is None:
        raise HTTPException(status_code=401, detail="User not found.")
    return user


def _resolve_user_from_api_key(key: str, db: Session) -> User:
    prefix = key[:12] if len(key) >= 12 else key
    candidates = (
        db.execute(select(APIKey).where(APIKey.key_prefix == prefix, APIKey.revoked_at.is_(None))).scalars().all()
    )

    for candidate in candidates:
        if verify_api_key_hash(key, candidate.key_hash):
            candidate.last_used_at = datetime.now(timezone.utc)
            db.commit()
            user = db.get(User, candidate.created_by)
            if user is None:
                raise HTTPException(status_code=401, detail="API key owner not found.")
            return user

    raise HTTPException(status_code=401, detail="Invalid API key.")


async def verify_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    """Authenticate using the configured native or Cloud Run OIDC mode."""
    if AUTH_MODE == AUTH_MODE_CLOUD_RUN_OIDC:
        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="Cloud Run identity token required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        principal = await _resolve_service_principal(credentials.credentials)
        _mark_auth_type(request, "cloud_run_oidc")
        request.state.auth_principal = principal.email
        return principal

    if credentials is not None:
        _mark_auth_type(request, "bearer")
        return _resolve_user_from_jwt(credentials.credentials, db)

    if x_api_key is not None:
        if ADMIN_API_KEY and secrets.compare_digest(x_api_key, ADMIN_API_KEY):
            _mark_auth_type(request, "admin_api_key")
            return None
        _mark_auth_type(request, "api_key")
        return _resolve_user_from_api_key(x_api_key, db)

    if AUTH_DISABLED:
        _mark_auth_type(request, "disabled")
        return None

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def principal_has_permission(request: Request, principal: AuthPrincipal, permission: str) -> bool:
    """Check a route permission without changing native-mode behavior."""
    if permission not in KNOWN_SERVICE_PERMISSIONS:
        raise ValueError(f"Unknown Mem0 permission: {permission}")
    if isinstance(principal, ServicePrincipal):
        return principal.has_permission(permission)

    auth_type = getattr(request.state, "auth_type", "none")
    if permission == PERMISSION_ADMIN:
        if isinstance(principal, User):
            return principal.role == "admin"
        return auth_type in {"admin_api_key", "disabled"}

    # Native bearer/API-key users already had access to these endpoints.
    # Preserve that behavior while service principals use explicit scopes.
    return isinstance(principal, User) or auth_type in {"admin_api_key", "disabled"}


def require_permission(permission: str):
    """Build a FastAPI dependency that enforces a service-principal permission."""
    if permission not in KNOWN_SERVICE_PERMISSIONS:
        raise ValueError(f"Unknown Mem0 permission: {permission}")

    async def dependency(
        request: Request,
        principal: AuthPrincipal = Depends(verify_auth),
    ) -> AuthPrincipal:
        if not principal_has_permission(request, principal, permission):
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}.")
        return principal

    return dependency


async def require_config_read(
    request: Request,
    principal: AuthPrincipal = Depends(verify_auth),
) -> AuthPrincipal:
    """Config-read access: any authenticated native caller, admin for service principals.

    The dashboard configuration page and setup wizard load these endpoints for
    every logged-in user, so native mode must not require the admin role.
    """
    if isinstance(principal, ServicePrincipal) and not principal.has_permission(PERMISSION_ADMIN):
        raise HTTPException(status_code=403, detail=f"Permission required: {PERMISSION_ADMIN}.")
    return principal


async def require_auth(
    request: Request,
    user: AuthPrincipal = Depends(verify_auth),
    db: Session = Depends(get_db),
) -> User:
    """Like verify_auth but guarantees a non-None User. Use for endpoints that require auth."""
    if isinstance(user, ServicePrincipal):
        raise HTTPException(status_code=403, detail="A local user account is required for this endpoint.")
    if user is None:
        if getattr(request.state, "auth_type", "none") in {"admin_api_key", "disabled"}:
            default_user = _get_default_user(db)
            if default_user is not None:
                return default_user
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


_BOOTSTRAP_ADMIN = User(
    id=uuid.UUID(int=0),
    name="admin_api_key",
    email="",
    password_hash="",
    role="admin",
    created_at=datetime.min.replace(tzinfo=timezone.utc),
)


async def require_admin(
    request: Request,
    user: AuthPrincipal = Depends(verify_auth),
    db: Session = Depends(get_db),
) -> User | ServicePrincipal:
    """Like require_auth but also enforces admin role.

    ADMIN_API_KEY and AUTH_DISABLED callers are treated as admin even when
    the users table is empty (fresh-deploy bootstrap).
    """
    if isinstance(user, ServicePrincipal):
        if user.has_permission(PERMISSION_ADMIN):
            return user
        raise HTTPException(status_code=403, detail="Admin permission required.")

    auth_type = getattr(request.state, "auth_type", "none")
    if user is None:
        if auth_type in {"admin_api_key", "disabled"}:
            default_user = _get_default_user(db)
            if default_user is not None:
                if default_user.role != "admin":
                    raise HTTPException(status_code=403, detail="Admin role required.")
                return default_user
            return _BOOTSTRAP_ADMIN
        raise HTTPException(status_code=401, detail="Authentication required.")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required.")
    return user


def require_native_auth_mode() -> None:
    """Hide password/session endpoints when Cloud Run OIDC is authoritative."""
    if AUTH_MODE != AUTH_MODE_NATIVE:
        raise HTTPException(status_code=404, detail="Not found.")
