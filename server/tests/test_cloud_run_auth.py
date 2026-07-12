import asyncio
import json

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

import auth


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": []})


def test_parse_service_principals_normalizes_emails_and_permissions():
    principals = auth.parse_service_principals(
        json.dumps(
            {
                " Writer@Example.IAM.GServiceAccount.com ": [
                    auth.PERMISSION_MEMORY_ADD,
                    auth.PERMISSION_MEMORY_SEARCH,
                ]
            }
        )
    )

    assert principals == {
        "writer@example.iam.gserviceaccount.com": frozenset({auth.PERMISSION_MEMORY_ADD, auth.PERMISSION_MEMORY_SEARCH})
    }


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("not-json", "must be valid JSON"),
        ("[]", "must be a JSON object"),
        ('{"caller@example.com": []}', "non-empty JSON array"),
        ('{"caller@example.com": ["memory:unknown"]}', "Unknown permissions"),
    ],
)
def test_parse_service_principals_rejects_invalid_policy(raw, message):
    with pytest.raises(RuntimeError, match=message):
        auth.parse_service_principals(raw)


def test_validate_cloud_run_configuration_fails_closed(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)
    monkeypatch.setattr(auth, "AUTH_DISABLED", False)
    monkeypatch.setattr(auth, "CLOUD_RUN_EXPECTED_AUDIENCE", "")
    monkeypatch.setattr(
        auth,
        "SERVICE_PRINCIPALS",
        {"caller@example.com": frozenset({auth.PERMISSION_MEMORY_ADD})},
    )

    with pytest.raises(RuntimeError, match="CLOUD_RUN_EXPECTED_AUDIENCE"):
        auth.validate_auth_configuration()


def test_cloud_run_bearer_token_resolves_authorized_service_account(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)
    monkeypatch.setattr(
        auth,
        "SERVICE_PRINCIPALS",
        {"caller@example.com": frozenset({auth.PERMISSION_MEMORY_ADD})},
    )
    monkeypatch.setattr(
        auth,
        "_verify_google_identity_token",
        lambda token: {"sub": "service-account-id", "email": "Caller@Example.com", "email_verified": True},
    )
    request = _request()

    principal = asyncio.run(
        auth.verify_auth(
            request,
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token"),
            None,
            None,
        )
    )

    assert isinstance(principal, auth.ServicePrincipal)
    assert principal.email == "caller@example.com"
    assert principal.has_permission(auth.PERMISSION_MEMORY_ADD)
    assert not principal.has_permission(auth.PERMISSION_MEMORY_DELETE)
    assert request.state.auth_type == "cloud_run_oidc"
    assert request.state.auth_principal == "caller@example.com"


def test_cloud_run_bearer_token_rejects_unlisted_service_account(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)
    monkeypatch.setattr(auth, "SERVICE_PRINCIPALS", {})
    monkeypatch.setattr(
        auth,
        "_verify_google_identity_token",
        lambda token: {"sub": "service-account-id", "email": "unknown@example.com", "email_verified": True},
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth.verify_auth(
                _request(),
                HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token"),
                None,
                None,
            )
        )

    assert exc_info.value.status_code == 403


def test_cloud_run_mode_requires_bearer_token(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(auth.verify_auth(_request(), None, "legacy-api-key", None))

    assert exc_info.value.status_code == 401


def test_admin_permission_implies_all_service_permissions():
    principal = auth.ServicePrincipal(
        subject="service-account-id",
        email="admin@example.com",
        permissions=frozenset({auth.PERMISSION_ADMIN}),
    )

    assert all(principal.has_permission(permission) for permission in auth.KNOWN_SERVICE_PERMISSIONS)


def test_permission_dependency_enforces_service_scope():
    principal = auth.ServicePrincipal(
        subject="service-account-id",
        email="writer@example.com",
        permissions=frozenset({auth.PERMISSION_MEMORY_ADD}),
    )
    request = _request()

    allowed = asyncio.run(auth.require_permission(auth.PERMISSION_MEMORY_ADD)(request, principal))
    assert allowed is principal

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(auth.require_permission(auth.PERMISSION_MEMORY_SEARCH)(request, principal))

    assert exc_info.value.status_code == 403


def test_google_token_verification_uses_configured_audience(monkeypatch):
    captured = {}
    google_request = object()
    monkeypatch.setattr(auth, "CLOUD_RUN_EXPECTED_AUDIENCE", "https://mem0.example.run.app")
    monkeypatch.setattr(auth, "_get_google_auth_request", lambda: google_request)

    def verify(token, request, **kwargs):
        captured.update(token=token, request=request, **kwargs)
        return {"sub": "service-account-id", "email": "caller@example.com"}

    monkeypatch.setattr(auth.google_id_token, "verify_oauth2_token", verify)

    claims = auth._verify_google_identity_token("signed-token")

    assert claims["sub"] == "service-account-id"
    assert captured == {
        "token": "signed-token",
        "request": google_request,
        "audience": "https://mem0.example.run.app",
        "clock_skew_in_seconds": 30,
    }


def test_native_user_keeps_existing_memory_access():
    request = _request()
    request.state.auth_type = "bearer"
    user = auth.User(
        name="caller",
        email="caller@example.com",
        password_hash="unused",
        role="user",
    )

    assert auth.principal_has_permission(request, user, auth.PERMISSION_MEMORY_ADD)
    assert auth.principal_has_permission(request, user, auth.PERMISSION_MEMORY_SEARCH)
    assert not auth.principal_has_permission(request, user, auth.PERMISSION_ADMIN)


def test_token_with_unverified_email_is_rejected(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)
    monkeypatch.setattr(
        auth,
        "SERVICE_PRINCIPALS",
        {"caller@example.com": frozenset({auth.PERMISSION_MEMORY_ADD})},
    )
    monkeypatch.setattr(
        auth,
        "_verify_google_identity_token",
        lambda token: {"sub": "service-account-id", "email": "caller@example.com"},
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth.verify_auth(
                _request(),
                HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token"),
                None,
                None,
            )
        )

    assert exc_info.value.status_code == 401
    assert "verified" in exc_info.value.detail


def test_certificate_fetch_failure_returns_503(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)

    def raise_transport_error(token):
        raise auth.TransportError("certificate endpoint unreachable")

    monkeypatch.setattr(auth, "_verify_google_identity_token", raise_transport_error)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth.verify_auth(
                _request(),
                HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token"),
                None,
                None,
            )
        )

    assert exc_info.value.status_code == 503


def test_config_read_allows_any_native_principal():
    user = auth.User(
        name="caller",
        email="caller@example.com",
        password_hash="unused",
        role="user",
    )

    assert asyncio.run(auth.require_config_read(_request(), user)) is user
    # ADMIN_API_KEY and AUTH_DISABLED callers resolve to a None principal.
    assert asyncio.run(auth.require_config_read(_request(), None)) is None


def test_config_read_requires_admin_for_service_principals():
    reader = auth.ServicePrincipal(
        subject="service-account-id",
        email="reader@example.com",
        permissions=frozenset({auth.PERMISSION_MEMORY_READ}),
    )
    admin = auth.ServicePrincipal(
        subject="service-account-id",
        email="admin@example.com",
        permissions=frozenset({auth.PERMISSION_ADMIN}),
    )

    assert asyncio.run(auth.require_config_read(_request(), admin)) is admin

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(auth.require_config_read(_request(), reader))

    assert exc_info.value.status_code == 403


def test_native_only_routers_hidden_in_cloud_run_mode(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_CLOUD_RUN_OIDC)

    with pytest.raises(HTTPException) as exc_info:
        auth.require_native_auth_mode()

    assert exc_info.value.status_code == 404

    monkeypatch.setattr(auth, "AUTH_MODE", auth.AUTH_MODE_NATIVE)
    auth.require_native_auth_mode()
