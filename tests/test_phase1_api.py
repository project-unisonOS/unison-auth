from __future__ import annotations

from dataclasses import replace
import base64

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import auth_service
from identity_store import IdentityStore


def _client(tmp_path, monkeypatch):
    store = IdentityStore(str(tmp_path / "identity.db"))
    monkeypatch.setattr(auth_service, "IDENTITY_STORE", store)
    monkeypatch.setattr(
        auth_service,
        "SETTINGS",
        replace(
            auth_service.SETTINGS,
            bootstrap_token="bootstrap-secret",
            identity_database_path=str(tmp_path / "identity.db"),
        ),
    )
    monkeypatch.setattr(auth_service, "is_rate_limited", lambda _ip: False)
    monkeypatch.setattr(auth_service, "is_token_blacklisted", lambda _jti: False)
    monkeypatch.setattr(auth_service, "blacklist_token", lambda _jti, _exp: None)
    return TestClient(auth_service.app), store


def _bootstrap(client):
    return client.post(
        "/bootstrap/admin",
        headers={"X-Unison-Bootstrap-Token": "bootstrap-secret"},
        json={
            "username": "alice-login",
            "display_name": "Alice Example",
            "household_name": "Example household",
            "password": "Correct-Horse-7!",
            "confirmed": True,
        },
    )


def _login(client):
    issued = client.post(
        "/token",
        data={"username": "alice-login", "password": "Correct-Horse-7!", "grant_type": "password"},
    ).json()
    return issued, {"Authorization": f"Bearer {issued['access_token']}"}


def test_first_person_token_contains_server_bound_authority(tmp_path, monkeypatch):
    client, store = _client(tmp_path, monkeypatch)
    created = _bootstrap(client)
    assert created.status_code == 201
    identity = created.json()
    assert identity["username"] != identity["person_id"]

    token_response = client.post(
        "/token",
        data={"username": "alice-login", "password": "Correct-Horse-7!", "grant_type": "password"},
    )
    assert token_response.status_code == 200
    claims = auth_service.decode_token(token_response.json()["access_token"])
    persisted = store.identity_for_login("alice-login")
    assert claims["principal_id"] == persisted["principal_id"]
    assert claims["person_id"] == persisted["person_id"]
    assert claims["assistant_instance_id"] == persisted["assistant_instance_id"]
    assert claims["data_namespace"] == persisted["data_namespace"]
    assert claims["login_handle"] == "alice-login"


def test_duplicate_first_person_and_unconfirmed_enrollment_are_denied(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    unconfirmed = client.post(
        "/bootstrap/admin",
        headers={"X-Unison-Bootstrap-Token": "bootstrap-secret"},
        json={
            "username": "alice-login",
            "display_name": "Alice",
            "household_name": "Home",
            "password": "Correct-Horse-7!",
            "confirmed": False,
        },
    )
    assert unconfirmed.status_code == 409
    assert _bootstrap(client).status_code == 201
    assert _bootstrap(client).status_code == 409


def test_workload_token_requires_allowed_audience(tmp_path, monkeypatch):
    client, store = _client(tmp_path, monkeypatch)
    secret = "workload-secret-that-is-long-enough"
    store.register_workload(
        client_id="context-reader",
        secret_hash=auth_service.get_password_hash(secret),
        audiences=["context"],
        scopes=["profile:read"],
    )
    missing = client.post(
        "/token",
        data={"username": "context-reader", "password": secret, "grant_type": "client_credentials"},
    )
    assert missing.status_code == 400
    confused = client.post(
        "/token",
        data={"username": "context-reader", "password": secret, "grant_type": "client_credentials", "audience": "storage"},
    )
    assert confused.status_code == 403
    allowed = client.post(
        "/token",
        data={"username": "context-reader", "password": secret, "grant_type": "client_credentials", "audience": "context"},
    )
    claims = auth_service.decode_token(allowed.json()["access_token"])
    assert claims["principal_kind"] == "workload"
    assert claims["aud"] == ["context"]


def test_revoked_session_cannot_refresh_or_verify(tmp_path, monkeypatch):
    client, store = _client(tmp_path, monkeypatch)
    assert _bootstrap(client).status_code == 201
    issued = client.post(
        "/token",
        data={"username": "alice-login", "password": "Correct-Horse-7!", "grant_type": "password"},
    ).json()
    claims = auth_service.decode_token(issued["access_token"])
    store.revoke_session(claims["session_id"], "test")
    assert client.post("/refresh", params={"refresh_token": issued["refresh_token"]}).status_code == 401
    assert client.post("/verify", json={"token": issued["access_token"]}).status_code == 401


def test_passkey_registration_and_authentication_bind_high_assurance_session(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    assert _bootstrap(client).status_code == 201
    _, headers = _login(client)
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    options = client.post("/passkeys/register/options", headers=headers).json()
    proof = private_key.sign(f"unison-passkey-register:{options['challenge']}".encode("utf-8"))
    complete = client.post(
        "/passkeys/register/complete",
        headers=headers,
        json={
            **options,
            "credential_id": "credential-alice",
            "public_key_pem": public_pem,
            "proof_signature_b64": base64.b64encode(proof).decode("ascii"),
            "transports": ["internal"],
        },
    )
    assert complete.status_code == 201

    auth_options = client.post("/passkeys/authenticate/options", json={"username": "alice-login"}).json()
    signature = private_key.sign(
        f"unison-passkey-authenticate:{auth_options['challenge']}:1".encode("utf-8")
    )
    authenticated = client.post(
        "/passkeys/authenticate/complete",
        json={
            **auth_options,
            "credential_id": "credential-alice",
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "sign_count": 1,
        },
    )
    assert authenticated.status_code == 200
    claims = auth_service.decode_token(authenticated.json()["access_token"])
    assert claims["auth_method"] == "passkey"
    assert claims["assurance"] == "high"


def test_workload_delegation_preserves_person_and_restricts_scope(tmp_path, monkeypatch):
    client, store = _client(tmp_path, monkeypatch)
    assert _bootstrap(client).status_code == 201
    issued, headers = _login(client)
    store.register_workload(
        client_id="profile-worker",
        secret_hash=auth_service.get_password_hash("unused-but-long-enough-secret"),
        audiences=["context"],
        scopes=["profile:read"],
    )
    denied = client.post(
        "/delegations/workload-token",
        headers=headers,
        json={"client_id": "profile-worker", "audience": "storage", "scopes": ["profile:read"], "purpose": "read profile"},
    )
    assert denied.status_code == 403
    delegated = client.post(
        "/delegations/workload-token",
        headers=headers,
        json={"client_id": "profile-worker", "audience": "context", "scopes": ["profile:read"], "purpose": "read profile"},
    )
    assert delegated.status_code == 200
    parent = auth_service.decode_token(issued["access_token"])
    child = auth_service.decode_token(delegated.json()["access_token"])
    assert child["principal_kind"] == "workload"
    assert child["person_id"] == parent["person_id"]
    assert child["session_id"] == parent["session_id"]
    assert child["aud"] == ["context"]
