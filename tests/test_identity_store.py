from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from identity_store import (
    IdentityConflict,
    IdentityNotFound,
    IdentityRevoked,
    IdentityStore,
    MigrationError,
)


def make_store(tmp_path):
    return IdentityStore(str(tmp_path / "identity.db"))


def bootstrap(store):
    return store.bootstrap_first_person(
        confirmed=True,
        login_handle="alice-login",
        display_name="Alice Example",
        household_name="Example household",
        password_hash="hash-alice",
        email="alice@example.invalid",
    )


def test_bootstrap_creates_distinct_person_login_and_isolation_handles(tmp_path):
    store = make_store(tmp_path)
    identity = bootstrap(store)
    loaded = store.identity_for_login("alice-login")
    assert store.schema_version() == 3
    assert loaded["person_id"] == identity["person_id"]
    assert loaded["login_handle"] != loaded["person_id"]
    assert len({loaded["key_handle"], loaded["credential_namespace"], loaded["data_namespace"], loaded["cache_namespace"], loaded["index_namespace"]}) == 5


def test_bootstrap_requires_confirmation_and_is_single_use(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(IdentityConflict, match="confirmation"):
        store.bootstrap_first_person(
            confirmed=False,
            login_handle="alice-login",
            display_name="Alice",
            household_name="Home",
            password_hash="hash",
        )
    bootstrap(store)
    with pytest.raises(IdentityConflict, match="already complete"):
        bootstrap(store)


def test_invitation_pairs_independent_person_into_household(tmp_path):
    store = make_store(tmp_path)
    alice = bootstrap(store)
    token, invitation = store.create_invitation(
        invited_by_person_id=alice["person_id"],
        household_id=alice["household_id"],
    )
    bob = store.accept_invitation(
        invitation_token=token,
        login_handle="bob-login",
        display_name="Bob Example",
        password_hash="hash-bob",
    )
    assert bob["household_id"] == alice["household_id"]
    assert bob["person_id"] != alice["person_id"]
    assert bob["data_namespace"] != alice["data_namespace"]
    with pytest.raises(Exception):
        store.accept_invitation(
            invitation_token=token,
            login_handle="duplicate",
            display_name="Duplicate",
            password_hash="hash",
        )
    assert invitation["invitation_id"].startswith("inv_")


def test_household_admin_lists_minimized_members_and_removes_without_private_access(tmp_path):
    store = make_store(tmp_path)
    alice = bootstrap(store)
    token, _ = store.create_invitation(
        invited_by_person_id=alice["person_id"], household_id=alice["household_id"]
    )
    bob = store.accept_invitation(
        invitation_token=token,
        login_handle="bob-login",
        display_name="Bob Example",
        password_hash="hash-bob",
    )
    members = store.list_household_members(
        requesting_person_id=bob["person_id"], household_id=alice["household_id"]
    )
    assert {member["person_id"] for member in members} == {alice["person_id"], bob["person_id"]}
    assert all("key_handle" not in member and "data_namespace" not in member for member in members)

    result = store.remove_household_member(
        removed_by_person_id=alice["person_id"],
        household_id=alice["household_id"],
        person_id=bob["person_id"],
    )
    assert result["private_data_transferred"] is False
    assert result["private_keys_disclosed"] is False
    assert store.identity_for_person(bob["person_id"])["active"] is False
    with pytest.raises(IdentityConflict):
        store.remove_household_member(
            removed_by_person_id=alice["person_id"],
            household_id=alice["household_id"],
            person_id=alice["person_id"],
        )


def test_session_revocation_and_lock_are_fail_closed(tmp_path):
    store = make_store(tmp_path)
    identity = bootstrap(store)
    session = store.create_session(identity, auth_method="password", assurance="medium", lifetime_minutes=30)
    assert store.session_is_active(session, identity["person_id"])
    assert not store.session_is_active(session, "forged-person")
    assert store.revoke_session(session)
    assert not store.session_is_active(session, identity["person_id"])

    second = store.create_session(identity, auth_method="passkey", assurance="high", lifetime_minutes=30)
    store.lock_person(identity["person_id"])
    assert not store.session_is_active(second)
    assert store.identity_for_login("alice-login")["active"] is False


def test_device_and_channel_revocation_are_person_scoped(tmp_path):
    store = make_store(tmp_path)
    identity = bootstrap(store)
    device = store.register_device(person_id=identity["person_id"], display_name="Alice phone", assurance="high")
    session = store.create_session(
        identity,
        auth_method="passkey",
        assurance="high",
        lifetime_minutes=30,
        device_principal_id=device,
    )
    assert store.session_is_active(session)
    assert store.revoke_device(device)
    assert not store.session_is_active(session)

    channel = store.bind_channel_identity(
        person_id=identity["person_id"],
        provider="test-provider",
        external_subject="private-external-subject",
        assurance="medium",
    )
    assert not store.revoke_channel_identity(channel, "forged-person")
    assert store.revoke_channel_identity(channel, identity["person_id"])


def test_telegram_pairing_requires_step_up_and_is_one_use(tmp_path):
    store = IdentityStore(str(tmp_path / "identity.db"))
    alice = store.bootstrap_first_person(
        confirmed=True, login_handle="alice", display_name="Alice",
        household_name="Household", password_hash="hash",
    )
    with pytest.raises(IdentityConflict, match="stronger local authentication"):
        store.create_channel_pairing(
            person_id=alice["person_id"], provider="telegram",
            provider_account_id="bot-alice", local_assurance="low",
        )
    code, challenge = store.create_channel_pairing(
        person_id=alice["person_id"], provider="telegram",
        provider_account_id="bot-alice", local_assurance="passkey",
    )
    binding = store.complete_channel_pairing(
        challenge_id=challenge["challenge_id"], pairing_code=code,
        provider="telegram", provider_account_id="bot-alice", external_subject="1001",
    )
    assert binding["assurance"] == "low"
    assert store.resolve_channel_binding(
        provider="telegram", provider_account_id="bot-alice", external_subject="1001"
    )["person_id"] == alice["person_id"]
    with pytest.raises(IdentityNotFound, match="pairing is unavailable"):
        store.complete_channel_pairing(
            challenge_id=challenge["challenge_id"], pairing_code=code,
            provider="telegram", provider_account_id="bot-alice", external_subject="1001",
        )


def test_wrong_person_reassignment_and_revocation_fail_closed(tmp_path):
    store = IdentityStore(str(tmp_path / "identity.db"))
    alice = store.bootstrap_first_person(
        confirmed=True, login_handle="alice", display_name="Alice",
        household_name="Household", password_hash="hash",
    )
    invitation, _ = store.create_invitation(
        invited_by_person_id=alice["person_id"], household_id=alice["household_id"]
    )
    bob = store.accept_invitation(
        invitation_token=invitation, login_handle="bob", display_name="Bob", password_hash="hash"
    )
    code, challenge = store.create_channel_pairing(
        person_id=alice["person_id"], provider="telegram",
        provider_account_id="bot-shared", local_assurance="high",
    )
    binding = store.complete_channel_pairing(
        challenge_id=challenge["challenge_id"], pairing_code=code,
        provider="telegram", provider_account_id="bot-shared", external_subject="1001",
    )
    code2, challenge2 = store.create_channel_pairing(
        person_id=bob["person_id"], provider="telegram",
        provider_account_id="bot-shared", local_assurance="high",
    )
    with pytest.raises(IdentityConflict, match="pairing is unavailable"):
        store.complete_channel_pairing(
            challenge_id=challenge2["challenge_id"], pairing_code=code2,
            provider="telegram", provider_account_id="bot-shared", external_subject="1001",
        )
    assert not store.revoke_paired_channel(
        channel_identity_id=binding["channel_identity_id"], person_id=bob["person_id"]
    )
    assert store.revoke_paired_channel(
        channel_identity_id=binding["channel_identity_id"], person_id=alice["person_id"]
    )
    assert store.resolve_channel_binding(
        provider="telegram", provider_account_id="bot-shared", external_subject="1001"
    ) is None


def test_workload_audience_is_narrow_and_required(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(IdentityConflict, match="audience"):
        store.register_workload(client_id="broad", secret_hash="hash", audiences=[], scopes=[])
    workload = store.register_workload(
        client_id="context-reader",
        secret_hash="hash",
        audiences=["context"],
        scopes=["profile:read"],
    )
    loaded = store.workload_for_client("context-reader")
    assert loaded["principal_id"] == workload["principal_id"]
    assert loaded["audiences"] == ["context"]


def test_passkey_challenge_is_one_time_and_counter_detects_replay(tmp_path):
    store = make_store(tmp_path)
    identity = bootstrap(store)
    challenge_id, challenge = store.issue_challenge(person_id=identity["person_id"], purpose="passkey-register")
    assert store.consume_challenge(challenge_id, challenge, "passkey-register") == identity["person_id"]
    with pytest.raises(IdentityRevoked, match="already used"):
        store.consume_challenge(challenge_id, challenge, "passkey-register")
    store.register_passkey(
        person_id=identity["person_id"],
        credential_id="credential-one",
        public_key_pem="test-public-key",
    )
    store.advance_passkey_counter("credential-one", 1)
    with pytest.raises(IdentityRevoked, match="did not advance"):
        store.advance_passkey_counter("credential-one", 1)


def test_legacy_migration_encrypted_backup_round_trip_and_rollback(tmp_path):
    source = tmp_path / "users.json"
    legacy = {
        "admin": {
            "username": "legacy-admin",
            "display_name": "Legacy Admin",
            "email": "admin@example.invalid",
            "hashed_password": "legacy-hash",
            "roles": ["admin"],
            "active": True,
        }
    }
    source.write_text(json.dumps(legacy), encoding="utf-8")
    key = Fernet.generate_key()
    store = make_store(tmp_path)
    migrated = store.migrate_legacy_users(
        source_path=str(source),
        backup_key=key,
        confirmed=True,
    )
    encrypted = (tmp_path / ("users.json." + migrated["batch_id"] + ".pre-phase1.enc")).read_bytes()
    assert b"legacy-admin" not in encrypted
    assert store.identity_for_login("legacy-admin") is not None

    result = store.rollback_legacy_migration(migrated["batch_id"], key)
    assert json.loads(source.read_text(encoding="utf-8")) == legacy
    assert store.identity_for_login("legacy-admin") is None
    assert result["restored_path"] == str(source)


def test_interrupted_migration_leaves_no_partial_identity(tmp_path):
    source = tmp_path / "users.json"
    source.write_text(json.dumps({"admin": {"username": "admin", "hashed_password": "hash", "roles": ["admin"], "active": True}}), encoding="utf-8")
    store = make_store(tmp_path)
    with pytest.raises(MigrationError, match="simulated interruption"):
        store.migrate_legacy_users(
            source_path=str(source),
            backup_key=Fernet.generate_key(),
            confirmed=True,
            interrupt_after_backup=True,
        )
    assert not store.has_people()


def test_migration_recovery_rejects_wrong_key_then_restores(tmp_path):
    source = tmp_path / "users.json"
    legacy = {"admin": {"username": "admin", "hashed_password": "hash", "roles": ["admin"], "active": True}}
    source.write_text(json.dumps(legacy), encoding="utf-8")
    correct_key = Fernet.generate_key()
    store = make_store(tmp_path)
    migrated = store.migrate_legacy_users(source_path=str(source), backup_key=correct_key, confirmed=True)
    with pytest.raises(MigrationError, match="decrypt"):
        store.rollback_legacy_migration(migrated["batch_id"], Fernet.generate_key())
    assert store.identity_for_login("admin") is not None
    store.rollback_legacy_migration(migrated["batch_id"], correct_key)
    assert store.identity_for_login("admin") is None
    assert json.loads(source.read_text(encoding="utf-8")) == legacy
