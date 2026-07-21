"""Transactional Phase 1 identity and principal-binding store."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken


MIGRATION_VERSION = 1


class IdentityConflict(RuntimeError):
    pass


class IdentityNotFound(RuntimeError):
    pass


class IdentityRevoked(RuntimeError):
    pass


class MigrationError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class IdentityStore:
    def __init__(self, database_path: str, migrations_dir: str | None = None):
        self.database_path = str(Path(database_path).expanduser())
        self.migrations_dir = Path(migrations_dir or Path(__file__).resolve().parents[1] / "migrations")
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self.apply_migrations()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def apply_migrations(self) -> None:
        script = (self.migrations_dir / "0001_phase1_identity.sql").read_text(encoding="utf-8")
        with self.connect() as connection:
            connection.executescript(script)
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (MIGRATION_VERSION, "phase1_identity", iso()),
            )

    def schema_version(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
        return int(row["version"] or 0)

    def has_people(self) -> bool:
        with self.connect() as connection:
            row = connection.execute("SELECT 1 FROM persons WHERE status='active' LIMIT 1").fetchone()
        return row is not None

    def has_admin(self) -> bool:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT roles_json FROM login_accounts WHERE active=1"
            ).fetchall()
        return any("admin" in json.loads(row["roles_json"]) for row in rows)

    def _create_person_graph(
        self,
        connection: sqlite3.Connection,
        *,
        login_handle: str,
        display_name: str,
        email: str | None,
        password_hash: str,
        roles: list[str],
        household_id: str | None,
        household_name: str | None,
        membership_role: str,
        source_batch_id: str | None = None,
    ) -> dict[str, Any]:
        created = iso()
        person_id = new_id("per")
        principal_id = f"person:{person_id}"
        assistant_id = new_id("ast")
        membership_id = new_id("mem")
        account_id = new_id("acct")
        household_id = household_id or new_id("hh")
        if household_name is not None:
            connection.execute(
                "INSERT INTO households VALUES (?, ?, 'active', ?, ?)",
                (household_id, household_name, created, source_batch_id),
            )
        connection.execute(
            "INSERT INTO persons VALUES (?, ?, ?, 'active', ?, ?)",
            (person_id, display_name, email, created, source_batch_id),
        )
        connection.execute(
            "INSERT INTO assistant_instances VALUES (?, ?, 'active', ?, ?)",
            (assistant_id, person_id, created, source_batch_id),
        )
        connection.execute(
            "INSERT INTO household_memberships VALUES (?, ?, ?, ?, 'active', ?, NULL, ?)",
            (membership_id, household_id, person_id, membership_role, created, source_batch_id),
        )
        connection.execute(
            "INSERT INTO login_accounts VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (account_id, login_handle, person_id, password_hash, json.dumps(roles), created, source_batch_id),
        )
        resources = {
            "key_handle": new_id("key"),
            "credential_namespace": new_id("cred"),
            "data_namespace": new_id("data"),
            "cache_namespace": new_id("cache"),
            "index_namespace": new_id("index"),
        }
        connection.execute(
            """
            INSERT INTO principal_resources
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (person_id, *resources.values(), created, source_batch_id),
        )
        return {
            "principal_id": principal_id,
            "person_id": person_id,
            "assistant_instance_id": assistant_id,
            "household_id": household_id,
            "membership_id": membership_id,
            "login_handle": login_handle,
            "display_name": display_name,
            "roles": roles,
            **resources,
        }

    def bootstrap_first_person(
        self,
        *,
        confirmed: bool,
        login_handle: str,
        display_name: str,
        household_name: str,
        password_hash: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise IdentityConflict("first-person enrollment requires explicit confirmation")
        with self.transaction() as connection:
            if connection.execute("SELECT 1 FROM persons LIMIT 1").fetchone():
                raise IdentityConflict("first-person enrollment is already complete")
            return self._create_person_graph(
                connection,
                login_handle=login_handle,
                display_name=display_name,
                email=email,
                password_hash=password_hash,
                roles=["admin", "household-admin", "adult-member"],
                household_id=None,
                household_name=household_name,
                membership_role="household-admin",
            )

    def create_invitation(
        self,
        *,
        invited_by_person_id: str,
        household_id: str,
        intended_role: str = "adult-member",
        ttl_minutes: int = 30,
    ) -> tuple[str, dict[str, Any]]:
        invitation_id = new_id("inv")
        raw_token = secrets.token_urlsafe(32)
        created = utc_now()
        expires = created + timedelta(minutes=ttl_minutes)
        with self.transaction() as connection:
            membership = connection.execute(
                """
                SELECT role FROM household_memberships
                WHERE household_id=? AND person_id=? AND status='active'
                """,
                (household_id, invited_by_person_id),
            ).fetchone()
            if membership is None or membership["role"] != "household-admin":
                raise IdentityNotFound("inviter is not an active household administrator")
            connection.execute(
                "INSERT INTO invitations VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                (
                    invitation_id,
                    household_id,
                    invited_by_person_id,
                    _hash_token(raw_token),
                    intended_role,
                    iso(expires),
                    iso(created),
                ),
            )
        return raw_token, {"invitation_id": invitation_id, "expires_at": iso(expires)}

    def accept_invitation(
        self,
        *,
        invitation_token: str,
        login_handle: str,
        display_name: str,
        password_hash: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            invitation = connection.execute(
                """
                SELECT * FROM invitations
                WHERE token_hash=? AND accepted_at IS NULL AND revoked_at IS NULL
                """,
                (_hash_token(invitation_token),),
            ).fetchone()
            if invitation is None:
                raise IdentityNotFound("invitation is invalid or no longer available")
            if datetime.fromisoformat(invitation["expires_at"].replace("Z", "+00:00")) <= utc_now():
                raise IdentityRevoked("invitation has expired")
            identity = self._create_person_graph(
                connection,
                login_handle=login_handle,
                display_name=display_name,
                email=email,
                password_hash=password_hash,
                roles=[invitation["intended_role"]],
                household_id=invitation["household_id"],
                household_name=None,
                membership_role=invitation["intended_role"],
            )
            connection.execute(
                "UPDATE invitations SET accepted_at=? WHERE invitation_id=?",
                (iso(), invitation["invitation_id"]),
            )
            return identity

    def identity_for_login(self, login_handle: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT a.account_id, a.login_handle, a.password_hash, a.roles_json,
                       a.active AS account_active, p.person_id, p.display_name, p.email,
                       p.status AS person_status, ai.assistant_instance_id,
                       ai.status AS assistant_status, hm.household_id, hm.membership_id,
                       hm.role AS membership_role, hm.status AS membership_status,
                       r.key_handle, r.credential_namespace, r.data_namespace,
                       r.cache_namespace, r.index_namespace
                FROM login_accounts a
                JOIN persons p ON p.person_id=a.person_id
                JOIN assistant_instances ai ON ai.person_id=p.person_id
                JOIN household_memberships hm ON hm.person_id=p.person_id
                JOIN principal_resources r ON r.person_id=p.person_id
                WHERE a.login_handle=?
                """,
                (login_handle,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["roles"] = json.loads(result.pop("roles_json"))
        result["principal_id"] = f"person:{result['person_id']}"
        result["active"] = bool(result.pop("account_active")) and all(
            result[name] == "active"
            for name in ("person_status", "assistant_status", "membership_status")
        )
        return result

    def identity_for_person(self, person_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT login_handle FROM login_accounts WHERE person_id=?",
                (person_id,),
            ).fetchone()
        return self.identity_for_login(row["login_handle"]) if row else None

    def list_identities(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            handles = connection.execute(
                "SELECT login_handle FROM login_accounts ORDER BY created_at"
            ).fetchall()
        return [identity for row in handles if (identity := self.identity_for_login(row["login_handle"]))]

    def list_household_members(
        self, *, requesting_person_id: str, household_id: str
    ) -> list[dict[str, Any]]:
        """Return operational membership facts without private resource handles."""
        with self.connect() as connection:
            requester = connection.execute(
                """SELECT 1 FROM household_memberships
                   WHERE household_id=? AND person_id=? AND status='active'""",
                (household_id, requesting_person_id),
            ).fetchone()
            if requester is None:
                raise IdentityNotFound("household membership is unavailable")
            rows = connection.execute(
                """SELECT p.person_id, p.display_name, hm.role AS membership_role,
                          hm.status, ai.assistant_instance_id
                   FROM household_memberships hm
                   JOIN persons p ON p.person_id=hm.person_id
                   JOIN assistant_instances ai ON ai.person_id=p.person_id
                   WHERE hm.household_id=? ORDER BY hm.created_at""",
                (household_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def remove_household_member(
        self,
        *,
        removed_by_person_id: str,
        household_id: str,
        person_id: str,
        reason: str = "household-member-removal",
    ) -> dict[str, Any]:
        """Revoke appliance access without exposing or transferring private data."""
        if removed_by_person_id == person_id:
            raise IdentityConflict("household administrators cannot remove themselves")
        with self.transaction() as connection:
            administrator = connection.execute(
                """SELECT role FROM household_memberships
                   WHERE household_id=? AND person_id=? AND status='active'""",
                (household_id, removed_by_person_id),
            ).fetchone()
            if administrator is None or administrator["role"] != "household-admin":
                raise IdentityNotFound("household membership is unavailable")
            member = connection.execute(
                """SELECT hm.membership_id, p.display_name, ai.assistant_instance_id
                   FROM household_memberships hm
                   JOIN persons p ON p.person_id=hm.person_id
                   JOIN assistant_instances ai ON ai.person_id=p.person_id
                   WHERE hm.household_id=? AND hm.person_id=? AND hm.status='active'""",
                (household_id, person_id),
            ).fetchone()
            if member is None:
                raise IdentityNotFound("household membership is unavailable")
            revoked_at = iso()
            connection.execute(
                "UPDATE household_memberships SET status='revoked', revoked_at=? WHERE membership_id=?",
                (revoked_at, member["membership_id"]),
            )
            connection.execute(
                "UPDATE assistant_instances SET status='revoked' WHERE person_id=?",
                (person_id,),
            )
            connection.execute("UPDATE login_accounts SET active=0 WHERE person_id=?", (person_id,))
            connection.execute(
                """UPDATE sessions SET revoked_at=?, revocation_reason=?
                   WHERE person_id=? AND revoked_at IS NULL""",
                (revoked_at, reason, person_id),
            )
        return {
            "person_id": person_id,
            "assistant_instance_id": member["assistant_instance_id"],
            "display_name": member["display_name"],
            "status": "revoked",
            "private_data_transferred": False,
            "private_keys_disclosed": False,
        }

    def issue_challenge(
        self,
        *,
        person_id: str | None,
        purpose: str,
        ttl_minutes: int = 5,
    ) -> tuple[str, str]:
        challenge_id = new_id("chl")
        challenge = secrets.token_urlsafe(32)
        created = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO authentication_challenges VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (
                    challenge_id,
                    person_id,
                    purpose,
                    _hash_token(challenge),
                    iso(created + timedelta(minutes=ttl_minutes)),
                    iso(created),
                ),
            )
        return challenge_id, challenge

    def consume_challenge(self, challenge_id: str, challenge: str, purpose: str) -> str | None:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM authentication_challenges WHERE challenge_id=? AND purpose=?",
                (challenge_id, purpose),
            ).fetchone()
            if row is None or row["used_at"] is not None:
                raise IdentityRevoked("authentication challenge is invalid or already used")
            if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= utc_now():
                raise IdentityRevoked("authentication challenge expired")
            if not secrets.compare_digest(row["challenge_hash"], _hash_token(challenge)):
                raise IdentityRevoked("authentication challenge does not match")
            connection.execute(
                "UPDATE authentication_challenges SET used_at=? WHERE challenge_id=?",
                (iso(), challenge_id),
            )
            return row["person_id"]

    def register_passkey(
        self,
        *,
        person_id: str,
        credential_id: str,
        public_key_pem: str,
        transports: list[str] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO passkey_credentials VALUES (?, ?, ?, 0, ?, 1, ?, NULL)",
                (credential_id, person_id, public_key_pem, json.dumps(transports or []), iso()),
            )

    def passkey(self, credential_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM passkey_credentials WHERE credential_id=? AND active=1 AND revoked_at IS NULL",
                (credential_id,),
            ).fetchone()
        return dict(row) if row else None

    def advance_passkey_counter(self, credential_id: str, new_count: int) -> None:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT sign_count FROM passkey_credentials WHERE credential_id=? AND active=1",
                (credential_id,),
            ).fetchone()
            if row is None or new_count <= int(row["sign_count"]):
                raise IdentityRevoked("passkey signature counter did not advance")
            connection.execute(
                "UPDATE passkey_credentials SET sign_count=? WHERE credential_id=?",
                (new_count, credential_id),
            )

    def create_session(
        self,
        identity: dict[str, Any],
        *,
        auth_method: str,
        assurance: str,
        lifetime_minutes: int,
        device_principal_id: str | None = None,
    ) -> str:
        session_id = new_id("ses")
        created = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    session_id,
                    identity["principal_id"],
                    identity["person_id"],
                    device_principal_id,
                    auth_method,
                    assurance,
                    iso(created),
                    iso(created + timedelta(minutes=lifetime_minutes)),
                ),
            )
        return session_id

    def session_is_active(self, session_id: str, person_id: str | None = None) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT person_id, expires_at, revoked_at FROM sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
        if row is None or row["revoked_at"] is not None:
            return False
        if person_id is not None and row["person_id"] != person_id:
            return False
        return datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) > utc_now()

    def revoke_session(self, session_id: str, reason: str = "user-request") -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at=?, revocation_reason=?
                WHERE session_id=? AND revoked_at IS NULL
                """,
                (iso(), reason, session_id),
            )
        return cursor.rowcount == 1

    def lock_person(self, person_id: str, reason: str = "locked") -> None:
        with self.transaction() as connection:
            if not connection.execute("SELECT 1 FROM persons WHERE person_id=?", (person_id,)).fetchone():
                raise IdentityNotFound("person not found")
            connection.execute("UPDATE persons SET status='locked' WHERE person_id=?", (person_id,))
            connection.execute("UPDATE login_accounts SET active=0 WHERE person_id=?", (person_id,))
            connection.execute(
                "UPDATE sessions SET revoked_at=?, revocation_reason=? WHERE person_id=? AND revoked_at IS NULL",
                (iso(), reason, person_id),
            )

    def register_device(self, *, person_id: str, display_name: str, assurance: str) -> str:
        device_id = new_id("dev")
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO device_principals VALUES (?, ?, ?, ?, 'active', ?, NULL)",
                (device_id, person_id, display_name, assurance, iso()),
            )
        return device_id

    def revoke_device(self, device_principal_id: str) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE device_principals SET status='revoked', revoked_at=? WHERE device_principal_id=? AND status='active'",
                (iso(), device_principal_id),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at=?, revocation_reason='device-revoked' WHERE device_principal_id=? AND revoked_at IS NULL",
                (iso(), device_principal_id),
            )
        return cursor.rowcount == 1

    def bind_channel_identity(
        self,
        *,
        person_id: str,
        provider: str,
        external_subject: str,
        assurance: str,
    ) -> str:
        channel_id = new_id("chn")
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO channel_identities VALUES (?, ?, ?, ?, ?, 'active', ?, NULL)",
                (channel_id, person_id, provider, _hash_token(external_subject), assurance, iso()),
            )
        return channel_id

    def revoke_channel_identity(self, channel_identity_id: str, person_id: str) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE channel_identities SET status='revoked', revoked_at=?
                WHERE channel_identity_id=? AND person_id=? AND status='active'
                """,
                (iso(), channel_identity_id, person_id),
            )
        return cursor.rowcount == 1

    def register_workload(
        self,
        *,
        client_id: str,
        secret_hash: str,
        audiences: list[str],
        scopes: list[str],
    ) -> dict[str, Any]:
        if not audiences:
            raise IdentityConflict("workload audience is required")
        principal_id = new_id("wrk")
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO workload_principals VALUES (?, ?, ?, ?, ?, 1, ?, NULL)",
                (principal_id, client_id, secret_hash, json.dumps(sorted(set(audiences))), json.dumps(sorted(set(scopes))), iso()),
            )
        return {"principal_id": principal_id, "client_id": client_id, "audiences": audiences, "scopes": scopes}

    def workload_for_client(self, client_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM workload_principals WHERE client_id=? AND active=1 AND revoked_at IS NULL",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["audiences"] = json.loads(result.pop("audiences_json"))
        result["scopes"] = json.loads(result.pop("scopes_json"))
        return result

    def migrate_legacy_users(
        self,
        *,
        source_path: str,
        backup_key: bytes,
        confirmed: bool,
        interrupt_after_backup: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            raise MigrationError("legacy migration requires explicit confirmation")
        if self.has_people():
            raise IdentityConflict("identity store is not empty")
        source = Path(source_path)
        raw = source.read_bytes()
        try:
            users = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MigrationError("legacy user store is invalid") from exc
        if not isinstance(users, dict) or not users:
            raise MigrationError("legacy user store contains no users")
        admins = [item for item in users.values() if "admin" in item.get("roles", []) and item.get("active", True)]
        if len(admins) != 1:
            raise MigrationError("legacy migration requires exactly one active admin")

        batch_id = new_id("mig")
        backup_path = source.with_suffix(source.suffix + f".{batch_id}.pre-phase1.enc")
        backup_path.write_bytes(Fernet(backup_key).encrypt(raw))
        os.chmod(backup_path, 0o600)
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO migration_runs VALUES (?, ?, ?, 'started', ?, NULL, NULL)",
                (batch_id, str(source), str(backup_path), iso()),
            )
        if interrupt_after_backup:
            raise MigrationError("simulated interruption after encrypted backup")

        admin = admins[0]
        try:
            with self.transaction() as connection:
                identity = self._create_person_graph(
                    connection,
                    login_handle=admin["username"],
                    display_name=admin.get("display_name") or admin["username"],
                    email=admin.get("email"),
                    password_hash=admin["hashed_password"],
                    roles=["admin", "household-admin", "adult-member"],
                    household_id=None,
                    household_name=admin.get("household_name") or "My household",
                    membership_role="household-admin",
                    source_batch_id=batch_id,
                )
                connection.execute(
                    "UPDATE migration_runs SET status='complete', completed_at=? WHERE batch_id=?",
                    (iso(), batch_id),
                )
        except Exception as exc:
            with self.transaction() as connection:
                connection.execute(
                    "UPDATE migration_runs SET status='failed', error_code='transaction-failed' WHERE batch_id=?",
                    (batch_id,),
                )
            raise MigrationError("legacy migration transaction failed") from exc
        return {"batch_id": batch_id, "backup_path": str(backup_path), "identity": identity}

    def rollback_legacy_migration(self, batch_id: str, backup_key: bytes) -> dict[str, Any]:
        with self.transaction() as connection:
            run = connection.execute("SELECT * FROM migration_runs WHERE batch_id=?", (batch_id,)).fetchone()
            if run is None or run["status"] != "complete":
                raise MigrationError("migration is not eligible for rollback")
            source_batch_count = connection.execute(
                "SELECT COUNT(*) AS count FROM persons WHERE source_batch_id IS NULL"
            ).fetchone()["count"]
            if source_batch_count:
                raise MigrationError("new identities exist; automatic rollback is unsafe")
            encrypted = Path(run["backup_path"]).read_bytes()
            try:
                restored = Fernet(backup_key).decrypt(encrypted)
            except InvalidToken as exc:
                raise MigrationError("backup key cannot decrypt the migration backup") from exc
            person_rows = connection.execute(
                "SELECT person_id FROM persons WHERE source_batch_id=?", (batch_id,)
            ).fetchall()
            for row in person_rows:
                connection.execute("DELETE FROM persons WHERE person_id=?", (row["person_id"],))
            connection.execute("DELETE FROM households WHERE source_batch_id=?", (batch_id,))
            connection.execute(
                "UPDATE migration_runs SET status='rolled-back', completed_at=? WHERE batch_id=?",
                (iso(), batch_id),
            )
        Path(run["source_path"]).write_bytes(restored)
        os.chmod(run["source_path"], 0o600)
        return {"batch_id": batch_id, "restored_path": run["source_path"]}


__all__ = [
    "IdentityConflict",
    "IdentityNotFound",
    "IdentityRevoked",
    "IdentityStore",
    "MIGRATION_VERSION",
    "MigrationError",
]
