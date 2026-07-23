from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.identity_store import IdentityConflict, IdentityStore


def _identity(store):
    return store.bootstrap_first_person(
        confirmed=True,
        login_handle="alice",
        display_name="Alice",
        email=None,
        password_hash="hash",
        household_name="Home",
    )


def _checkpoint(sequence=1, digest="a" * 64):
    return {
        "opaque_scope_id": "opaque-person-alice",
        "sequence": sequence,
        "manifest_digest": digest,
        "signer_fingerprint": "b" * 64,
    }


def _public(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_recovery_authority_is_person_controlled_and_not_admin_recoverable(tmp_path):
    store = IdentityStore(str(tmp_path / "identity.db"))
    identity = _identity(store)
    key = Ed25519PrivateKey.generate()
    enrollment = store.enroll_recovery_authority(
        person_id=identity["person_id"],
        recovery_public_key=_public(key),
        capsule_digest=hashlib.sha256(b"ciphertext-capsule").hexdigest(),
        checkpoint=_checkpoint(),
        locally_authenticated=True,
        input_modality="keyboard",
    )
    assert enrollment["provider_has_recovery_secret"] is False
    assert enrollment["household_admin_can_recover"] is False
    assert store.schema_version() == 3


@pytest.mark.parametrize("modality", ["voice", "remote-channel"])
def test_voice_and_remote_channel_cannot_enroll_recovery(tmp_path, modality):
    store = IdentityStore(str(tmp_path / f"{modality}.db"))
    identity = _identity(store)
    with pytest.raises(IdentityConflict, match="local non-voice"):
        store.enroll_recovery_authority(
            person_id=identity["person_id"],
            recovery_public_key=_public(Ed25519PrivateKey.generate()),
            capsule_digest="a" * 64,
            checkpoint=_checkpoint(),
            locally_authenticated=True,
            input_modality=modality,
        )


def test_replacement_device_requires_signed_proof_and_current_anchor(tmp_path):
    store = IdentityStore(str(tmp_path / "identity.db"))
    identity = _identity(store)
    key = Ed25519PrivateKey.generate()
    enrollment = store.enroll_recovery_authority(
        person_id=identity["person_id"],
        recovery_public_key=_public(key),
        capsule_digest="a" * 64,
        checkpoint=_checkpoint(),
        locally_authenticated=True,
        input_modality="keyboard",
    )
    challenge = store.issue_recovery_challenge(
        recovery_enrollment_id=enrollment["recovery_enrollment_id"],
        target_device_id="device-replacement",
    )
    checkpoint = _checkpoint(sequence=2, digest="c" * 64)
    signed = (
        f"unison-recovery-v1:{challenge['challenge_id']}:"
        f"{challenge['challenge']}:device-replacement:{checkpoint['manifest_digest']}"
    ).encode()
    signature = base64.urlsafe_b64encode(key.sign(signed)).decode().rstrip("=")
    result = store.complete_replacement_device_recovery(
        recovery_enrollment_id=enrollment["recovery_enrollment_id"],
        challenge_id=challenge["challenge_id"],
        target_device_id="device-replacement",
        signature=signature,
        checkpoint=checkpoint,
        input_modality="keyboard",
    )
    assert result["person_id"] == identity["person_id"]
    assert result["old_devices_revoked"] is True
    assert result["person_key_rotation_required"] is True
    assert result["shared_space_rewrap_required"] is True


def test_replacement_device_rejects_rollback_wrong_signature_and_admin_substitution(tmp_path):
    store = IdentityStore(str(tmp_path / "identity.db"))
    identity = _identity(store)
    key = Ed25519PrivateKey.generate()
    enrollment = store.enroll_recovery_authority(
        person_id=identity["person_id"],
        recovery_public_key=_public(key),
        capsule_digest="a" * 64,
        checkpoint=_checkpoint(sequence=4, digest="d" * 64),
        locally_authenticated=True,
        input_modality="keyboard",
    )
    challenge = store.issue_recovery_challenge(
        recovery_enrollment_id=enrollment["recovery_enrollment_id"],
        target_device_id="device-replacement",
    )
    with pytest.raises(IdentityConflict, match="rolled back"):
        store.complete_replacement_device_recovery(
            recovery_enrollment_id=enrollment["recovery_enrollment_id"],
            challenge_id=challenge["challenge_id"],
            target_device_id="device-replacement",
            signature="invalid",
            checkpoint=_checkpoint(sequence=3),
            input_modality="keyboard",
        )
    current = _checkpoint(sequence=5, digest="e" * 64)
    with pytest.raises(IdentityConflict, match="proof is invalid"):
        store.complete_replacement_device_recovery(
            recovery_enrollment_id=enrollment["recovery_enrollment_id"],
            challenge_id=challenge["challenge_id"],
            target_device_id="device-replacement",
            signature=base64.urlsafe_b64encode(
                Ed25519PrivateKey.generate().sign(b"administrator substitution")
            ).decode().rstrip("="),
            checkpoint=current,
            input_modality="keyboard",
        )
