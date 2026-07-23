CREATE TABLE IF NOT EXISTS recovery_enrollments (
    recovery_enrollment_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    recovery_public_key TEXT NOT NULL,
    capsule_digest TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked')),
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    UNIQUE(person_id, recovery_public_key)
);

CREATE TABLE IF NOT EXISTS recovery_challenges (
    challenge_id TEXT PRIMARY KEY,
    recovery_enrollment_id TEXT NOT NULL REFERENCES recovery_enrollments(recovery_enrollment_id) ON DELETE CASCADE,
    target_device_id TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS recovery_events (
    recovery_event_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    recovery_enrollment_id TEXT NOT NULL,
    target_device_id TEXT,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at TEXT NOT NULL,
    detail_code TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_enrollments_person
    ON recovery_enrollments(person_id, status);
CREATE INDEX IF NOT EXISTS idx_recovery_challenges_enrollment
    ON recovery_challenges(recovery_enrollment_id, expires_at);
