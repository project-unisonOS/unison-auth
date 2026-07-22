CREATE TABLE IF NOT EXISTS channel_pairing_challenges (
    challenge_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    minimum_local_assurance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'used', 'expired', 'revoked')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS channel_binding_details (
    channel_identity_id TEXT PRIMARY KEY REFERENCES channel_identities(channel_identity_id) ON DELETE CASCADE,
    assistant_instance_id TEXT NOT NULL REFERENCES assistant_instances(assistant_instance_id) ON DELETE CASCADE,
    provider_account_id TEXT NOT NULL,
    paired_challenge_id TEXT NOT NULL REFERENCES channel_pairing_challenges(challenge_id),
    last_verified_at TEXT NOT NULL,
    reassignment_guard TEXT NOT NULL,
    UNIQUE (provider_account_id, reassignment_guard)
);

CREATE INDEX IF NOT EXISTS idx_pairing_person_status
ON channel_pairing_challenges(person_id, provider, status);
