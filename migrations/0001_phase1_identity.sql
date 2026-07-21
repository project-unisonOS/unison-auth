PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS households (
    household_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'locked', 'deleted')),
    created_at TEXT NOT NULL,
    source_batch_id TEXT
);

CREATE TABLE IF NOT EXISTS persons (
    person_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'locked', 'revoked', 'deleted')),
    created_at TEXT NOT NULL,
    source_batch_id TEXT
);

CREATE TABLE IF NOT EXISTS assistant_instances (
    assistant_instance_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL UNIQUE REFERENCES persons(person_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('active', 'locked', 'revoked')),
    created_at TEXT NOT NULL,
    source_batch_id TEXT
);

CREATE TABLE IF NOT EXISTS household_memberships (
    membership_id TEXT PRIMARY KEY,
    household_id TEXT NOT NULL REFERENCES households(household_id) ON DELETE CASCADE,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('adult-member', 'household-admin', 'dependent', 'caregiver')),
    status TEXT NOT NULL CHECK (status IN ('active', 'invited', 'revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    source_batch_id TEXT,
    UNIQUE (household_id, person_id)
);

CREATE TABLE IF NOT EXISTS login_accounts (
    account_id TEXT PRIMARY KEY,
    login_handle TEXT NOT NULL UNIQUE,
    person_id TEXT NOT NULL UNIQUE REFERENCES persons(person_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    source_batch_id TEXT
);

CREATE TABLE IF NOT EXISTS principal_resources (
    person_id TEXT PRIMARY KEY REFERENCES persons(person_id) ON DELETE CASCADE,
    key_handle TEXT NOT NULL UNIQUE,
    credential_namespace TEXT NOT NULL UNIQUE,
    data_namespace TEXT NOT NULL UNIQUE,
    cache_namespace TEXT NOT NULL UNIQUE,
    index_namespace TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    source_batch_id TEXT
);

CREATE TABLE IF NOT EXISTS device_principals (
    device_principal_id TEXT PRIMARY KEY,
    person_id TEXT REFERENCES persons(person_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    assurance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS channel_identities (
    channel_identity_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_subject_hash TEXT NOT NULL,
    assurance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE (provider, external_subject_hash)
);

CREATE TABLE IF NOT EXISTS workload_principals (
    principal_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    audiences_json TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    person_id TEXT REFERENCES persons(person_id) ON DELETE CASCADE,
    device_principal_id TEXT REFERENCES device_principals(device_principal_id),
    auth_method TEXT NOT NULL,
    assurance TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    public_key_pem TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports_json TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS authentication_challenges (
    challenge_id TEXT PRIMARY KEY,
    person_id TEXT REFERENCES persons(person_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invitations (
    invitation_id TEXT PRIMARY KEY,
    household_id TEXT NOT NULL REFERENCES households(household_id) ON DELETE CASCADE,
    invited_by_person_id TEXT NOT NULL REFERENCES persons(person_id),
    token_hash TEXT NOT NULL UNIQUE,
    intended_role TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS migration_runs (
    batch_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('started', 'complete', 'rolled-back', 'failed')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_person ON sessions(person_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_memberships_person ON household_memberships(person_id, status);
CREATE INDEX IF NOT EXISTS idx_channels_person ON channel_identities(person_id, status);
CREATE INDEX IF NOT EXISTS idx_passkeys_person ON passkey_credentials(person_id, active);
