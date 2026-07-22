#!/usr/bin/env python3
"""Explicit, reversible migration from the legacy JSON admin store."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from identity_store import IdentityStore, MigrationError  # noqa: E402


def _key(path: str) -> bytes:
    key_path = Path(path)
    if not key_path.is_file():
        raise MigrationError("backup key file does not exist")
    mode = key_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise MigrationError("backup key file must not be accessible by group or others")
    return key_path.read_bytes().strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, help="Phase 1 SQLite identity database")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status")
    status.add_argument("--legacy-store")

    apply = sub.add_parser("apply")
    apply.add_argument("--legacy-store", required=True)
    apply.add_argument("--backup-key-file", required=True)
    apply.add_argument("--confirm", action="store_true", help="Confirm migration of the first admin profile")

    rollback = sub.add_parser("rollback")
    rollback.add_argument("--batch-id", required=True)
    rollback.add_argument("--backup-key-file", required=True)
    rollback.add_argument("--confirm", action="store_true", help="Confirm destructive database rollback")

    args = parser.parse_args()
    store = IdentityStore(args.database)
    try:
        if args.command == "status":
            print(json.dumps({"schema_version": store.schema_version(), "people_exist": store.has_people(), "legacy_store": args.legacy_store}, indent=2))
            return 0
        if args.command == "apply":
            result = store.migrate_legacy_users(
                source_path=args.legacy_store,
                backup_key=_key(args.backup_key_file),
                confirmed=args.confirm,
            )
            print(json.dumps(result, indent=2))
            return 0
        if not args.confirm:
            raise MigrationError("rollback requires --confirm")
        result = store.rollback_legacy_migration(args.batch_id, _key(args.backup_key_file))
        print(json.dumps(result, indent=2))
        return 0
    except MigrationError as exc:
        print(f"migration refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
