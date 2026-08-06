#!/usr/bin/env python3
"""
ShadowGrid History Archiver — storage tiering for the onboard eMMC.

Keeps the most recent N days of time-series telemetry in the live database
(on the small onboard eMMC) and moves everything older to a cold-archive
SQLite database on external storage (the USB drive). Rows are copied to the
archive and only then deleted locally, inside a transaction per table, so a
row is never deleted unless it was successfully archived.

The archive DB is a normal SQLite file — query it directly:
    sqlite3 /mnt/data01/shadowgrid-archive.db "SELECT * FROM readings LIMIT 5;"

Usage:
    python3 archive_history.py                 # archive with defaults
    python3 archive_history.py --days 14       # retention window (default 14)
    python3 archive_history.py --dry-run       # report only, change nothing
    python3 archive_history.py --archive-dir /mnt/data01
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Time-series telemetry tables that get tiered. Config/registry/audit tables
# (devices, auth, bms_passwords, maintenance_log, loadshed_log, ...) are left
# untouched on purpose — they are small and not append-only history.
TELEMETRY_TABLES = [
    "readings",
    "energy_log",
    "victron_readings",
    "ecoflow_readings",
    "scanner_log",
    "remote_readings",
    "weather_log",
    "chargecontroller_readings",
    "balance_log",
    "balance_snapshots",
    "cerbo_readings",
    "power_readings",
]

DEFAULT_DB = str(Path(__file__).resolve().parent / "shadowgrid.db")
DEFAULT_ARCHIVE_DIR = "/mnt/data01"
ARCHIVE_NAME = "shadowgrid-archive.db"
TS_COL = "timestamp"


def log(msg: str) -> None:
    print(f"[archive] {msg}", flush=True)


def table_exists(conn: sqlite3.Connection, schema: str, name: str) -> bool:
    r = conn.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return r is not None


def has_timestamp_col(conn: sqlite3.Connection, name: str) -> bool:
    cols = [c[1] for c in conn.execute(f'PRAGMA table_info("{name}")').fetchall()]
    return TS_COL in cols


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier ShadowGrid history to external storage.")
    ap.add_argument("--db", default=DEFAULT_DB, help="Live database path")
    ap.add_argument("--archive-dir", default=DEFAULT_ARCHIVE_DIR,
                    help="Directory on external storage for the archive DB")
    ap.add_argument("--days", type=int, default=14,
                    help="Days of history to keep locally (default 14)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would move; make no changes")
    args = ap.parse_args()

    if args.days < 1:
        log("ERROR: --days must be >= 1")
        return 2

    live_path = Path(args.db)
    if not live_path.exists():
        log(f"ERROR: live DB not found: {live_path}")
        return 2

    archive_dir = Path(args.archive_dir)
    # Safety: refuse to write the archive unless the target is a real mount.
    # Otherwise we'd silently write to the onboard eMMC and defeat the point.
    if not os.path.ismount(str(archive_dir)):
        log(f"ERROR: {archive_dir} is not a mounted filesystem — aborting so we "
            f"don't archive onto the onboard disk. Is the USB drive plugged in?")
        return 3
    if not os.access(str(archive_dir), os.W_OK):
        log(f"ERROR: {archive_dir} is not writable by {os.environ.get('USER','?')}")
        return 3

    archive_path = archive_dir / ARCHIVE_NAME

    # Cutoff in the SAME textual format the app stores (datetime.now().isoformat(),
    # e.g. 2026-08-01T11:35:48.540561) so lexical string comparison is correct.
    cutoff = (datetime.now() - timedelta(days=args.days)).isoformat()
    log(f"live DB       : {live_path}")
    log(f"archive DB    : {archive_path}")
    log(f"retention     : {args.days} days  (move rows with {TS_COL} < {cutoff})")
    if args.dry_run:
        log("mode          : DRY RUN (no changes)")

    size_before = live_path.stat().st_size

    conn = sqlite3.connect(str(live_path), timeout=60)
    conn.execute("PRAGMA busy_timeout = 60000")  # wait out the running service
    conn.execute("ATTACH DATABASE ? AS arc", (str(archive_path),))

    total_moved = 0
    per_table = {}
    try:
        for name in TELEMETRY_TABLES:
            if not table_exists(conn, "main", name):
                continue
            if not has_timestamp_col(conn, name):
                log(f"  {name}: no '{TS_COL}' column, skipping")
                continue

            n = conn.execute(
                f'SELECT COUNT(*) FROM main."{name}" WHERE "{TS_COL}" < ?', (cutoff,)
            ).fetchone()[0]

            if n == 0:
                per_table[name] = 0
                continue

            if args.dry_run:
                log(f"  {name}: would move {n} rows")
                per_table[name] = n
                total_moved += n
                continue

            # Ensure the archive table exists with matching columns.
            if not table_exists(conn, "arc", name):
                conn.execute(
                    f'CREATE TABLE arc."{name}" AS SELECT * FROM main."{name}" WHERE 0'
                )
                conn.execute(
                    f'CREATE INDEX IF NOT EXISTS arc."idx_{name}_ts" ON "{name}"("{TS_COL}")'
                )

            # Copy-then-delete atomically; verify counts match before commit.
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                f'INSERT INTO arc."{name}" SELECT * FROM main."{name}" WHERE "{TS_COL}" < ?',
                (cutoff,),
            )
            inserted = conn.execute(
                f'SELECT COUNT(*) FROM arc."{name}" WHERE "{TS_COL}" < ?', (cutoff,)
            ).fetchone()[0]
            deleted = conn.execute(
                f'DELETE FROM main."{name}" WHERE "{TS_COL}" < ?', (cutoff,)
            ).rowcount
            if deleted != n or inserted < n:
                conn.execute("ROLLBACK")
                log(f"  {name}: COUNT MISMATCH (expected {n}, archived {inserted}, "
                    f"deleted {deleted}) — rolled back, nothing changed")
                return 4
            conn.commit()
            log(f"  {name}: moved {deleted} rows -> archive")
            per_table[name] = deleted
            total_moved += deleted
    finally:
        if not args.dry_run and total_moved > 0:
            # Reclaim freed space on the onboard disk (DELETE alone doesn't shrink).
            log("VACUUM live DB to reclaim space...")
            conn.execute("VACUUM")
        conn.execute("DETACH DATABASE arc")
        conn.close()

    if args.dry_run:
        log(f"DRY RUN complete — {total_moved} rows are older than {args.days} days")
        return 0

    size_after = live_path.stat().st_size
    freed = size_before - size_after
    log(f"done — moved {total_moved} rows total")
    log(f"live DB: {size_before/1024/1024:.1f} MB -> {size_after/1024/1024:.1f} MB "
        f"(freed {freed/1024/1024:.1f} MB)")
    if archive_path.exists():
        log(f"archive DB size: {archive_path.stat().st_size/1024/1024:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
