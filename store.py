# store.py
#
# The SQLite side: one table of events, one small table of notes about
# what was loaded. Everything the rules and the dashboard read comes
# from here.

import sqlite3
import sys

from parsers import parse_line, parse_macos

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    ts      TEXT NOT NULL,   -- local time, 'YYYY-MM-DD HH:MM:SS'
    source  TEXT,            -- auth, web, firewall, macos
    src_ip  TEXT,
    user    TEXT,
    event   TEXT,            -- login_failure, login_success, http_404, fw_block, ...
    detail  TEXT,            -- login method, URL path, or protocol/port
    raw     TEXT             -- the original log line
);
CREATE INDEX IF NOT EXISTS events_by_ip ON events (src_ip, event, ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def open_db(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def reset(db):
    db.execute("DELETE FROM events")
    db.execute("DELETE FROM meta")
    db.commit()


def add_event(db, e):
    db.execute("INSERT INTO events (ts, source, src_ip, user, event, detail, raw) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)",
               (e["ts"], e["source"], e["src_ip"], e["user"], e["event"], e["detail"], e["raw"]))


def ingest_lines(db, lines, macos_only=False):
    """Parse and store lines. Returns (added, skipped).

    A "# ... SYNTHETIC ..." note line marks the database as holding mock
    data, so the dashboard and every output can say so.
    """
    added = 0
    skipped = 0
    for line in lines:
        if line.startswith("#"):
            if "SYNTHETIC" in line.upper():
                db.execute("INSERT OR REPLACE INTO meta VALUES ('synthetic', 'yes')")
            continue
        if line.strip() == "":
            continue

        if macos_only:
            event = parse_macos(line.rstrip("\r\n"))
        else:
            event = parse_line(line)

        if event is None:
            skipped += 1
        else:
            add_event(db, event)
            added += 1
    db.commit()
    return added, skipped


def ingest_file(db, path, macos_only=False):
    """path can be "-" to read from standard input (for pasting)."""
    if path == "-":
        return ingest_lines(db, sys.stdin, macos_only)
    with open(path, encoding="utf-8", errors="replace") as f:
        return ingest_lines(db, f, macos_only)


def is_synthetic(db):
    row = db.execute("SELECT value FROM meta WHERE key = 'synthetic'").fetchone()
    return row is not None and row["value"] == "yes"


def count_events(db):
    return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
