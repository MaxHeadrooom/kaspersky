from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE vendor (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE product (
    id        INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendor (id),
    name      TEXT NOT NULL,
    UNIQUE (vendor_id, name)
);
CREATE INDEX product_name_idx ON product (name COLLATE NOCASE);

CREATE TABLE product_version (
    id          INTEGER PRIMARY KEY,
    product_id  INTEGER NOT NULL REFERENCES product (id),
    version     TEXT NOT NULL,
    version_key TEXT NOT NULL,
    UNIQUE (product_id, version)
);
CREATE INDEX product_version_key_idx ON product_version (product_id, version_key);

CREATE TABLE advisory (
    id           INTEGER PRIMARY KEY,
    kla_id       TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL,
    publish_date TEXT NOT NULL
);

CREATE TABLE affected_range (
    id              INTEGER PRIMARY KEY,
    advisory_id     INTEGER NOT NULL REFERENCES advisory (id),
    product_id      INTEGER NOT NULL REFERENCES product (id),
    start_version   TEXT NOT NULL,
    fixed_version   TEXT NOT NULL,
    effective_start TEXT NOT NULL,
    start_key       TEXT NOT NULL,
    fixed_key       TEXT NOT NULL,
    UNIQUE (advisory_id, product_id, fixed_version)
);
CREATE INDEX affected_range_lookup_idx ON affected_range (product_id, start_key, fixed_key);
"""

TABLES = ("affected_range", "advisory", "product_version", "product", "vendor")


class DatabaseNotInitializedError(RuntimeError):
    pass


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    if not path.is_file():
        raise DatabaseNotInitializedError(
            f"база {path} не найдена, сначала выполните `vulndb init`"
        )
    conn = _open(path)
    existing = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not set(TABLES) <= existing:
        conn.close()
        raise DatabaseNotInitializedError(
            f"в базе {path} нет схемы, сначала выполните `vulndb init`"
        )
    return conn


def create(path: str | Path) -> sqlite3.Connection:
    conn = _open(Path(path))
    with conn:
        for table in TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.executescript(SCHEMA)
    return conn


def _open(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
