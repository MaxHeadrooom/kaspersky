from __future__ import annotations

import difflib
import sqlite3
from dataclasses import dataclass

from .version import version_key


@dataclass(frozen=True)
class Product:
    id: int
    vendor: str
    name: str


@dataclass(frozen=True)
class Vulnerability:
    kla_id: str
    description: str
    publish_date: str
    affected_from: str
    fixed_version: str


def list_products(conn: sqlite3.Connection) -> list[Product]:
    rows = conn.execute(
        """
        SELECT p.id, v.name AS vendor, p.name
        FROM product p JOIN vendor v ON v.id = p.vendor_id
        ORDER BY p.name COLLATE NOCASE, v.name COLLATE NOCASE
        """
    )
    return [Product(row["id"], row["vendor"], row["name"]) for row in rows]


def find_products(conn: sqlite3.Connection, name: str, vendor: str | None = None) -> list[Product]:
    sql = """
        SELECT p.id, v.name AS vendor, p.name
        FROM product p JOIN vendor v ON v.id = p.vendor_id
        WHERE p.name = ? COLLATE NOCASE
    """
    params: list[str] = [name.strip()]
    if vendor is not None:
        sql += " AND v.name = ? COLLATE NOCASE"
        params.append(vendor.strip())
    return [Product(row["id"], row["vendor"], row["name"]) for row in conn.execute(sql, params)]


def suggest_products(conn: sqlite3.Connection, name: str, limit: int = 5) -> list[str]:
    names = sorted({product.name for product in list_products(conn)})
    needle = name.strip().lower()
    substring = [candidate for candidate in names if needle and needle in candidate.lower()]
    lowered = {candidate.lower(): candidate for candidate in names}
    close = [lowered[match] for match in difflib.get_close_matches(needle, lowered, n=limit, cutoff=0.5)]
    return list(dict.fromkeys(substring + close))[:limit]


def vulnerabilities_for(conn: sqlite3.Connection, product: Product, version: str) -> list[Vulnerability]:
    key = version_key(version)
    rows = conn.execute(
        """
        SELECT a.kla_id, a.description, a.publish_date, r.effective_start, r.fixed_version
        FROM affected_range r JOIN advisory a ON a.id = r.advisory_id
        WHERE r.product_id = ? AND r.start_key <= ? AND ? < r.fixed_key
        ORDER BY a.publish_date DESC, a.kla_id
        """,
        (product.id, key, key),
    )
    result: dict[str, Vulnerability] = {}
    for row in rows:
        result.setdefault(
            row["kla_id"],
            Vulnerability(
                row["kla_id"],
                row["description"],
                row["publish_date"],
                row["effective_start"],
                row["fixed_version"],
            ),
        )
    return list(result.values())


def known_versions(conn: sqlite3.Connection, product: Product) -> list[str]:
    rows = conn.execute(
        "SELECT version FROM product_version WHERE product_id = ? ORDER BY version_key DESC",
        (product.id,),
    )
    return [row["version"] for row in rows]


def safe_versions(conn: sqlite3.Connection, product: Product) -> list[str]:
    rows = conn.execute(
        """
        SELECT v.version
        FROM product_version v
        WHERE v.product_id = ?
          AND NOT EXISTS (
              SELECT 1 FROM affected_range r
              WHERE r.product_id = v.product_id
                AND r.start_key <= v.version_key AND v.version_key < r.fixed_key
          )
        ORDER BY v.version_key DESC
        """,
        (product.id,),
    )
    return [row["version"] for row in rows]
