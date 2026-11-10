from __future__ import annotations

import datetime as dt
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .version import InvalidVersionError, branch_start, version_key

VERSION_FIELDS = ("vendor", "product", "version")
VULNERABILITY_FIELDS = (
    "vendor",
    "product",
    "KLA_id",
    "description",
    "publish_date",
    "start_vuln_version",
    "fixed_version",
)


class FeedError(ValueError):
    pass


@dataclass
class ImportStats:
    vendors: int = 0
    products: int = 0
    versions: int = 0
    advisories: int = 0
    ranges: int = 0
    warnings: list[str] = field(default_factory=list)


def load_feed(path: str | Path) -> list[dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedError(f"не удалось прочитать фид {path}: {exc}") from exc
    if not isinstance(data, list):
        raise FeedError(f"фид {path} должен содержать JSON-массив")
    return data


def import_feeds(
    conn: sqlite3.Connection,
    versions: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
) -> ImportStats:
    importer = _Importer(conn)
    with conn:
        importer.import_versions(versions)
        importer.import_vulnerabilities(vulnerabilities)
    return importer.stats


class _Importer:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.stats = ImportStats()
        self._vendor_ids: dict[str, int] = {}
        self._product_ids: dict[tuple[str, str], int] = {}

    def import_versions(self, records: list[dict[str, Any]]) -> None:
        seen: set[tuple[int, str]] = set()
        for index, record in enumerate(records):
            where = f"versions[{index}]"
            if not self._has_fields(record, VERSION_FIELDS, where):
                continue
            version = record["version"].strip()
            try:
                key = version_key(version)
            except InvalidVersionError as exc:
                self._warn(f"{where}: {exc}")
                continue
            product_id = self._product_id(record["vendor"], record["product"])
            if (product_id, version) in seen:
                self._warn(f"{where}: повторная версия {version} продукта {record['product']}")
                continue
            seen.add((product_id, version))
            self.conn.execute(
                "INSERT INTO product_version (product_id, version, version_key) VALUES (?, ?, ?)",
                (product_id, version, key),
            )
            self.stats.versions += 1

    def import_vulnerabilities(self, records: list[dict[str, Any]]) -> None:
        groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
        advisory_ids: dict[str, int] = {}

        for index, record in enumerate(records):
            where = f"vulnerabilities[{index}]"
            if not self._has_fields(record, VULNERABILITY_FIELDS, where):
                continue
            record = {name: record[name].strip() for name in VULNERABILITY_FIELDS}
            try:
                start_key = version_key(record["start_vuln_version"])
                fixed_key = version_key(record["fixed_version"])
            except InvalidVersionError as exc:
                self._warn(f"{where}: {exc}")
                continue
            try:
                dt.date.fromisoformat(record["publish_date"])
            except ValueError:
                self._warn(f"{where}: некорректная дата {record['publish_date']!r}, запись пропущена")
                continue
            if start_key >= fixed_key:
                self._warn(
                    f"{where}: пустой диапазон {record['start_vuln_version']}"
                    f" .. {record['fixed_version']} в {record['KLA_id']}, запись пропущена"
                )
                continue

            kla_id = record["KLA_id"]
            if kla_id not in advisory_ids:
                advisory_ids[kla_id] = self._insert_advisory(record)
            else:
                self._check_advisory_consistent(record, where)
            groups[(kla_id, record["vendor"], record["product"])].append(record)

        for (kla_id, vendor, product), group in groups.items():
            product_id = self._product_id(vendor, product)
            for record, effective_start in self._effective_starts(group):
                self.conn.execute(
                    """
                    INSERT INTO affected_range (
                        advisory_id, product_id, start_version, fixed_version,
                        effective_start, start_key, fixed_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        advisory_ids[kla_id],
                        product_id,
                        record["start_vuln_version"],
                        record["fixed_version"],
                        effective_start,
                        version_key(effective_start),
                        version_key(record["fixed_version"]),
                    ),
                )
                self.stats.ranges += 1

    def _effective_starts(self, group: list[dict[str, str]]) -> list[tuple[dict[str, str], str]]:
        group = sorted(group, key=lambda record: version_key(record["fixed_version"]))
        result: list[tuple[dict[str, str], str]] = []
        previous_fixed: str | None = None
        for record in group:
            fixed = record["fixed_version"]
            if previous_fixed is not None and version_key(previous_fixed) == version_key(fixed):
                self._warn(
                    f"повторный диапазон ..{fixed} для {record['product']} в {record['KLA_id']}, пропущен"
                )
                continue
            start = record["start_vuln_version"]
            if previous_fixed is not None:
                branch = branch_start(previous_fixed, fixed)
                start = max(start, branch, key=version_key)
            result.append((record, start))
            previous_fixed = fixed
        return result

    def _insert_advisory(self, record: dict[str, str]) -> int:
        cursor = self.conn.execute(
            "INSERT INTO advisory (kla_id, description, publish_date) VALUES (?, ?, ?)",
            (record["KLA_id"], record["description"], record["publish_date"]),
        )
        self.stats.advisories += 1
        return cursor.lastrowid

    def _check_advisory_consistent(self, record: dict[str, str], where: str) -> None:
        stored = self.conn.execute(
            "SELECT description, publish_date FROM advisory WHERE kla_id = ?",
            (record["KLA_id"],),
        ).fetchone()
        if (stored["description"], stored["publish_date"]) != (
            record["description"],
            record["publish_date"],
        ):
            self._warn(
                f"{where}: у {record['KLA_id']} описание или дата отличаются от первой записи,"
                " оставлена первая"
            )

    def _product_id(self, vendor: str, product: str) -> int:
        vendor, product = vendor.strip(), product.strip()
        key = (vendor, product)
        if key not in self._product_ids:
            cursor = self.conn.execute(
                "INSERT INTO product (vendor_id, name) VALUES (?, ?)",
                (self._vendor_id(vendor), product),
            )
            self._product_ids[key] = cursor.lastrowid
            self.stats.products += 1
        return self._product_ids[key]

    def _vendor_id(self, vendor: str) -> int:
        if vendor not in self._vendor_ids:
            cursor = self.conn.execute("INSERT INTO vendor (name) VALUES (?)", (vendor,))
            self._vendor_ids[vendor] = cursor.lastrowid
            self.stats.vendors += 1
        return self._vendor_ids[vendor]

    def _has_fields(self, record: Any, fields: tuple[str, ...], where: str) -> bool:
        if not isinstance(record, dict):
            self._warn(f"{where}: запись не является объектом, пропущена")
            return False
        bad = [name for name in fields if not isinstance(record.get(name), str) or not record[name].strip()]
        if bad:
            self._warn(f"{where}: отсутствуют или пусты поля {', '.join(bad)}, запись пропущена")
            return False
        return True

    def _warn(self, message: str) -> None:
        self.stats.warnings.append(message)
