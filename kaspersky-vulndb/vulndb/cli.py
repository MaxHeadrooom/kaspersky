from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections.abc import Sequence
from contextlib import closing

from . import db, queries
from .importer import FeedError, import_feeds, load_feed
from .queries import Product
from .version import InvalidVersionError

DEFAULT_DB = os.environ.get("VULNDB_DB", "vulndb.sqlite3")

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 3


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db",
        default=DEFAULT_DB,
        help="путь к базе SQLite (по умолчанию: %(default)s или $VULNDB_DB)",
    )
    product_args = argparse.ArgumentParser(add_help=False)
    product_args.add_argument("product", help='название продукта, например "Mozilla Thunderbird" (регистр не важен)')
    product_args.add_argument("--vendor", help="производитель, нужен только если название продукта неоднозначно")

    parser = argparse.ArgumentParser(
        prog="vulndb",
        description="Поиск уязвимостей продуктов по базе, собранной из фидов KLA.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    init = commands.add_parser("init", parents=[common], help="создать базу и загрузить в неё фиды")
    init.add_argument("--versions", default="data/versions.json", help="фид версий (по умолчанию: %(default)s)")
    init.add_argument(
        "--vulnerabilities",
        default="data/vulnerabilities.json",
        help="фид уязвимостей (по умолчанию: %(default)s)",
    )
    init.set_defaults(handler=cmd_init)

    products = commands.add_parser("products", parents=[common], help="список продуктов в базе")
    products.set_defaults(handler=cmd_products)

    safe = commands.add_parser(
        "safe-version",
        parents=[common, product_args],
        help="самая новая версия продукта без известных уязвимостей",
    )
    safe.add_argument("--all", action="store_true", help="вывести все известные версии без уязвимостей")
    safe.set_defaults(handler=cmd_safe_version)

    vulns = commands.add_parser(
        "vulns",
        parents=[common, product_args],
        help="уязвимости, затрагивающие версию продукта",
    )
    vulns.add_argument("version", help="версия продукта, например 115.10.0")
    vulns.set_defaults(handler=cmd_vulns)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except CliError as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return exc.code
    except (db.DatabaseNotInitializedError, FeedError, InvalidVersionError) as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except sqlite3.Error as exc:
        print(f"ошибка базы данных: {exc}", file=sys.stderr)
        return EXIT_ERROR


def cmd_init(args: argparse.Namespace) -> int:
    versions = load_feed(args.versions)
    vulnerabilities = load_feed(args.vulnerabilities)
    conn = db.create(args.db)
    try:
        stats = import_feeds(conn, versions, vulnerabilities)
    finally:
        conn.close()
    for warning in stats.warnings:
        print(f"предупреждение: {warning}", file=sys.stderr)
    print(
        f"База {args.db} создана: производителей {stats.vendors}, продуктов {stats.products}, "
        f"версий {stats.versions}, статей {stats.advisories}, уязвимых диапазонов {stats.ranges}."
    )
    return EXIT_OK


def cmd_products(args: argparse.Namespace) -> int:
    with _connect(args) as conn:
        for product in queries.list_products(conn):
            print(f"{product.name}  ({product.vendor})")
    return EXIT_OK


def cmd_safe_version(args: argparse.Namespace) -> int:
    with _connect(args) as conn:
        product = _resolve_product(conn, args.product, args.vendor)
        known = queries.known_versions(conn, product)
        safe = queries.safe_versions(conn, product)

    if not known:
        print(f"{_label(product)}: в фиде версий нет версий этого продукта.")
        return EXIT_NOT_FOUND
    if not safe:
        print(f"{_label(product)}: все известные версии уязвимы (самая новая: {known[0]}).")
        return EXIT_NOT_FOUND
    if args.all:
        print(f"{_label(product)}: версии без известных уязвимостей (от новых к старым):")
        for version in safe:
            print(f"  {version}")
    else:
        print(f"{_label(product)}: {safe[0]}")
        if safe[0] != known[0]:
            print(f"  примечание: есть более новая версия {known[0]}, но у неё есть уязвимости")
    return EXIT_OK


def cmd_vulns(args: argparse.Namespace) -> int:
    with _connect(args) as conn:
        product = _resolve_product(conn, args.product, args.vendor)
        found = queries.vulnerabilities_for(conn, product, args.version)
        known = queries.known_versions(conn, product)
        safe = queries.safe_versions(conn, product)

    title = f"{product.name} {args.version} ({product.vendor})"
    if not found:
        print(f"{title}: известных уязвимостей нет.")
    else:
        print(f"{title}: известных уязвимостей: {len(found)}\n")
        for vuln in found:
            print(f"{vuln.kla_id}  {vuln.publish_date}  {vuln.description}")
            print(f"    затронуты: {vuln.affected_from} <= версия < {vuln.fixed_version}")
        if safe:
            print(f"\nСамая новая версия без известных уязвимостей: {safe[0]}")

    if known and args.version.strip() not in known:
        print(f"примечание: версии {args.version} нет в фиде версий")
    return EXIT_OK


def _connect(args: argparse.Namespace) -> closing[sqlite3.Connection]:
    return closing(db.connect(args.db))


def _resolve_product(conn: sqlite3.Connection, name: str, vendor: str | None) -> Product:
    matches = queries.find_products(conn, name, vendor)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        vendors = ", ".join(sorted(product.vendor for product in matches))
        raise CliError(f'продукт "{name}" выпускают несколько производителей ({vendors}), укажите --vendor')
    message = f'продукт "{name}"' + (f' производителя "{vendor}"' if vendor else "") + " не найден"
    suggestions = queries.suggest_products(conn, name)
    if suggestions:
        message += "; возможно, вы имели в виду: " + ", ".join(f'"{s}"' for s in suggestions)
    raise CliError(message, EXIT_NOT_FOUND)


def _label(product: Product) -> str:
    return f"{product.name} ({product.vendor})"
