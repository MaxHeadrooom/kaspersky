import pytest

from vulndb import db, queries
from vulndb.importer import import_feeds


def vuln(kla, product, start, fixed, vendor="ACME", date="2024-01-01", description=None):
    return {
        "vendor": vendor,
        "product": product,
        "KLA_id": kla,
        "description": description or f"Issue {kla}",
        "publish_date": date,
        "start_vuln_version": start,
        "fixed_version": fixed,
    }


def versions(product, *items, vendor="ACME"):
    return [{"vendor": vendor, "product": product, "version": item} for item in items]


@pytest.fixture
def make_db(tmp_path):
    def make(version_records, vuln_records):
        conn = db.create(tmp_path / "test.sqlite3")
        stats = import_feeds(conn, version_records, vuln_records)
        return conn, stats

    return make


def product(conn, name="Widget"):
    (found,) = queries.find_products(conn, name)
    return found


def ids(found):
    return [item.kla_id for item in found]


def test_range_is_half_open(make_db):
    conn, _ = make_db(versions("Widget", "1.0"), [vuln("KLA1", "Widget", "1.2", "1.5")])
    widget = product(conn)
    assert ids(queries.vulnerabilities_for(conn, widget, "1.1.9")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "1.2")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "1.4.99")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "1.5")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "1.5.0.0")) == []


def test_numeric_not_lexicographic_comparison(make_db):
    conn, _ = make_db([], [vuln("KLA1", "Widget", "0", "1.10")])
    assert ids(queries.vulnerabilities_for(conn, product(conn), "1.9")) == ["KLA1"]


def test_multi_branch_advisory_is_split_by_branch(make_db):
    records = [
        vuln("KLA1", "Widget", "0", "13.17.1"),
        vuln("KLA1", "Widget", "0", "12.21.1"),
        vuln("KLA1", "Widget", "0", "14.14.1"),
    ]
    conn, stats = make_db([], records)
    widget = product(conn)
    assert stats.advisories == 1 and stats.ranges == 3
    assert ids(queries.vulnerabilities_for(conn, widget, "11.0")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "12.21.0")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "12.21.1")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "12.22")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "13.0")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "13.17.1")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "14.14.1")) == []
    (found,) = queries.vulnerabilities_for(conn, widget, "13.5")
    assert (found.affected_from, found.fixed_version) == ("13", "13.17.1")


def test_explicit_branch_starts_are_kept(make_db):
    records = [vuln("KLA1", "Widget", "7.0", "7.0.24"), vuln("KLA1", "Widget", "7.1", "7.1.6")]
    conn, _ = make_db([], records)
    widget = product(conn)
    assert ids(queries.vulnerabilities_for(conn, widget, "6.9")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "7.0.23")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, widget, "7.0.24")) == []
    assert ids(queries.vulnerabilities_for(conn, widget, "7.1.5")) == ["KLA1"]


def test_advisory_shared_by_products(make_db):
    records = [vuln("KLA1", "Widget", "0", "2.0"), vuln("KLA1", "Widget Pro", "0", "3.0")]
    conn, stats = make_db([], records)
    assert stats.advisories == 1 and stats.products == 2
    assert ids(queries.vulnerabilities_for(conn, product(conn, "Widget Pro"), "2.5")) == ["KLA1"]
    assert ids(queries.vulnerabilities_for(conn, product(conn, "Widget"), "2.5")) == []


def test_results_newest_first(make_db):
    records = [
        vuln("KLA1", "Widget", "0", "5", date="2023-01-01"),
        vuln("KLA2", "Widget", "0", "5", date="2024-06-01"),
        vuln("KLA3", "Widget", "0", "5", date="2022-03-01"),
    ]
    conn, _ = make_db([], records)
    assert ids(queries.vulnerabilities_for(conn, product(conn), "1")) == ["KLA2", "KLA1", "KLA3"]


def test_safe_versions(make_db):
    conn, _ = make_db(
        versions("Widget", "1.0", "1.9", "1.10", "2.0", "2.1", "3.0"),
        [vuln("KLA1", "Widget", "0", "1.10"), vuln("KLA2", "Widget", "2.0", "2.2")],
    )
    widget = product(conn)
    assert queries.safe_versions(conn, widget) == ["3.0", "1.10"]
    assert queries.known_versions(conn, widget) == ["3.0", "2.1", "2.0", "1.10", "1.9", "1.0"]


def test_no_safe_versions(make_db):
    conn, _ = make_db(versions("Widget", "1.0", "1.1"), [vuln("KLA1", "Widget", "0", "2.0")])
    assert queries.safe_versions(conn, product(conn)) == []


def test_find_products_ignores_case_and_filters_vendor(make_db):
    conn, _ = make_db(
        versions("Widget", "1.0", vendor="ACME") + versions("Widget", "1.0", vendor="Globex"),
        [],
    )
    assert len(queries.find_products(conn, "  widget ")) == 2
    (found,) = queries.find_products(conn, "WIDGET", vendor="globex")
    assert found.vendor == "Globex"
    assert queries.find_products(conn, "Widg") == []


def test_suggest_products(make_db):
    conn, _ = make_db(versions("Google Chrome", "1") + versions("Mozilla Firefox ESR", "1"), [])
    assert queries.suggest_products(conn, "chrome") == ["Google Chrome"]
    assert queries.suggest_products(conn, "Mozila Firefox ESR") == ["Mozilla Firefox ESR"]


def test_malformed_records_are_skipped_with_warnings(make_db):
    conn, stats = make_db(
        [
            {"vendor": "ACME", "product": "Widget", "version": "1.0"},
            {"vendor": "ACME", "product": "Widget", "version": "1.0"},
            {"vendor": "ACME", "product": "Widget", "version": "beta"},
            {"vendor": "ACME", "product": "Widget"},
            "not an object",
        ],
        [
            vuln("KLA1", "Widget", "0", "2.0"),
            vuln("KLA2", "Widget", "3", "3.0"),
            vuln("KLA3", "Widget", "0", "2.0", date="yesterday"),
            vuln("KLA1", "Widget", "0", "2.0"),
            {**vuln("KLA4", "Widget", "0", "1"), "fixed_version": None},
            vuln("KLA1", "Widget", "0", "5.0", description="Other text"),
        ],
    )
    assert stats.versions == 1
    assert stats.advisories == 1
    assert stats.ranges == 2
    assert len(stats.warnings) == 9
    assert conn.execute("SELECT description FROM advisory").fetchone()[0] == "Issue KLA1"
