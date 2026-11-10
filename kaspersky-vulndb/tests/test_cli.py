from pathlib import Path

import pytest

from vulndb.cli import EXIT_ERROR, EXIT_NOT_FOUND, EXIT_OK, main

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("db") / "vulndb.sqlite3"
    code = main(
        [
            "init",
            "--db", str(path),
            "--versions", str(DATA / "versions.json"),
            "--vulnerabilities", str(DATA / "vulnerabilities.json"),
        ]
    )
    assert code == EXIT_OK
    return str(path)


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_init_is_repeatable(db_path, capsys):
    code, out, err = run(
        capsys,
        "init",
        "--db", db_path,
        "--versions", str(DATA / "versions.json"),
        "--vulnerabilities", str(DATA / "vulnerabilities.json"),
    )
    assert code == EXIT_OK
    assert "продуктов 24, версий 834" in out
    assert "KLA70478" in err


def test_safe_version(db_path, capsys):
    code, out, _ = run(capsys, "safe-version", "postgresql", "--db", db_path)
    assert code == EXIT_OK
    assert out.strip() == "PostgreSQL (Postgresql): 17.2.1"


def test_safe_version_all(db_path, capsys):
    code, out, _ = run(capsys, "safe-version", "Git for Windows", "--all", "--db", db_path)
    assert code == EXIT_OK
    lines = [line.strip() for line in out.splitlines()[1:]]
    assert lines[0] == "2.47.1.2"
    assert "2.45.1" in lines and "2.45.0" not in lines


def test_vulns_for_fixed_branch_version(db_path, capsys):
    code, out, _ = run(capsys, "vulns", "PostgreSQL", "13.17.1", "--db", db_path)
    assert code == EXIT_OK
    assert "KLA77143" not in out


def test_vulns_lists_advisories(db_path, capsys):
    code, out, _ = run(capsys, "vulns", "PostgreSQL", "13.16", "--db", db_path)
    assert code == EXIT_OK
    assert "известных уязвимостей: 3" in out
    assert "KLA77143" in out and "13 <= версия < 13.17.1" in out
    assert "примечание: версии 13.16 нет в фиде версий" in out


def test_vulns_for_safe_version(db_path, capsys):
    code, out, _ = run(capsys, "vulns", "PostgreSQL", "17.2.1", "--db", db_path)
    assert code == EXIT_OK
    assert "известных уязвимостей нет" in out


def test_unknown_product_suggests_names(db_path, capsys):
    code, _, err = run(capsys, "safe-version", "chrome", "--db", db_path)
    assert code == EXIT_NOT_FOUND
    assert '"Google Chrome"' in err


def test_invalid_version(db_path, capsys):
    code, _, err = run(capsys, "vulns", "PostgreSQL", "13.x", "--db", db_path)
    assert code == EXIT_ERROR
    assert "некорректная версия" in err


def test_missing_database(tmp_path, capsys):
    code, _, err = run(capsys, "products", "--db", str(tmp_path / "missing.sqlite3"))
    assert code == EXIT_ERROR
    assert "vulndb init" in err
    assert not (tmp_path / "missing.sqlite3").exists()
