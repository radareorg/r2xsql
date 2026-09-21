# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
"""Public smoke coverage of the SQL surface.

A small, standalone sanity suite a consumer can run against a built
`core_r2xsql` plugin with nothing but a C compiler and radare2 on
PATH: it compiles a deterministic fixture, opens it, and checks that the core
tables, views, the type system, and the writable comment surface behave. The
exhaustive coverage lives in the project's private suite; this file is the
portable, dependency-light layer.

Every assertion targets a surface that genuinely exists and is checked against
the actual table/column names.
"""

from __future__ import annotations

from test_support import R2xsqlRunner


def _addr_of(runner: R2xsqlRunner, name_like: str) -> str:
    r = runner.query(f"SELECT addr FROM funcs WHERE name LIKE '%{name_like}%' LIMIT 1")
    assert r.ok, r.stderr
    assert r.rows, f"no function matching {name_like!r} found"
    return r.rows[0][0]


# --- core tables ------------------------------------------------------------


def test_funcs_is_nonempty(runner: R2xsqlRunner) -> None:
    r = runner.query("SELECT count(*) AS n FROM funcs")
    assert r.ok, r.stderr
    assert int(r.rows[0][0]) > 0


def test_funcs_has_named_function(runner: R2xsqlRunner) -> None:
    # "main" rather than one of the fixture's own helper functions
    # (r2xsql_add/r2xsql_mul/r2xsql_compute): those get real names only from a
    # full local symtab, which ELF (`gcc -g`) embeds directly in the binary but
    # MSVC/PE keeps in a separate .pdb this fixture is built without (for
    # portability). "main" is reliably named on every platform: radare2
    # recognizes the standard CRT startup call into it even with no debug info.
    r = runner.query("SELECT name FROM funcs WHERE name LIKE '%main%'")
    assert r.ok, r.stderr
    assert any("main" in row[0] for row in r.rows)


def test_strings_has_marker(runner: R2xsqlRunner) -> None:
    # The `strings` column is `content` (tables_strings.cpp).
    r = runner.query(
        "SELECT content FROM strings WHERE content LIKE '%r2xsql_test_marker_string%'"
    )
    assert r.ok, r.stderr
    assert r.rows, "marker string not found in strings table"


def test_xrefs_is_nonempty(runner: R2xsqlRunner) -> None:
    # r2xsql_compute calls r2xsql_add and r2xsql_mul, so real CALL xrefs exist.
    r = runner.query("SELECT count(*) AS n FROM xrefs")
    assert r.ok, r.stderr
    assert int(r.rows[0][0]) > 0


def test_sections_has_text_section(runner: R2xsqlRunner) -> None:
    r = runner.query("SELECT name FROM sections WHERE name LIKE '%text%'")
    assert r.ok, r.stderr
    assert r.rows, "no section with 'text' in its name (expected .text/__text)"


# --- function signature / calling convention --------------------------------
# The signature surface is `funcs.prototype` (read) and `funcs.calltype`
# (read-only), both plain columns rather than scalar functions.


def test_funcs_prototype_column_exists(runner: R2xsqlRunner) -> None:
    r = runner.query("SELECT prototype FROM funcs WHERE name LIKE '%main%'")
    assert r.ok, r.stderr
    assert r.columns == ["prototype"]
    assert r.rows, "no row for 'main'"


def test_funcs_calltype_reads_correctly(runner: R2xsqlRunner) -> None:
    # `calltype` is read-only (tables_funcs.cpp declares it `.column_text`, not
    # `.column_text_rw`; the schema catalog's `funcs` write-bullet list never
    # included it) -- caught when a genuinely fresh build (not a stale one --
    # see the MSBuild-staleness note above) rejected the UPDATE with
    # "column \"calltype\" is read-only".
    #
    # What IS worth pinning: the READ must resolve to the correct native calling
    # convention for the target's ABI, NOT the "reg" fallback a degraded
    # calling-convention SDB reports -- the exact failure the calltype data-dir
    # dependency can cause (a real, confirmed radare2 data-dir dependency; see
    # deployment.md).
    #
    # The convention is ABI-specific, so the expectation is platform-aware: a PE
    # (Windows/MSVC) fixture reports "ms" (Microsoft x64); an ELF (Linux/macOS,
    # gcc/clang) fixture reports "amd64" (System V). The invariant on BOTH: it
    # must be the native convention and must NOT be "reg" (the cliff fallback).
    r = runner.query("SELECT lower(value) FROM binary WHERE key = 'bintype'")
    is_pe = bool(r.ok and r.rows and "pe" in r.rows[0][0])
    expected = "ms" if is_pe else "amd64"

    addr = _addr_of(runner, "main")
    r = runner.query(f"SELECT calltype FROM funcs WHERE addr = {addr}")
    assert r.ok, r.stderr
    got = r.rows[0][0] if r.rows else None
    assert got != "reg", (
        f"calltype is 'reg' -- the calling-convention SDB degraded to its "
        f"data-dir-cliff fallback (expected the native {expected!r})"
    )
    assert got == expected, (
        f"expected the native calling convention {expected!r} for a "
        f"{'PE' if is_pe else 'ELF'} target, got {got!r}"
    )


# --- function lookup by address / disassembly -------------------------------
# Both are ordinary table reads (a range query on `funcs`, a scan of
# `instructions`), not scalar functions.


def test_func_lookup_by_address(runner: R2xsqlRunner) -> None:
    addr = _addr_of(runner, "main")
    r = runner.query(
        f"SELECT name FROM funcs WHERE addr <= {addr} AND end_addr > {addr}"
    )
    assert r.ok, r.stderr
    assert any("main" in row[0] for row in r.rows)


def test_instructions_disasm_nonempty(runner: R2xsqlRunner) -> None:
    addr = _addr_of(runner, "main")
    r = runner.query(f"SELECT disasm FROM instructions WHERE func_addr = {addr}")
    assert r.ok, r.stderr
    assert r.rows, "no instructions decoded for main"
    assert all(row[0] for row in r.rows), "an instruction had an empty disasm"


# --- views -------------------------------------------------------------------
# Schema introspection uses `sqlite_master` -- the portable SQL way to list
# tables and views -- rather than any tool-specific introspection command.


def test_names_view_works(runner: R2xsqlRunner) -> None:
    r = runner.query("SELECT name FROM names LIMIT 1")
    assert r.ok, r.stderr
    assert r.rows


def test_schema_lists_funcs_and_callers(runner: R2xsqlRunner) -> None:
    r = runner.query(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') "
        "AND name IN ('funcs','callers')"
    )
    assert r.ok, r.stderr
    names = {row[0] for row in r.rows}
    assert names == {"funcs", "callers"}


# --- type system ---------------------------------------------------------
# A type is defined via the native td command; its members live in
# the `types_members` table (plural "types") -- confirmed against
# tables_types_members.cpp.


def test_type_define_and_read_back(runner: R2xsqlRunner) -> None:
    r = runner.script(
        [
            "SELECT name, kind FROM types WHERE name = 'R2xsqlPt'",
        ],
        write=True,
        setup_commands=['"td struct R2xsqlPt { int x; char name[8]; };"'],
    )
    assert r.ok, r.stderr
    assert r.rows and r.rows[0][0] == "R2xsqlPt" and r.rows[0][1] == "struct"


def test_type_members_populated(runner: R2xsqlRunner) -> None:
    r = runner.script(
        [
            "SELECT member_name FROM types_members WHERE type_name = 'R2xsqlPt2'",
        ],
        write=True,
        setup_commands=['"td struct R2xsqlPt2 { int a; int b; };"'],
    )
    assert r.ok, r.stderr
    members = {row[0] for row in r.rows}
    assert members == {"a", "b"}


# --- entity grep -------------------------------------------------------------
# Named-entity search is the `grep` table's `pattern` pushdown column, not a
# scalar function.


def test_grep_finds_function(runner: R2xsqlRunner) -> None:
    r = runner.query("SELECT name FROM grep WHERE pattern = 'main'")
    assert r.ok, r.stderr
    assert any("main" in row[0] for row in r.rows)


# --- live mutation + injection safety ---------------------------------------
# The writable `comments` table passes its text as `base64:` specifically so a
# value can never be interpreted as an r2 command (schema-catalog.md). The
# second test proves that guard holds.


def test_comment_write_is_live(runner: R2xsqlRunner) -> None:
    addr = _addr_of(runner, "main")
    r = runner.script(
        [
            f"INSERT INTO comments (addr, text) VALUES ({addr}, 'tagged')",
            f"SELECT text FROM comments WHERE addr = {addr}",
        ],
        write=True,
    )
    assert r.ok, r.stderr
    assert any(row[0] == "tagged" for row in r.rows)


def test_comment_text_cannot_inject_a_command(runner: R2xsqlRunner) -> None:
    addr = _addr_of(runner, "main")
    payload = "x; f INJ_FLAG @ 0x1000"
    r = runner.script(
        [
            f"INSERT INTO comments (addr, text) VALUES ({addr}, '{payload}')",
            "SELECT count(*) AS n FROM flags WHERE name = 'INJ_FLAG'",
        ],
        write=True,
    )
    assert r.ok, r.stderr
    assert r.rows and r.rows[-1][0] == "0", "comment text executed as an r2 command"


def test_native_commands_replace_sql_wrappers(runner):
    result = runner.query("SELECT name FROM pragma_function_list WHERE name IN "
                          "('r2xsql_project_save','r2xsql_project_open','r2xsql_type_define')")
    assert result.ok and not result.rows, result.stderr
    result = runner.query("SELECT 'abc' REGEXP '^a' AS matches")
    assert result.ok and result.rows == [["1"]], result.stderr
    result = runner.script(["INSERT INTO types(name,kind) VALUES('EmptyNative','struct')",
                            "DELETE FROM types WHERE name='EmptyNative'",
                            "SELECT name FROM types WHERE name='EmptyNative'"])
    assert result.ok and not result.rows, result.stderr
