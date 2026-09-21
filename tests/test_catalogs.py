"""Catalog commands follow the live schema, including user-created objects."""

import json
import subprocess


def test_catalogs(r2_bin, r2xsql_plugin):
    commands = ['"sql CREATE TABLE catalog_table(n);"',
                '"sql CREATE VIEW catalog_view AS SELECT 1 AS n;"',
                'e cfg.table.format=tsv']
    for kind, command in [("table", "sql.tables"), ("view", "sql.views")]:
        commands += [command, "?e SPLIT", command + "?", "?e SPLIT",
                     f'"sqlj SELECT name FROM sqlite_master WHERE type=\'{kind}\' ORDER BY name"',
                     "?e SPLIT"]
    commands += ['"sql DROP VIEW catalog_view"', '"sql DROP TABLE catalog_table"',
                 'sql.tables', 'sql.views']
    args = [r2_bin, "-N", "-q", "-e", "scr.color=0", "-i", str(r2xsql_plugin)]
    for command in commands:
        args += ["-c", command]
    result = subprocess.run(args + ["malloc://1024"], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    parts = result.stdout.split("SPLIT\n")
    assert len(parts) == 7, result.stdout
    for offset in (0, 3):
        envelope = json.loads(parts[offset + 2])
        assert envelope["success"], envelope
        names = [row[0] for row in envelope["results"][0]["rows"]]
        assert parts[offset].strip().splitlines() == names
        assert parts[offset + 1].strip() == parts[offset].strip()
    assert "catalog_table" in parts[0] and "catalog_view" in parts[3]
    assert "catalog_table" not in parts[6] and "catalog_view" not in parts[6]
