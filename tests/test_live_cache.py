"""Repeated queries observe a changed target and register configuration."""

import json
import subprocess


def test_live_cache(r2_bin, r2xsql_plugin, fixture_binary):
    query = '"sqlj SELECT name FROM libs; SELECT addr FROM relocs; SELECT DISTINCT bits FROM registers"'
    commands = [query, "o-- malloc://1024", "e asm.bits=32", query]
    args = [r2_bin, "-N", "-q", "-b", "64", "-i", str(r2xsql_plugin)]
    for command in commands:
        args += ["-c", command]
    proc = subprocess.run(args + [str(fixture_binary)], capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    results = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
    assert len(results) == 2, proc.stdout
    before, after = results
    assert before["success"] and after["success"], results
    assert before["results"][0]["rows"], "fixture must import a library"
    assert before["results"][1]["rows"], "fixture must have relocations"
    assert before["results"][2]["rows"] == [["64"]]
    assert [r["rows"] for r in after["results"]] == [[], [], [["32"]]]
