"""Machine-readable SQL scripts preserve NULLs, errors, and session state."""

import json
import subprocess


def test_sqlj(r2_bin, r2xsql_plugin):
    def run(sql):
        command = '"sqlj ' + sql.replace('"', '\\"') + '"'
        proc = subprocess.run([r2_bin, "-N", "-q", "-i", str(r2xsql_plugin),
                               "-c", command, "malloc://1024"],
                              capture_output=True, text=True, timeout=15)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    result = run("SELECT NULL AS missing, '' AS empty, 'NULL' AS literal; SELECT 7 > 3 AS n")
    assert result["success"] and result["statement_count"] == 2
    first, second = result["results"]
    assert first["columns"] == ["missing", "empty", "literal"]
    assert first["rows"] == [[None, "", "NULL"]]
    assert second["rows"] == [["1"]]
    assert result["elapsed_ms_total"] >= 0

    result = run("INSERT INTO comments(addr,text) VALUES(0,'a;b|c'); SELECT text FROM comments WHERE addr=0")
    assert result["success"]
    assert result["results"][1]["rows"] == [["a;b|c"]]
    result = run("SELECT 1; SELECT * FROM missing_table; SELECT 2")
    assert not result["success"] and len(result["results"]) == 2
    assert "missing_table" in result["results"][1]["error"]
    result = run("SELECT 'unterminated")
    assert not result["success"] and result["results"][0]["error"]
