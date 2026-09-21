"""Exercise the plugin through radare2's own HTTP command endpoint."""

import socket
import subprocess
import time
from urllib.parse import quote
from urllib.request import build_opener, ProxyHandler

import pytest


@pytest.mark.parametrize("post", [False, True], ids=["GET", "POST"])
def test_r2_http(r2_bin, r2xsql_plugin, fixture_binary, tmp_path, post):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    http = build_opener(ProxyHandler({}))

    def command(text, use_post=post):
        url = f"http://127.0.0.1:{port}/cmd/" + ("" if use_post else quote(text, safe=""))
        with http.open(url, data=text.encode() if use_post else None, timeout=5) as response:
            assert response.status == 200
            return response.read().decode()

    def sql(text):
        return command('"sql ' + text.replace('"', '\\"') + '"')

    log_path = tmp_path / "r2-http.log"
    with log_path.open("w") as log:
        proc = subprocess.Popen([
            r2_bin, "-N", "-q", "-e", "http.bind=127.0.0.1", "-e", f"http.port={port}",
            "-e", "http.log=false", "-e", "scr.color=0",
            "-i", str(r2xsql_plugin), "-c", "aa", "-c", "=h", str(fixture_binary),
        ], stdout=log, stderr=log, cwd=tmp_path)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert proc.poll() is None, log_path.read_text()
                try:
                    command("?V")
                    break
                except OSError:
                    assert time.monotonic() < deadline, log_path.read_text()
                    time.sleep(0.05)

            assert "sql <SQL>" in command("sql?"), log_path.read_text()
            assert int(sql("SELECT count(*) AS n FROM funcs").splitlines()[1]) > 0
            literal = "a|b;?e INJECTED & # % + ? @ café" + ("x" * 4096 if post else "")
            assert sql(f"SELECT 7 > 3 AS comparison, 1 | 2 AS bits, '{literal}' AS literal") == (
                f"comparison\tbits\tliteral\n1\t3\t{literal}\n(1 rows)\n")
            assert sql('SELECT 9 AS "quoted id"') == "quoted id\n9\n(1 rows)\n"
            payload = "x; f R2XSQL_HTTP_INJECTED @ 0x1000 | > < & # % + ?"
            assert "ERROR:" not in sql(f"INSERT INTO comments(addr,text) VALUES(0, '{payload}')")
            assert sql("SELECT text FROM comments WHERE addr=0") == f"text\n{payload}\n(1 rows)\n"
            assert sql("SELECT count(*) AS n FROM flags WHERE name='R2XSQL_HTTP_INJECTED'") == "n\n0\n(1 rows)\n"
            assert "ERROR:" not in sql("UPDATE comments SET text='updated' WHERE addr=0")
            assert sql("SELECT text FROM comments WHERE addr=0") == "text\nupdated\n(1 rows)\n"
            assert "ERROR:" not in sql("DELETE FROM comments WHERE addr=0")
            assert sql("SELECT count(*) AS n FROM comments WHERE addr=0") == "n\n0\n(1 rows)\n"
            assert sql("SELECT * FROM nonexistent_table").startswith("ERROR:")
            assert sql("SELECT 42 AS alive") == "alive\n42\n(1 rows)\n"
            assert "sql.http" not in command("sql.?")
            for removed in ("sql.http", "sql.http?", "sql.http-"):
                assert f"Unknown sql subcommand: {removed}" in command(removed)
            command("=h--", use_post=False)
            assert proc.wait(timeout=5) == 0, log_path.read_text()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
