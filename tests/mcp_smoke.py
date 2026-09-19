#!/usr/bin/env python3
"""Exercise the in-r2 plugin through r2mcp using only the Python standard library."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from test_support import build_fixture


def check(r2mcp: Path, plugin: Path, fixture: Path) -> None:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "r2xsql-smoke", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    ]
    calls = [
        ("open_file", {"file_path": str(fixture)}),
        ("run_command", {"command": "aa"}),
        ("sql", {"query": "SELECT count(*) AS n FROM funcs"}),
        ("sql", {"query": "SELECT 7 > 3 AS comparison, 'a|b;?e INJECTED' AS literal"}),
        ("sql", {"query": "INSERT INTO comments(addr, text) VALUES(0, 'via r2mcp')"}),
        ("sql", {"query": "SELECT text FROM comments WHERE addr = 0"}),
        ("sql", {"query": "DELETE FROM comments WHERE addr = 0"}),
        ("sql", {"query": "SELECT count(*) AS n FROM comments WHERE addr = 0"}),
        ("run_command", {"command": "sql.?"}),

    ]
    for ident, (name, arguments) in enumerate(calls, 2):
        requests.append({"jsonrpc": "2.0", "id": ident, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
    result = subprocess.run(
        [str(r2mcp), "-n", "-N", "-r", "-c", f"L {plugin}"],
        input="\n".join(json.dumps(r) for r in requests) + "\n",
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # Parse every line: startup commands must not leak output onto MCP stdout.
    replies = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(replies) == len(calls) + 1, result.stdout
    by_id = {reply["id"]: reply for reply in replies}
    for reply in replies:
        assert "error" not in reply, reply
        assert not reply["result"].get("isError"), reply

    def text(ident):
        return by_id[ident]["result"]["content"][0]["text"]

    assert int(text(4).splitlines()[1]) > 0, text(4)
    assert text(5) == "comparison\tliteral\n1\ta|b;?e INJECTED\n(1 rows)\n", text(5)
    assert text(7) == "text\nvia r2mcp\n(1 rows)\n", text(7)
    assert text(9) == "n\n0\n(1 rows)\n", text(9)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("r2mcp", type=Path, help="path to the r2mcp executable")
    parser.add_argument("plugin", type=Path, help="path to core_r2xsql.so/.dylib/.dll")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="r2xsql-mcp-") as tmp:
        fixture = build_fixture(Path(tmp))
        check(args.r2mcp.resolve(), args.plugin.resolve(), fixture)
    print("MCP SQL reads, writes, operators, help and removed commands: OK")
