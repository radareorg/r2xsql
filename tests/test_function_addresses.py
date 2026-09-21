"""A func_addr equality must not relabel a containing function's rows."""

import json
import subprocess


def test_function_addresses(r2_bin, r2xsql_plugin):
    tables = ["blocks", "cfg_edges", "switch_tables", "dominators", "post_dominators",
              "loops", "instructions", "instruction_operands", "esil_ops", "esil_operands",
              "function_frames", "pseudocode"]
    # x86-64: xor eax,eax; inc eax; cmp eax,3; jl loop; ret
    args = [r2_bin, "-N", "-q", "-a", "x86", "-b", "64", "-i", str(r2xsql_plugin),
            "-c", "wx 31c0ffc083f8037cf9c3", "-c", "af @ 0"]
    for table in tables:
        for address in (0, 1, 128):
            # SELECT * forces rendered instruction columns on the libr backend.
            args += ["-c", f'"sqlj SELECT * FROM {table} WHERE func_addr={address}"']
    proc = subprocess.run(args + ["malloc://1024"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    results = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
    assert len(results) == len(tables) * 3, proc.stdout
    for i, table in enumerate(tables):
        start, interior, missing = results[i * 3:i * 3 + 3]
        if table == "pseudocode" and not start["success"]:
            assert "no such table: pseudocode" in start["results"][0]["error"]
            continue
        for result in (start, interior, missing):
            assert result["success"], (table, result)
        assert interior["results"][0]["rows"] == [], table
        assert missing["results"][0]["rows"] == [], table
        if table != "switch_tables":
            assert start["results"][0]["rows"], table
