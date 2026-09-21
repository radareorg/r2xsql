"""Native table formatting and suffix dispatch through the plugin."""

import subprocess


def test_table_output(r2_bin, r2xsql_plugin):
    def run(*commands):
        args = [r2_bin, "-N", "-q", "-e", "scr.color=0", "-e", "scr.utf8=false",
                "-i", str(r2xsql_plugin)]
        for command in commands:
            args.extend(["-c", command])
        proc = subprocess.run(args + ["malloc://1024"], capture_output=True,
                              text=True, timeout=15)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    assert run('"sql SELECT 1 AS n, \'abc\' AS name"') == "n name\n------\n1 abc\n"
    assert run('"sql,:csv SELECT 1 AS n, \'a,b\' AS name"') == 'n,name\n1,"a,b"\n'
    assert run('"sql,n/gt/1,n/sort/dec,:quiet SELECT 1 AS n UNION SELECT 2 UNION SELECT 3"') == "3\n2\n"
    assert run("e cfg.table.format=csv", '"sql SELECT 7 AS n"') == "7\n"
    assert ":csv" in run("sql,?")
    assert ":csv" in run("sql,:help")
    assert run('"sql,:csv SELECT 1 AS n WHERE 0"') == "n\n"
    assert run('"sql,:csv SELECT * FROM missing_table"').startswith("ERROR:")
    assert "Unknown sql subcommand" in run("sql.SELECT 1")
