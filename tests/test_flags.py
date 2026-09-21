"""A flag self-rename succeeds and a refused rename remains an SQL error."""


def test_flag_renames(runner):
    setup = ["INSERT INTO flags(addr,name) VALUES(0,'r2xsql_flag_a')",
             "INSERT INTO flags(addr,name) VALUES(4,'r2xsql_flag_b')"]
    result = runner.script(setup + [
        "UPDATE flags SET name=name WHERE name='r2xsql_flag_a'",
        "UPDATE flags SET name='r2xsql_flag_new' WHERE name='r2xsql_flag_a'",
        "SELECT name FROM flags WHERE name IN ('r2xsql_flag_a','r2xsql_flag_new')"])
    assert result.ok, result.stderr
    assert result.column("name") == ["r2xsql_flag_new"]
    result = runner.script(setup + [
        "UPDATE flags SET name='r2xsql_flag_b' WHERE name='r2xsql_flag_a'",
        "SELECT name FROM flags WHERE name='r2xsql_flag_a'"])
    assert not result.ok
    assert "\nname\nr2xsql_flag_a\n" in result.stdout
