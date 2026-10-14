# SQL access

## Queries

For direct console use or programmatic clients:

```sql
SELECT name, size FROM funcs WHERE name LIKE 'main%';
SELECT content  FROM strings WHERE content LIKE '%password%';
UPDATE comments SET text = 'reviewed' WHERE addr = 0x1234;
```

Tables read native analysis data or the JSON form of the relevant r2 command
(`aflj`, `izj`, `axtj`, …) from the host's in-process core.

## It's not read-only — and your work saves

Load the plugin in radare2 and mutate analysis through ordinary SQL writes.
Use radare2's `-w` option when writing binary bytes:

```sql
UPDATE funcs   SET name = 'parse_header' WHERE addr = 0x401000;   -- rename
UPDATE funcs   SET prototype = 'int parse_header(char *buf)' WHERE name = 'parse_header';
INSERT INTO comments(addr, text) VALUES (0x401044, 'bounds check missing');
UPDATE locals  SET name = 'len', type = 'int' WHERE func_addr = 0x401000 AND name = 'var_8h';
INSERT INTO types(name, kind) VALUES ('Header', 'struct');
INSERT INTO bookmarks(addr, name) VALUES (0x401000, 'entry-of-interest');
```

Writable surfaces: **funcs** (rename, prototype), **comments**, **flags**,
**locals** (rename + retype), **bookmarks**, **types** (create struct/union/
enum), **patches** (byte edits), **io_maps**, **bytes**.

**Persist it.** Save analysis with `Ps NAME` in radare2 and reopen it with
`r2 -p NAME` without a separate binary or reanalysis. The plugin uses radare2's native project format; it does not
automatically save on exit.

Project save/open and full type declarations use native radare2 commands:
`Ps NAME`, `P NAME`, and `"td struct Header { int magic; };"`. The former SQL
functions `r2xsql_project_save`, `r2xsql_project_open`, and
`r2xsql_type_define` are removed. SQL can still list/delete projects and
create empty struct/union/enum types through the corresponding tables.

## Output formats

`sql` executes one statement using radare2's table renderer. It honours
`cfg.table.format`, `cfg.table.maxcol` and `scr.utf8`. Put a table query
immediately after `sql,`, before the SQL:

```text
sql,:csv SELECT name,size FROM funcs
sql,:tsv SELECT name,size FROM funcs
sql,?
```

Use SQL `WHERE`, `ORDER BY` and `LIMIT` for filtering. Table JSON (`sql,:json`)
omits NULL and empty-string cells; use `sqlj` for programmatic access.
`sql.tables` / `sql.views` discover the current schema; `sql.?` lists
subcommands. The `sql.` namespace does not carry SQL statements.

## JSON results

Use `sqlj` for programmatic queries and scripts:

```text
"sqlj SELECT NULL AS missing, '' AS empty; SELECT count(*) AS n FROM funcs"
```

It returns libxsql's JSON envelope with per-statement columns, rows, errors,
and timings. SQL NULL is JSON `null`, distinct from the empty string. Quoting
the entire r2 command also preserves statement separators and SQL operators.
Read [saving and reopening](usage.md#saving-and-reopening) for persistence.
The same command works through r2pipe and radare2's HTTP `/cmd/` endpoint.
