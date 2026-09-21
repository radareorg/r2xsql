# r2xsql

[![ci status](https://github.com/radareorg/r2xsql/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/radareorg/r2xsql/actions/workflows/build.yml?query=branch%3Amain)

SQL interface for [radare2](https://github.com/radareorg/radare2), powered
by [`libxsql`](https://github.com/0xeb/libxsql).

```sql
SELECT name, size FROM funcs WHERE name LIKE 'main%';
SELECT content  FROM strings WHERE content LIKE '%password%';
UPDATE comments SET text = 'reviewed' WHERE addr = 0x1234;
```

`r2xsql` exposes radare2's analysis state as live SQL virtual tables: every
query reads native analysis data or the JSON form of the relevant r2 command
(`aflj`, `izj`, `axtj`, …) from an in-process core or a spawned `radare2 -q0`
pipe. Most live tables cache rows only for the duration of a query.

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
`P NAME`. The plugin uses radare2's native project format; it does not
automatically save on exit.

Project save/open and full type declarations use native radare2 commands:
`Ps NAME`, `P NAME`, and `"td struct Header { int magic; };"`. The former SQL
functions `r2xsql_project_save`, `r2xsql_project_open`, and
`r2xsql_type_define` are removed. SQL can still list/delete projects and
create empty struct/union/enum types through the corresponding tables.

## Requirements

**You need radare2.** r2xsql does not bundle it and does not install it.

```bash
# any one of these
r2pm -ci radare2                       # radare2's own package manager
git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
sudo apt install radare2               # distro package (may lag; see below)
brew install radare2                   # macOS
```

Build `core_r2xsql` against the same radare2 installation that will load it:
the in-process plugin depends on radare2's ABI.

## Using the plugin

Load the built module and analyze a target:

```sh
r2 -i /absolute/path/core_r2xsql.so -A ./target
```

Use the actual `.so`, `.dylib`, or `.dll` path; omit `-i` once the plugin is
installed in radare2's plugin directory. At the radare2 prompt:

```text
sql SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10
pdf @ entry0
q
```

For a one-shot query:

```sh
r2 -q -A -i /absolute/path/core_r2xsql.so \
  -c '"sql SELECT name, size FROM funcs WHERE size > 100 LIMIT 5"' ./target
```

Each `sql` command executes one statement. Quote the whole r2 command when SQL
contains r2 operators such as `>` or `|`. Use repeated `-c` options, a radare2
command script, or a persistent session for multiple statements.

`sql` uses radare2's table renderer and honours `cfg.table.format` and
`scr.utf8`. Add a table query immediately after the command, before the SQL:

```text
sql,:csv SELECT name, size FROM funcs
sql,size/gt/100,:quiet SELECT name, size FROM funcs
sql,?
```

Use `sql,:tsv` for tab-separated output. Native tables have no SQL NULL type;
in particular, `sql,:json` omits NULL and empty-string cells.

## Build

Linux / macOS:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DRadare2_ROOT=/path/to/radare2/prefix
cmake --build build
```

Windows (MSVC):

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DRadare2_ROOT=C:\path\to\radare2\prefix
cmake --build build --config Release
```

`Radare2_ROOT` is a radare2 **install prefix** containing `include/libr/`
and `lib/`. CMake requires radare2 and builds the libr backend and plugin by
default; a missing radare2 installation is a configure error. The plugin is in
`build/bin/` (`build/bin/Release/` for the MSVC Release configuration).

`R2XSQL_BUILD_PLUGIN=OFF` disables the plugin target and
`R2XSQL_BUILD_EXAMPLES=OFF` disables examples. The backend-neutral static
library and r2pipe backend remain available to C++ consumers. The project
also supports being added as a CMake subdirectory.

### Building the in-r2 plugin the radare2 way (Makefile / meson)

CMake above builds the library, examples, and plugin, including on Windows. If you
only want the in-r2 plugin — the `core_r2xsql` module that adds the `sql`
command inside radare2 — there is also a radare2-native build that needs no
CMake, matching how radare2 plugins are usually built (plugin paths from
`r2 -H`, radare2 from `pkg-config r_core`):

```bash
make                 # -> build-make/core_r2xsql.$(r2 -H R2_LIBEXT)
make user-install    # install into the per-user plugin dir (no root)
make install         # install system-wide (R2_LIBR_PLUGINS)
make test            # load it in r2 and run one SQL query
# only `radare2` (not `r2`) on PATH?  ->  make R2=radare2
```

or with meson (what radare2 itself uses):

```bash
meson setup build-meson
meson compile -C build-meson
meson install -C build-meson                 # into R2_LIBR_PLUGINS
meson setup build-meson -Dr2_user_plugins=true   # ... or the per-user dir
```

Both build the same plugin: the `sql` command. Both
consume [`libxsql`](https://github.com/0xeb/libxsql): the Makefile uses a
sibling `../libxsql` checkout (else clones it), and meson pulls it as a
subproject. A current libxsql is required (same as CMake's `FetchContent`).

### JSON results

Use `sqlj` for programmatic queries and scripts:

```text
"sqlj SELECT NULL AS missing, '' AS empty; SELECT count(*) AS n FROM funcs"
```

It returns libxsql's JSON envelope with per-statement columns, rows, errors,
and timings. SQL NULL is JSON `null`, distinct from the empty string. Quoting
the entire r2 command also preserves statement separators and SQL operators.
The same command works through r2pipe and radare2's HTTP `/cmd/` endpoint.

## HTTP access through radare2

Load the plugin in a persistent radare2 session and start r2's web server:

```sh
r2 -N -q -i /absolute/path/core_r2xsql.so \
  -e http.bind=127.0.0.1 -e http.port=9090 -c aa -c '=h' ./target
```

Use the plugin's actual `.so`, `.dylib`, or `.dll` path. If it is installed,
omit `-i`. Send a quoted SQL command through r2's `POST /cmd/` endpoint:

```sh
curl --data-binary '"sql SELECT name, size FROM funcs WHERE size > 100 LIMIT 5"' \
  http://127.0.0.1:9090/cmd/
```

`GET /cmd/<encoded-command>` also works for short queries:

```python
from urllib.parse import quote
from urllib.request import urlopen

sql = "SELECT name, size FROM funcs WHERE size > 100 ORDER BY size DESC LIMIT 5"
command = '"sql ' + sql.replace('"', '\\"') + '"'
with urlopen("http://127.0.0.1:9090/cmd/" + quote(command, safe="")) as response:
    print(response.read().decode(), end="")
```

Quote the **whole r2 command**, escape any SQL double quotes, then URL-encode
it for GET; POST sends the quoted command as the raw body. URL encoding alone
does not protect SQL operators such as `>` and `|` from r2's command parser.
Prefer POST for longer SQL to avoid r2's request-line length limit.
`sql` executes one statement; `sqlj` executes a script and returns a JSON
envelope. The session persists between requests, including analysis and
comment changes.

Responses are native tables for `sql`, with no added row-count footer, or JSON
for `sqlj`. SQL errors can arrive with HTTP status 200: check `ERROR: ...` in
table output or `success` and per-statement errors in the JSON envelope. The old
`sql.http*` and `/query` interface is removed;
configure the native server with r2's `http.*` settings instead.

## Tests

Run the regression suite with radare2, `r2r`, a C compiler and Python 3 on
`PATH` (Python's standard library is used only for the HTTP transport test):

```sh
make test
```

This builds the plugin and runs the r2r database in `tests/db`. Each test loads
the exact build explicitly, ignoring installed user plugins, and checks its
output; SQL exceptions fail the suite even when radare2 exits successfully.
The fixture is compiled locally, with no downloaded test binaries or pytest.

To test an existing CMake/Meson build, or select matching radare2 tools:

```sh
make -C tests R2XSQL_PLUGIN=/absolute/path/core_r2xsql.so R2=/path/to/r2 R2R=/path/to/r2r
# Only command tests (no Python needed):
make -C tests TESTS=db/cmd
```

`R2R_ARGS` accepts r2r options (default `-L`); for example, `R2R_ARGS=-i` enables
interactive failure review. One small standard-library helper retains real
HTTP GET/POST coverage, including server startup and shutdown; r2r checks its
result alongside the command tests.

The Make build tracks header dependencies. This prevents stale adapters after
C++ interface changes, which could previously cause `std::bad_alloc` during
`make test`. After updating this Makefile, existing objects are rebuilt once
to establish dependency files. For older checkouts, `make clean && make test`
clears those stale objects.

## Backends (internal detail)

The library retains these backends for embedding and testing:

| Backend | Used by | Notes |
|---|---|---|
| `R2PipeBackend` | C++ consumers (`open_r2pipe`) | Spawns and manages `radare2 -q0` over stdio. |
| `LibrBackend` | `core_r2xsql` and C++ consumers (`open_libr`) | Uses radare2 in-process; the plugin wraps its host core. |
| `MockBackend`   | embedding/tests | Canned `{command → response}` map, records issued commands — no live radare2. |

## Skills (Claude Code / Codex)

Agent skills teach Claude Code and Codex to drive `r2xsql`: query and annotate
radare2 analysis through SQL, pick the right backend. They ship in the radare2 community skills catalog,
**[`radare2-skills`](https://github.com/radareorg/radare2-skills)**, as the
`r2xsql/` category alongside `dev/` and `radius2/`. Install a category
with its `make install` (or `python install.py install` for `r2xsql/`, which copies
rather than symlinks so it needs no elevated rights on Windows).

Start with the `connect` skill; its `references/schema-catalog.md` is the
canonical reference for the SQL surface.

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified r2xsql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use r2xsql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by r2xsql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [radareorg/r2xsql/issues](https://github.com/radareorg/r2xsql/issues).

If r2xsql materially informs a distributed project, preserve the human origin: credit r2xsql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, radare2 (libr / r2pipe), and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).
