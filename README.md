# r2xsql

SQL interface for [radare2](https://github.com/radareorg/radare2), powered
by [`libxsql`](https://github.com/0xeb/libxsql).

```sql
SELECT name, size FROM funcs WHERE name LIKE 'main%';
SELECT text     FROM strings WHERE text LIKE '%password%';
UPDATE comments SET text = 'reviewed' WHERE addr = 0x1234;
```

`r2xsql` exposes radare2's analysis state as live SQL virtual tables: every
query re-issues the JSON form of the relevant r2 command (`aflj`, `izj`,
`axtj`, …) against an in-process core (`r_core_cmd_str`) or a spawned
`radare2 -q0` pipe — no flat dump, no stale snapshot.

## It's not read-only — and your work saves

Open with `-w` and mutate analysis through ordinary SQL writes:

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

**Persist it.** `--project NAME` together with `-w` saves everything — renames,
comments, types, flags — to an **r2 project** on exit (radare2's own `Ps`), and
`-s <project>` reopens it fully restored. Because it *is* radare2's native
project format, a project you build in r2xsql opens in plain `radare2` and
vice-versa; the analysis is not trapped inside r2xsql.

## Requirements

**You need radare2.** r2xsql does not bundle it and does not install it.

```bash
# any one of these
r2pm -ci radare2                       # radare2's own package manager
git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
sudo apt install radare2               # distro package (may lag; see below)
brew install radare2                   # macOS
```

The default `r2xsql` binary finds radare2 by name on your `PATH` — literally
`radare2` (`radare2.exe` on Windows); it never looks for `r2`, never searches
next to itself, and reads no environment variable. If radare2 is not on `PATH`,
point at it explicitly:

```bash
r2xsql --r2-exe /opt/radare2/bin/radare2 -s ./target -q "SELECT count(*) FROM funcs"
```

Version: r2xsql reads radare2's JSON output, so it is **not** tied to a specific
radare2 ABI — but it is sensitive to that JSON's field naming, which changes
across major r2 series. Prefer a recent radare2 (6.x). A too-old radare2 does not
error; affected columns simply come back empty. Check what you actually connected
to with `SELECT value FROM binary WHERE key='radare2_version'`.

## Which build do I want?

**Almost certainly just `r2xsql`.** It is the default, it is the only one built
unless you ask for more, and it does everything the SQL surface offers. If you
are reading this and unsure — this is your answer. Stop here.

`r2xsql-full` is an **optional second binary** you opt into with
`-DR2XSQL_BUILD_FULL=ON`. Same SQL, same CLI — the *only* reasons
to build it are:

1. you want to run SQL **inside a live radare2 session** (it ships the in-r2
   `core_r2xsql` plugin — `r2xsql` alone cannot do this), or
2. you keep **one session open and fire thousands of queries** at it and want to
   shave per-query overhead (see "Is `r2xsql` slower?" below — for normal use the
   answer is no).

|  | **`r2xsql`** — the default | **`r2xsql-full`** — optional |
|---|---|---|
| built by | every build, always | only with `-DR2XSQL_BUILD_FULL=ON` |
| how it talks to radare2 | **launches and manages its own** `radare2` subprocess | radare2's libraries linked **in-process** |
| needs radare2 at runtime | **yes** — on `PATH` (or `--r2-exe`) | no — libraries are baked in |
| radare2 version | **portable** across releases | **locked** to the exact build it compiled against |
| in-r2 `sql` plugin | — | yes |
| wrong-answers-if-misdeployed | cannot happen | possible (data-dir cliff, see below) |

Both are built from one configure when `-DR2XSQL_BUILD_FULL=ON` is set, and the
test suite pins them to each other field-for-field — **the answers are always
identical**, so this is never a correctness choice.

### Using `r2xsql-full` with the skills / tooling

The agent skills, scripts, and the `connect` skill all invoke the **command
`r2xsql`** — none of them know about `r2xsql-full`. And a full build still
produces **both** binaries (`r2xsql` = pipe, `r2xsql-full` = libr) as two
separate files, so that tooling keeps using pipe by default.

To make the tooling use the full binary, put it on `PATH` **under the name
`r2xsql`** — the CLI is identical, so nothing else changes:

```bash
ln -sf "$(command -v r2xsql-full)" ~/.local/bin/r2xsql   # Linux/macOS, ahead on PATH
```

(On Windows, copy `r2xsql-full.exe` to `r2xsql.exe` in a dir earlier on `PATH`.)
This is the whole mechanism — there is no runtime flag that switches a `r2xsql`
invocation to the libr engine; the choice is which binary the name resolves to.

### How `r2xsql` connects to radare2

`r2xsql` **starts and owns its own** `radare2` process. You point it at a file
with `-s <file>` and it runs `radare2 -q0` under the hood for the life of the
session, then shuts it down. You do **not** — and cannot — hand it a `radare2`
you launched yourself; there is no "attach to a running instance" mode.
`--r2-exe <path>` only chooses *which* `radare2` binary it launches (use it when
radare2 is installed but not on `PATH`). If you want SQL against a radare2
session *you* are driving, that is the `core_r2xsql` plugin in `r2xsql-full`,
which reuses that session's core — the opposite direction.

### Is `r2xsql` slower?

For normal use, **no** — measured end-to-end, a one-shot query is
indistinguishable from `r2xsql-full` (both are dominated by radare2's analysis
pass, which is identical). `r2xsql-full`'s speed advantage is *per query on an
already-open session* and only adds up when a long-lived session or REPL answers
many queries in a row. A person or an agent asking questions will not feel it.

### The two catches with `r2xsql-full`

- **ABI-locked.** It is welded to the exact radare2 build it compiled against —
  the `core_r2xsql` plugin especially. Do not pair it with a different radare2.
- **Silent-if-misdeployed.** `libr` finds radare2's data directory relative to
  the *loading executable's own location*. Deployed away from that layout it
  does not error — it degrades quietly (wrong calling convention, a `types`
  table collapsed to a handful of built-ins). `r2xsql-full` detects and corrects
  this at open time, but it is a class of failure `r2xsql` simply cannot have.

## Build

Linux / macOS:

```bash
# Pipe-only r2xsql (default) — portable, needs radare2 on PATH at runtime:
cmake -S . -B build/r2xsql -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/r2xsql

# Also build the full flavor (r2xsql-full + core_r2xsql plugin):
cmake -S . -B build/r2xsql-full -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DR2XSQL_BUILD_FULL=ON -DRadare2_ROOT=/path/to/radare2/prefix
cmake --build build/r2xsql-full
```

Windows (MSVC):

```powershell
# Pipe-only r2xsql (default):
cmake -S . -B build/r2xsql -G "Visual Studio 17 2022" -A x64
cmake --build build/r2xsql --config Release

# Also build the full flavor (line continuation is a backtick in PowerShell):
cmake -S . -B build/r2xsql-full -G "Visual Studio 17 2022" -A x64 `
  -DR2XSQL_BUILD_FULL=ON -DRadare2_ROOT=C:\path\to\radare2\prefix
cmake --build build/r2xsql-full --config Release
```

`Radare2_ROOT` is a radare2 **install prefix** — the directory containing
`include/libr/` and `lib/`, i.e. what `--prefix` pointed at when radare2 was
built/installed (`r2pm`, `sys/install.sh`, or a meson `--prefix`). The pipe-only
build needs none of this; it only needs the `radare2` binary at runtime.

A single configure with `-DR2XSQL_BUILD_FULL=ON` produces **both** `r2xsql` and
`r2xsql-full` (+ the plugin). This is the standalone build; it also builds cleanly
when vendored as a subdirectory of a larger project — the `CMakeLists.txt` here
detects the situation and adapts.

### Building the in-r2 plugin the radare2 way (Makefile / meson)

CMake above is the full build (both CLI flavors and Windows support). If you
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

Both build the same plugin: the `sql` command. All builds use
[`r2mcp`](https://github.com/radareorg/radare2-mcp) for MCP access to the
plugin's `sql` command; r2xsql no longer embeds an MCP server. Both
consume [`libxsql`](https://github.com/0xeb/libxsql): the Makefile uses a
sibling `../libxsql` checkout (else clones it), and meson pulls it as a
subproject. A current libxsql is required (same as CMake's `FetchContent`).

## MCP access through r2mcp

MCP is provided by [r2mcp](https://github.com/radareorg/radare2-mcp), using
`core_r2xsql` in its radare2 session. Build/install the plugin as above against
the **same radare2 installation** used to build r2mcp. The standalone pipe-only
`r2xsql` executable is not an MCP server.

Use an r2mcp build containing
[the SQL/startup-command integration](https://github.com/radareorg/radare2-mcp/pull/78).
For an installed plugin, configure your MCP client with:

```json
{
  "mcpServers": {
    "radare2": {
      "command": "r2pm",
      "args": ["-r", "r2mcp", "-r"]
    }
  }
}
```

The first `-r` asks r2pm to run its installed binary; the final `-r` enables
r2mcp's command and SQL tools. You can also use `"command": "r2mcp"` with
`"args": ["-r"]` when the executable is on `PATH`. The `sql` tool allows writes
to analysis data and is excluded from r2mcp's read-only mode.

For an uninstalled plugin, add `"-c", "L /absolute/path/core_r2xsql.so"` to
r2mcp's arguments (use the actual `.so`, `.dylib`, or `.dll` filename). Do not
use `-n` when relying on automatic loading of an installed plugin.

After connecting, call the following tools in order:

| Tool | Arguments |
|---|---|
| `open_file` | `{"file_path":"/absolute/path/target"}` |
| `analyze` | `{"level":0}` |
| `sql` | `{"query":"SELECT name, size FROM funcs WHERE size > 100 ORDER BY size DESC LIMIT 10"}` |

`sql` accepts one statement and returns the plugin's text table in MCP
`content[].text`; SQL errors appear as `ERROR: ...` in that text. Use this
tool for queries: `run_command` applies r2 command filtering, which can
truncate SQL operators such as `>` or `|`. Plugin commands such as `sql.?`
remain available through `run_command`.

For HTTP MCP transport, start `r2mcp -r -H 8765` with the plugin installed.
The old embedded HTTP REST server (`--http` / `sql.http`), the `--mcp` option,
the `sql.mcp` subcommand, the `r2xsql_query` tool, and the `R2XSQL_WITH_MCP`
build option have all been removed — remote access now goes through r2mcp.

Run the integration smoke test against your built executable and plugin:

```bash
python3 tests/mcp_smoke.py /path/to/r2mcp /path/to/core_r2xsql.so
```

It compiles a temporary fixture, loads the plugin through r2mcp, and checks
SQL reads, comment writes/deletes, literal text, operators, and command help.
It needs Python 3 and a C compiler, with no Python MCP package required.

## Backends (internal detail)

Each binary above is one of these backends wired up — you rarely name them
directly:

| Backend | Which binary | Notes |
|---|---|---|
| `R2PipeBackend` | **`r2xsql`** (and forceable in `r2xsql-full` with `--r2pipe`) | Spawns and manages `radare2 -q0` over stdio. |
| `LibrBackend`   | `r2xsql-full` | radare2 linked in-process; used automatically when the binary has libr support. |
| `MockBackend`   | embedding/tests | Canned `{command → response}` map, records issued commands — no live radare2. |
| `MockBackend`   | In-memory mock: canned command→response map, records issued commands — for embedding/offline use without a live radare2. |

## Skills (Claude Code / Codex)

Agent skills teach Claude Code and Codex to drive `r2xsql`: query and annotate
radare2 analysis through SQL, pick the right backend, and use MCP through
r2mcp. They ship in the radare2 community skills catalog,
**[`radare2-skills`](https://github.com/radareorg/radare2-skills)**, as the
`r2xsql/` category alongside `dev/`, `r2mcp/` and `radius2/`. Install a category
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
