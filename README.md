# r2xsql

[![ci status](https://github.com/radareorg/r2xsql/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/radareorg/r2xsql/actions/workflows/build.yml?query=branch%3Amain)

SQL interface for [radare2](https://github.com/radareorg/radare2), powered
by [`libxsql`](https://github.com/0xeb/libxsql).

`r2xsql` is a radare2 core plugin. It exposes the host's live analysis state
as SQL virtual tables; reads and annotations operate on the binary already
open in radare2 or iaito. Most live tables cache rows only for a query.

## Analyze by asking your agent

Install a matching [plugin](#using-the-plugin) and the
[r2xsql skills](https://github.com/radareorg/radare2-skills/tree/main/r2xsql#install)
once, then ask your coding agent naturally:

> Open `target.exe` headlessly with r2xsql and show me the ten largest functions.
>
> Disassemble and decompile this function, then give it a descriptive name.
>
> Save the database beside the executable and keep it open.
>
> Save and shut down. Later, reopen `target.exe.r2` and continue.

The harness discovers the `r2xsql` entry skill and loads connection/domain
instructions as needed. The agent starts radare2, analyzes a fresh binary once,
and queries the live SQL surface using curl. Subsequent prompts use the same
background process. When reopening a saved project it restores analysis rather
than analyzing again. You do not need to write SQL or run a session script.

The saved "database" is a native radare2 project, not a SQLite export. Renames
and comments belong to that project; the original executable stays available.
See [headless sessions](#fully-headless-analysis-with-an-agent) or use the UI
workflow below.

## Tandem mode

Tandem means a human and an agent share the same live radare2 analysis. The
human can use r2's command-line prompt, its visual/panels text interface, or
[iaito](https://github.com/radareorg/iaito). The agent connects to that host's
HTTP server and queries or annotates the binary already open there. You do not
need to write SQL, and a GUI is not required.

1. Install the r2xsql plugin against the radare2 engine you will use (see
   [Using the plugin](#using-the-plugin)). Install the
   [r2xsql agent skills](https://github.com/radareorg/radare2-skills/tree/main/r2xsql)
   in your coding agent so it knows how to connect and query.
2. Open a fresh executable with `r2 -A ./target.exe`, or open it in iaito and
   let analysis finish. For saved analysis restore the project with `P` instead
   of running `aaa` / `-A`. Use the r2 prompt, or iaito's **View > Console**.
   An installed plugin normally loads automatically. If yours is not installed
   for automatic loading, load its file in the console:

   ```text
   L ./core_r2xsql.dll
   ```

   Replace `./core_r2xsql.dll` with your plugin's actual location; use `.so` on
   Linux or `.dylib` on macOS. It must match the host's radare2 ABI. `Lcj` lists
   loaded core plugins; check that `r2xsql` is present.
3. In that same console, start radare2's background HTTP server:

   ```text
   e http.bind=127.0.0.1
   e http.sandbox=false
   =h& 9090
   ```

   Choose a free port; 9090 is an example. Wait for
   `open http://127.0.0.1:9090/`. `e` sets configuration: `http.bind` selects
   the listening interface, and disabling `http.sandbox` permits the command
   workflow including project saves. `=h&` serves in the background so the
   prompt or UI stays available; `=h` without `&` serves in the foreground.
   For r2's visual/panels interface, start the server at the prompt first and
   then enter the text interface.
4. Tell your agent:

   > Use r2xsql at http://127.0.0.1:9090 on the binary already open in my r2 session.
   > Find network-related functions and explain the evidence.

The agent verifies the host/plugin and issues SQL through **POST `/cmd/`**.
Your follow-up questions use the same analysis session; the agent should not
open another host or reanalyze the binary on each question. Take turns with the
agent when running analysis-changing commands. Save annotations as a radare2
project with `Ps` (see [saving](#session-lifetime-saving-and-reopening)); there
is no automatic save on exit. Ending the agent's connection does not imply
closing the human's interactive r2 session.

This README covers the user's setup and endpoint handoff. The skills loaded
by the agent harness cover schema discovery, SQL construction, response/error
handling, evidence and persistence. Server startup uses radare2 commands;
r2xsql does not introduce another server or `/query` endpoint.

### Several tandem sessions from one agent session

Each interactive r2 process or iaito window has its own analysis state and server.
Choose a different port for each, then give the agent a mapping such as
**application = http://127.0.0.1:9090, library = http://127.0.0.1:9091**.
One coding session can query ten such endpoints and compare their results.
Name the intended session in your question; the agent should verify its binary
identity and label results by source. Each SQL request belongs to one endpoint;
cross-session comparisons combine results in the agent/client.

## SQL access

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
sudo apt install radare2               # distro package (may lag behind releases)
brew install radare2                   # macOS
```

Build `core_r2xsql` against the same radare2 installation that will load it:
the in-process plugin depends on radare2's ABI.

## Using the plugin

The recommended way to install the plugin is with r2pm:

```sh
r2pm -U
r2pm -ci r2xsql
```

The installed plugin loads automatically when radare2 starts:

```sh
r2 -A ./target
```

No plugin pathname or `L r2xsql` command is needed after installation. Verify
with `Lcj` and `sql?` at the r2 prompt. Restart an already-open host after
installing the plugin. Automatic loading must be enabled: `-NN` disables it,
whereas `-N` skips startup scripts while retaining plugin discovery.

For manual installation, copy the matching `core_r2xsql` file to the directory
printed by `r2 -NN -H R2_USER_PLUGINS`. Use the same engine that will host it,
including iaito's engine when using the GUI. Do not assume a DLL built for a
different radare2 ABI will load.

At the radare2 prompt:

```text
sql SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10
pdf @ entry0
q
```

For a one-shot query:

```sh
r2 -q -A \
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

For a local build, `make user-install` also installs the plugin for automatic
loading. To load a build without installing it, use `L`, either at the console
or in a radare2 startup command/script:

```sh
r2 -A -c 'L ./core_r2xsql.so' ./target
```

Use the actual `.so`, `.dylib`, or `.dll` path. Inside an existing radare2
session, use `L ./core_r2xsql.so` with your plugin's location.

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
`R2XSQL_BUILD_EXAMPLES=OFF` disables examples. C++ consumers can embed the
library with `open_libr` and the `r2xsql_libr` target. The project also supports
being added as a CMake subdirectory.

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
make user-uninstall  # remove the per-user plugin without building
make uninstall       # remove the system-wide plugin without building
make test            # load it in r2 and run one SQL query
# only `radare2` (not `r2`) on PATH?  ->  make R2=radare2
```

`make install` and `make uninstall` accept `PLUGDIR` and `DESTDIR` for a
custom plugin directory or staged install. User targets use `R2_USER_PLUGINS`;
override it on the make command line when needed.

Or with meson (what radare2 itself uses):

```bash
meson setup build-meson
meson compile -C build-meson
meson install -C build-meson                 # into R2_LIBR_PLUGINS
meson setup build-meson -Dr2_user_plugins=true   # ... or the per-user dir
```

Both build the same plugin: the `sql` command. Both
consume [`libxsql`](https://github.com/0xeb/libxsql): the Makefile uses a
sibling `../libxsql` checkout (else clones it), and meson pulls it as a
subproject. All three builds pin the same libxsql release tag (`v1.0.21`).

Release assets are named `r2xsql-<radare2-version>-<R2PM_TRIPLET>.zip`, for
example `r2xsql-6.2.2-linux-x86-64.zip`. Each contains the plugin in `plugins/`.
With a recent r2pm supporting binary installs, use `r2pm -U` followed by
`r2pm -bi r2xsql`; uninstall with `r2pm -u r2xsql`. Only matching radare2
versions and targets are installed. To install manually, copy the plugin to
the directory printed by `radare2 -NN -H R2_USER_PLUGINS`.

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

### Fully headless analysis with an agent

With the plugin installed, the agent opens a fresh binary and starts a native
radare2 process in the background. The commands it runs are:

```sh
r2 -N -q -c aaa -c 'e scr.html=false' \
  -c 'e http.bind=127.0.0.1' -c 'e http.sandbox=false' \
  -c '=h 9090' ./target.exe
```

The shell example shows r2's arguments; the agent backgrounds the process and
captures stdout/stderr to logs. On Windows it uses `Start-Process -WindowStyle
Hidden` (a complete example is in the skills' session guide); on POSIX it can
redirect output and append `&`. `aaa` runs once before serving. Foreground
`=h` keeps that background process alive, unlike a one-shot `-q -c` query.

Use the target's actual location and a free port. The agent waits for the
listener, verifies `?V`, `Lcj` and binary identity over curl, then queries
POST `/cmd/`. It keeps the PID, endpoint and target mapping across questions.
Saving alone leaves the host running until you request shutdown.

For an uninstalled local build, replace `-N` with `-NN` and insert
`-c 'L ./core_r2xsql.so'` before analysis. Supply the real plugin file (`.dll`
on Windows); this explicit-path fallback is separate from normal installation.

### Session lifetime, saving and reopening

Headless mode starts a persistent operating-system process. The agent launches
it in the background, redirects its output to logs and keeps its HTTP endpoint.
On Windows this can be a process without a console window. The radare2 `=h`
command stays in the HTTP server loop inside that process. Sending a query
does not launch or exit radare2; later requests use the same loaded binary and
analysis until the process stops.

Analysis is initially in memory. Ask the agent to **save the database beside
the executable**. It sends native `Ps` with the absolute `<binary-path>.r2`
filename to POST `/cmd/`, for example:

```sh
curl --data-binary 'Ps /absolute/path/target.exe.r2' http://127.0.0.1:9090/cmd/
```

Absolute paths select an adjacent project file; a bare name such as `Ps triage`
selects a named project under `dir.projects`. A relative `target.exe.r2` is not
an interchangeable project name. Use an absolute path for the sidecar workflow.
The agent verifies the saved file, checks relevant annotations, and reports
the location. A blank HTTP response is insufficient proof: a refused `Ps` can
return HTTP 200 with its error only in the host's stderr. `Pl` lists named
projects under `dir.projects`; it need not list an adjacent project elsewhere.

The project preserves analysis and annotations; SQL results and pseudocode are
recomputed from restored state. Keep the executable and any companion `.r2.d`
directory created by r2. Saving analysis does not patch the executable.
There is currently no SQL `save_database()`; native `Ps` travels over the same
curl connection as SQL. You can choose a different save location explicitly.

If you ask the agent to **save and shut down**, it saves first, verifies the
checkpoint, then stops foreground serving with GET `/cmd/=h--`. With the
`-q` launch above, radare2 exits after the server loop returns. There is no
automatic save merely because the process exits.

To reopen the saved state and serve it again:

```sh
r2 -N -q -c 'P /absolute/path/target.exe.r2' \
  -c 'e scr.html=false' -c 'e http.bind=127.0.0.1' \
  -c 'e http.sandbox=false' -c '=h 9090' ./target.exe
```

Substitute the actual saved project and original executable. HTTP settings
are applied after `P`, because restoring a project also restores configuration.
For a named project use `P triage` with its original `dir.projects`. There
is **no `aaa` or `-A`** in the reopen command: it restores the saved analysis.
The agent verifies the restored binary and function inventory and records the
new endpoint if the chosen port changed. You can simply ask it to **reopen
`target.exe.r2` and continue**. Do not start a second host if the matching
session is still running; attach to that session instead.

#### Verify restored annotations

Native radare2 6.2.2 project replay can lose some function names while keeping
the function count unchanged. In a reproduced DLL roundtrip, the saved project
contained the requested names, but reopening reported `Cannot add dupped
function` and left those functions named `fcn.*`. This native restore defect
is not fixed by these workflow instructions.

Compare saved annotations by address after reopening, including requested
renames; a count alone is insufficient. If native restore reports duplicate
function errors, check the complete function address/name inventory. Preserve
the saved project and logs when verification fails rather than overwriting
the checkpoint with the incorrectly restored state.

### HTTP client integration

For the user-facing interactive workflow, see [tandem mode](#tandem-mode)
above. The examples here describe headless serving and client integration.

Send a quoted SQL command through r2's `POST /cmd/` endpoint:

```sh
curl --data-binary '"sqlj SELECT name, size FROM funcs WHERE size > 100 LIMIT 5"' \
  http://127.0.0.1:9090/cmd/
```

Use `curl.exe` in Windows PowerShell to select the executable rather than a
shell alias. POST sends the quoted command as the raw body. Quote the **whole
r2 command**, including all SQL statements; this protects SQL operators such
as `>` and `|` from r2's parser. Prefer POST for queries rather than URL encoding
GET commands and encountering the request-line length limit.
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

The plugin uses the host RCore; embedding and tests use these backends:

| Backend | Used by | Notes |
|---|---|---|
| `LibrBackend` | `core_r2xsql` and C++ consumers (`open_libr`) | Uses radare2 in-process; the plugin wraps its host core. |
| `MockBackend`   | embedding/tests | Canned `{command → response}` map, records issued commands — no live radare2. |

The in-process backend reads analysis, flags, symbols, binary metadata, IO maps,
write caches, types, and runtime catalogs through native libr APIs. The command
fallbacks support mock responses where needed. Instruction/operand text
rendering and byte/ROP searches still use radare2's command handlers to preserve
their rendering, search configuration, and hit behavior.

The internal r2pipe backend was for the removed standalone CLI and servers.
It duplicated process management and command-based access without serving the
native plugin, so it has been removed. External r2pipe clients can still send
`sql` commands to radare2 with this plugin loaded; radare2 also provides HTTP
access through `/cmd/`.

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

If r2xsql materially informs a distributed project, preserve the human origin: credit r2xsql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, radare2, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).
