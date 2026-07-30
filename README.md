# r2sql

SQL interface for [radare2](https://github.com/radareorg/radare2), powered
by [`libxsql`](https://github.com/0xeb/libxsql).

```sql
SELECT name, size FROM funcs WHERE name LIKE 'main%';
SELECT text     FROM strings WHERE text LIKE '%password%';
UPDATE comments SET text = 'reviewed' WHERE addr = 0x1234;
```

`r2sql` exposes radare2's analysis state as live SQL virtual tables: every
query re-issues the JSON form of the relevant r2 command (`aflj`, `izj`,
`axtj`, …) against an in-process core (`r_core_cmd_str`) or a spawned
`radare2 -q0` pipe — no flat dump, no stale snapshot.

## Two flavors

r2sql builds in two flavors from one source tree:

| Flavor | Binary | What it is | Needs |
|---|---|---|---|
| **pipe-only** (default) | `r2sql` | portable single binary; **spawns and manages `radare2`** over a pipe (`--r2pipe`). No `r_*.dll` imports. | `radare2` on PATH at runtime |
| **full** (libr) | `r2sql-full` (+ `core_r2sql` plugin) | embeds radare2 in-process (`r_core_cmd_str`), fastest, and adds the in-r2 `sql` plugin | a built radare2 (`-DRadare2_ROOT=<prefix>`) |

The pipe-only `r2sql` is **always built**. The full `r2sql-full` + plugin are
built additionally when you pass `-DR2SQL_BUILD_FULL=ON`. Both expose the exact
same SQL surface, CLI, and HTTP/MCP servers. MCP support is gated behind
`R2SQL_WITH_MCP=ON` (fastmcpp dependency).

## Build

```powershell
# Pipe-only r2sql (default) — portable, needs radare2 on PATH:
cmake -S . -B build/r2sql -G "Visual Studio 17 2022" -A x64
cmake --build build/r2sql --config Release

# Also build the full flavor (r2sql-full + core_r2sql plugin):
cmake -S . -B build/r2sql -G "Visual Studio 17 2022" -A x64 \
  -DR2SQL_BUILD_FULL=ON -DRadare2_ROOT=<radare2 install prefix>
cmake --build build/r2sql --config Release
```

A single configure with `-DR2SQL_BUILD_FULL=ON` produces **both** `r2sql` and
`r2sql-full` (+ the plugin). This is the standalone build; it also builds cleanly
when vendored as a subdirectory of a larger project — the `CMakeLists.txt` here
detects the situation and adapts.

## Backends

| Backend | When to use |
|---|---|
| `LibrBackend`   | In-process, fastest. Default when r2sql was built with `R2SQL_HAVE_LIBR=1`. |
| `R2PipeBackend` | Spawns `radare2 -q0` and communicates over stdio. Default fallback; force with `--r2pipe`. |
| `MockBackend`   | In-memory mock: canned command→response map, records issued commands — for embedding/offline use without a live radare2. |

## Skills (Claude Code / Codex)

`r2sql` ships an agent-skills package —
[`r2sql-skills`](https://github.com/0xeb/r2sql-skills) — that teaches Claude Code
and Codex to drive it: query and annotate radare2 analysis through SQL, pick the
right backend, and reach the HTTP/MCP servers. Install it from the plugin
marketplace in that repo to point an agent at `r2sql`.

## Similar projects

`r2sql` is part of a family of SQL interfaces over reverse-engineering and
program-analysis backends, all sharing the
[`libxsql`](https://github.com/0xeb/libxsql) virtual-table engine:

| Project | Backend |
|---|---|
| [ghidrasql](https://github.com/0xeb/ghidrasql) | Ghidra |
| [bnsql](https://github.com/0xeb/bnsql) | Binary Ninja |
| [pdbsql](https://github.com/0xeb/pdbsql) | PDB symbol files |
| [clangsql](https://github.com/0xeb/clangsql) | Clang / C++ ASTs |
| [dwarfsql](https://github.com/0xeb/dwarfsql) | DWARF debug info |

**Related:** agent skills for driving `r2sql` →
[`r2sql-skills`](https://github.com/0xeb/r2sql-skills) (Claude Code / Codex).

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified r2sql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use r2sql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by r2sql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [0xeb/r2sql/issues](https://github.com/0xeb/r2sql/issues).

If r2sql materially informs a distributed project, preserve the human origin: credit r2sql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, radare2 (libr / r2pipe), and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).

Releases up to v0.0.1 remain under the MPL-2.0 they shipped with.
