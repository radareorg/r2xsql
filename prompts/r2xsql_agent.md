# r2xsql Agent Guide

You are working with **r2xsql**, a live SQL interface over a radare2 analysis
session. Every table is a thin view onto radare2: a query runs the relevant
radare2 command, parses its JSON, and returns rows. Prefer SQL for structured
inspection; drop to raw radare2 only when the table surface cannot express the
question.

This guide is the front door. For exhaustive per-topic detail (full column
tables, recipes, failure/recovery) the packaged skills are canonical:
`connect`, `data`, `disassembly`, `xrefs`, `functions`, `grep`, `decompiler`,
`annotations`, `analysis`, `re-source`, `r2js`.

---

## What is radare2 and Why SQL?

radare2 is a reverse-engineering framework: it loads a binary, analyzes it into
functions / basic blocks / cross-references, finds strings and imports, and can
decompile (with a plugin). Its native interface is a terse command language
(`aflj`, `izj`, `axtj`, …) that emits JSON.

r2xsql turns that surface into SQL tables. Instead of memorizing radare2 command
syntax and hand-parsing JSON, you write:

```sql
SELECT name, size, cc FROM funcs ORDER BY cc DESC LIMIT 10;
```

You get JOINs, aggregation, CTEs, window functions, and `WHERE` filters across
the whole binary — composable in ways the raw command line cannot match.

---

## Query Model (live, per-query cache)

**Tables are live.** Each query re-issues the underlying radare2 command(s) and
builds its result fresh. There is **no persistent or cross-query snapshot** — a
cache exists only for the duration of a single query. Consequences:

- If analysis state changes (you rename a function, run more analysis, open a
  project), the next query reflects it immediately. No "refresh" needed.
- Repeated identical queries each pay the radare2 round-trip again. For
  interactive drilling, **keep one session alive** (the `-i` REPL, or the
  in-r2 plugin) rather than re-launching the CLI per query.
- Broad, unfiltered scans of per-function tables are expensive (they enumerate
  every function). **Use pushdown filters** wherever they exist.

**Pushed-down filters** (turn a full scan into a single scoped radare2 command):

| Table          | Filter that pushes down            | Becomes            |
|----------------|------------------------------------|--------------------|
| `blocks`       | `func_addr = X`                    | `afbj @ X`         |
| `cfg_edges`    | `func_addr = X`                    | `afbj @ X`         |
| `switch_tables`| `func_addr = X`                    | `afbj @ X`         |
| `function_frames`| `func_addr = X`                  | `afij @ X`         |
| `dominators`   | `func_addr = X`                    | `afbj @ X`         |
| `post_dominators`| `func_addr = X`                  | `afbj @ X`         |
| `loops`        | `func_addr = X`                    | `afbj @ X`         |
| `instructions` | `func_addr = X`                    | `pdfj @ X`         |
| `instructions` | `start_addr = X AND count = N`     | `pdj N @ X`        |
| `instruction_operands` | `addr = X` / `func_addr = X`   | `aoj @ X`          |
| `bytes`        | `addr = X`                         | `p8 1 @ X`         |
| `pseudocode`   | `func_addr = X`                    | `<decomp> @ X`     |
| `xrefs`        | `to_addr = X`                      | `axtj @ X`         |
| `xrefs`        | `from_addr = X`                    | `axfj @ X`         |
| `grep`         | `pattern = '<glob>'`               | scoped name match  |

Without these, the table walks `aflj` and issues one command per function.
**Always filter `pseudocode` by `func_addr`** — an unfiltered scan decompiles
every function.

---

## Command-Line Interface

### Input and provenance

Open a target with `-s <file>` (a binary, or a saved radare2 project). By
default r2xsql runs radare2's auto-analysis (`aaa`) at startup; pass
`--no-analyze` to skip it (faster open, but `funcs`/`xrefs` will be sparse until
you analyze). Reusing a `--project` skips re-analysis entirely.

Always know **what binary** you are looking at before reasoning about results:

```sql
SELECT key, value FROM binary ORDER BY key;
```

### Invocation modes

```bash
# one-shot query (multiple statements separated by ;)
r2xsql -s ./target.exe -q "SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10"

# run a SQL script file
r2xsql -s ./target.exe -f ./audit.sql

# interactive REPL
r2xsql -s ./target.exe -i


```

### CLI options

| Option              | Meaning                                                          |
|---------------------|-----------------------------------------------------------------|
| `-s <file>`         | Open a binary or a saved radare2 project                         |
| `-q "<sql>"`        | Run one SQL statement (or several, `;`-separated) and exit       |
| `-f <file.sql>`     | Run a SQL script file                                            |
| `-i`                | Interactive REPL                                                 |
| `-w`, `--write`     | Open in **write mode**; persist analysis on exit (via `Ps`)      |
| `--no-analyze`      | Skip the implicit `aaa` auto-analysis at startup                 |
| `--project NAME`    | radare2 project name; reuses cached analysis, saves on exit if `-w` |
| `--r2pipe`          | Force the r2pipe backend (spawn `radare2`) even in the full build |
| `--r2-exe PATH`     | Path to the `radare2` executable for r2pipe (default: search PATH) |
| `--version`         | Print version and exit                                           |
| `-h`, `--help`      | Print help and exit                                              |

### Two flavors, four backends

r2xsql ships as **two executables built from one codebase**:

| Binary       | Backend     | Notes                                                       |
|--------------|-------------|------------------------------------------------------------|
| `r2xsql`      | r2pipe      | **Pipe-only, always built.** Portable single binary; spawns `radare2` over a pipe. Needs `radare2` on `PATH`. Deploy anywhere. |
| `r2xsql-full` | libr        | **In-process** (links radare2's libraries), no spawn. Faster *per query on a long-lived session*, NOT end-to-end (analysis dominates equally). **ABI-locked to the exact radare2 build it was compiled against** — never pair it with a different radare2. It detects and corrects the data-dir layout at open time, so it no longer has to live in radare2's `bin/`. |

Backend selection at a glance:

| Backend       | When to use                                                       |
|---------------|------------------------------------------------------------------|
| **r2pipe**    | `r2xsql` (or `--r2pipe`). Portable; spawns `radare2 -q0`. Always has the full data dir, since the spawned radare2 resolves its own `share/`. |
| **libr**      | `r2xsql-full`. In-process; faster per-query on a long-lived session, not end-to-end. ABI-locked to one radare2 build; the data-dir layout is auto-corrected at open. |
| **in-r2 plugin** | Already inside radare2: `L core_r2xsql.dll` then `sql <SQL>`.   |
| **mock**      | Embedding/testing: a canned `{cmd → response}` map, no live radare2. |

Pick `r2xsql` for portability, `r2xsql-full` for throughput on large binaries or
many queries. Functionally the SQL surface is identical.

### REPL commands and raw passthrough

In the REPL, type SQL directly. A line beginning with `.` (after optional
whitespace) is forwarded **raw to radare2** (the leading `.` is stripped);
`.quit` / `.exit` / `exit` leave the REPL.

```text
sql> SELECT name FROM funcs LIMIT 5;
sql> .pdf @ entry0          -- raw radare2: disassemble the entry function
sql> .quit
```

The same `.`-prefix works with `-q` (`r2xsql -s a.bin -q ".ij"`).

### Performance strategy

A one-shot `-q` pays the full open+analyze cost every invocation. For anything
interactive or scripted with many queries, use a long-lived session (e.g. via
the in-r2 plugin or `r2xsql-full`) so the session (and its analysis) stays warm.


---

## Core Concepts for Binary Analysis

### Addresses
Every code/data location has a virtual **address**. SQL returns them as
integers; format with `printf('0x%x', addr)` for hex display. Filter with
integer literals (`WHERE addr = 0x401000`) — fast and exact.

### Functions
radare2 groups code into **functions** (`funcs`): an entry `addr`, a `name`
(real symbol, or an auto-generated `fcn.<addr>` / `sym.*`), `size`, basic-block
count `nbbs`, CFG `edges`, cyclomatic complexity `cc`, `type`, and `calltype`.

### Cross-references (xrefs)
Analysis is about **relationships**. An xref is an edge `from_addr → to_addr`
with a `type`, and radare2's own vocabulary is the complete set: `CALL`,
`CODE`, `JUMP`, `ICOD` (indirect code), `DATA` (read/write), `STRN` (string),
`UNKN`, `NULL`. **A string reference is `STRN`, not `STRING`** — matching
`STRING` is not an error, it just returns nothing. "Who calls X?" is
`to_addr = X`; "what does X reference?" is `from_addr = X`.

### Sections vs segments vs io_maps
`sections` (`.text`, `.rdata`, `.data`, …) describe the file's logical layout;
`segments` describe the loader's memory view. Both carry `start_addr`,
`end_addr`, `vsize`, `paddr`, `size`, `name`, `perm` (a permission string like
`r-x`) — and both are read-only.
`io_maps` is r2's **writable** memory map (radare2 IO maps): INSERT a region,
DELETE it, query it. Use `io_maps` to add an SRAM region or rebase a raw image;
`sections`/`segments` are the binary's static headers.

**`r2xsql-full` reads `sections`/`segments` straight from radare2's
`RBinSection` vector instead of running `iSj`/`iSSj` and parsing the JSON** —
both commands share ONE producer (opposite `is_segment` filters over the same
vector), identical rows either way. Neither table needs an analysis pass at
all; both read straight off the loaded binary's own headers.

### Basic blocks
Within a function, **basic blocks** (`blocks`) are straight-line code runs with
a single entry and exit — the unit of control-flow analysis.

**`r2xsql-full` reads `blocks`/`cfg_edges`/`switch_tables`/`dominators`/
`post_dominators`/`loops` straight from radare2's in-process analysis state**
(`fcn->bbs`) instead of running `afbj @ X` and parsing its JSON — all six share
the same underlying block list, so this is one port that speeds up all six at
once, an unfiltered scan going from one command per function to none. The
pipe-only `r2xsql` drives a separate radare2 process, so it uses the `afbj @ X`
commands described below on both the full scan and the `func_addr` pushdown.
`switch_tables.table_addr` stays NULL on both flavors: the C API has the jump
table's own address, but no radare2 command exposes it, so surfacing it only
in-process would make the two flavors disagree on that column for the same
query.

### Control-flow edges
`cfg_edges` is the intra-function control-flow graph: one row per edge between two
basic blocks — `func_addr`, `from_addr`, `to_addr` (source/target block start
addresses), and `edge_type` (`normal`, `true`, `false`). Always filter by
`func_addr` (pushdown → `afbj @ X` on the pipe-only flavor). Branch points are
blocks with >1 successor; find them with `SELECT from_addr, COUNT(*) FROM
cfg_edges WHERE func_addr = X GROUP BY from_addr HAVING COUNT(*) > 1`.

### Dominators / post-dominators / loops
Canonical cross-tool CFG-graph tables (aligned with ghidrasql). Each maps a
function's basic blocks onto opaque node ids and runs the generic
`xsql::graph` module — pure r2xsql code, not a radare2 dominance API, so the
in-process speedup above comes entirely from how the block list itself is
read. Always filter by `func_addr` (pushdown → `afbj @ X` on the pipe-only
flavor).

| Table | Columns |
|-------|---------|
| `dominators` | `func_addr`, `node_addr`, `idom_addr` (NULL at entry), `depth`, `is_entry` |
| `post_dominators` | `func_addr`, `node_addr`, `ipdom_addr` (NULL to exit), `depth`, `is_exit` |
| `loops` | `func_addr`, `header_addr`, `latch_addr`, `start_addr`, `end_addr`, `depth`, `loop_kind`, `block_count` |

`loops.depth` is loop-nesting depth (outermost = 1); a self-loop is a 1-block loop.

```sql
-- Loops of a function, deepest nesting first
SELECT header_addr, block_count, depth FROM loops
WHERE func_addr = 0x401000 ORDER BY depth DESC;
```

### Raw bytes
`bytes` is the canonical byte surface: one row per mapped byte (`addr`, `value`
0..255 or NULL, `is_initialized`). The mapped address space comes from live
`omj`; `p8` supplies values and `iSj` identifies raw-backed section extents versus
BSS tails. Uninitialized or unreadable bytes have `value IS NULL`.
`WHERE addr = X` reads one mapped byte; an unmapped address returns no row.
`value` is **writable** — `UPDATE bytes SET value = X WHERE addr = Y` is a
direct, immediate, permanent one-byte overwrite via `wx`, requiring the
session opened `-w` (it writes straight through to the underlying file, not
just radare2's session metadata — no project save needed for it to stick).
This is deliberately **not** the same mechanism as `patches` (below): see
that table's own section for the distinction.

### Decompilation
With a decompiler plugin installed, `pseudocode` gives a C-like view of a
function — far more readable than disassembly. It is runtime-gated (see
*Decompiler Setup*) and must be filtered by `func_addr`.

### Annotations: flags, comments, bookmarks, locals
Your analysis notes live in radare2 and round-trip through writable tables:
`flags` (named addresses), `comments` (free text at an address), `bookmarks`
(flags in a dedicated `bookmarks` space), function **renames** via `funcs`, and
local-variable/argument **rename + retype** via `locals`.

### Projects
A radare2 **project** is the persistence unit. Edits stay in memory until saved
to a project — then you can reopen and resume later. See *Persistence & Projects*.

---

## Tables Reference

46 tables, including the runtime-gated `pseudocode`. Columns below are
authoritative; full detail lives in the per-topic skills.

### Orientation

#### `binary` (read-only)
Key/value binary metadata — `(key TEXT, value TEXT, type TEXT)`, one row per
fact, `type ∈ {string, hex, bool, int}`; the shape and canonical key names are
shared across the tool family, and the `summary` row is emitted first. Carries
radare2's raw bin-info fields (`arch`, `bits`, `bintype`, `os`, `baddr`,
`endian`, `compiler`, `lang`, …) plus r2xsql identity/entry/count keys AND
canonical family synonyms of the raw facts. Counts are JSON-array lengths, so
they match the corresponding tables exactly.

| Column  | Type | Notes                                        |
|---------|------|----------------------------------------------|
| `key`   | TEXT | field name                                   |
| `value` | TEXT | string representation                        |
| `type`  | TEXT | value type tag: string / hex / bool / int    |

Notable keys: `r2xsql_version`, `radare2_version`, `file`, `entry`,
`entry_name`, `func_count`, `string_count`, `import_count`, `section_count`,
`segment_count`, `symbol_count`, `summary`.

Canonical family keys (same names on idasql/bnsql/ghidrasql; values alias the
raw radare2 facts): `tool_name` (`r2xsql`), `tool_version`, `processor` (=arch),
`filetype` (=bintype), `image_base` (=baddr, hex), `entry_point` (=entry),
`is_64bit`, `endianness`, `filename` (=file), and `min_addr`/`max_addr` derived
from the section/segment maps (omitted when unmapped). `bits` doubles as the
canonical bits key. No `md5`/`sha256` (best-effort core; radare2 hashing is
unreliable).

`radare2_version` is the running radare2 ENGINE's own version (from `?Vj`),
distinct from `r2xsql_version`/`tool_version` above — on the r2pipe flavor
the engine actually running is whatever `radare2` binary is on `PATH` at
runtime, which can differ from what r2xsql itself was built against, so
this is the only reliable source for "which radare2 is this."

```sql
-- everything at a glance
SELECT key, value FROM binary ORDER BY key;

-- just format / arch / bits
SELECT key, value FROM binary
WHERE key IN ('format','bintype','arch','bits','os','endian','class');
```

**Binary-metadata summary recipe, no dedicated table needed**: `binary` (above)
plus `bininfo` already cover every metadata field a key/value `db_info`-style
table would carry, and every `*_count` field is trivially `SELECT COUNT(*) FROM
<table>` (`funcs`, `strings`, `names`, `imports`, `sections`, `xrefs`) — any
SQL table already supports `COUNT(*)`, so a duplicate summary table would
just be a second, driftable copy of the same numbers.

#### `bininfo` (read-only)
One-row, typed binary-metadata summary — architecture/format/OS facts plus
mitigation flags — for the "first question an analyst asks" shape a key/value
scan can't answer in one row: `SELECT has_nx, has_canary, has_pi FROM
bininfo`. Sourced from the SAME `iIj` payload `binary` already reads
generically (this table is an EXTENSION of that data, not a new radare2
capability) plus a second `ij` call for `file`, matching `binary`'s own
two-command shape.

| Column | Type | Notes |
|---|---|---|
| `file` | TEXT | nullable; `ij` → `core.file` |
| `format` | TEXT | `iIj` `bintype` (`RBinInfo::rclass`) |
| `arch` | TEXT | `iIj` `arch` |
| `cpu` | TEXT | nullable |
| `bits` | INT64 | |
| `os` | TEXT | nullable — see gating note below |
| `machine` | TEXT | nullable — gated |
| `endian` | TEXT | `big` / `little` |
| `lang` | TEXT | nullable — gated |
| `class` | TEXT | `iIj` `class` (`RBinInfo::bclass`) |
| `subsystem` | TEXT | nullable — gated |
| `compiler` | TEXT | may be empty (radare2 rarely detects it) |
| `baddr` | INT64 | image base |
| `has_va` | INT | nullable 0/1 — gated |
| `has_nx` | INT | nullable 0/1 — gated |
| `has_canary` | INT | **never** NULL — unconditional in `iIj` |
| `has_pi` | INT | nullable 0/1 — gated (PIC/PIE) |
| `default_cc` | TEXT | nullable — gated |

```sql
-- security-triage first question
SELECT has_nx, has_canary, has_pi, has_va FROM bininfo;

-- orientation in one row instead of a key/value scan
SELECT format, arch, bits, os, endian, class, compiler FROM bininfo;
```

**Caveats:**
- **`os`/`machine`/`lang`/`subsystem`/`default_cc`/`has_va`/`has_nx`/`has_pi`
  read NULL, not a guessed default, on a non-executable input** (radare2's
  own `bin_info()` gates these behind an internal "looks like code" check).
  `has_canary` is the one mitigation flag NOT gated this way — it is always a
  real 0/1.
- **No `rclass` column.** Verified
  against radare2's `bin_info()` source: `iIj` emits exactly one JSON key for
  `RBinInfo::rclass` (`"bintype"`, already `format` here) and never a
  separate key for `RBinInfo::type` — the field a `rclass`-vs-`format`
  distinction would need. Command-path-only (no C-API producer, so both
  backends must share identical JSON) means there is no safe second source
  for a third, distinct value.
- **JSON key names differ from the boolean column names.** `iIj` reports
  `nx`/`pic`/`va` (bare), not `has_nx`/`has_pi`/`has_va` — this table's
  columns follow the more self-documenting `RBinInfo` struct-field spelling;
  the rename is a source-mapping detail invisible to SQL callers.
- **Empty table, not a row of blanks, when no bin is loaded** — unlike
  `binary` (which always emits identity/version rows).

### Code structure

#### `funcs` (writable)
Source `aflj`. One row per analyzed function.

| Column     | Type  | Notes                                       |
|------------|-------|---------------------------------------------|
| `addr`     | INT64 | virtual address (entry)                     |
| `name`     | TEXT  | function name (**writable** ⇒ rename)       |
| `size`     | INT64 | declared size in bytes                      |
| `nbbs`     | INT64 | number of basic blocks                      |
| `edges`    | INT64 | CFG edge count                              |
| `cc`       | INT64 | **cyclomatic complexity** (radare2's own meaning) — the calling convention is `calltype`, not this |
| `type`     | TEXT  | `fcn` / `sym` / `loc`                        |
| `calltype` | TEXT  | calling convention name, e.g. `ms` / `amd64` / `reg` (**writable** ⇒ `afc`; validated up front against `calling_conventions`, then readback-verified via `afij`) |
| `prototype`| TEXT  | C signature (**writable** ⇒ `afs` set-signature); read from `aflj` `signature` |
| `end_addr` | INT64 | past the highest block — **not** `addr + size` (blocks can sit below the entry) |
| `ninstrs`  | INT64 | instruction count                            |
| `stackframe`| INT64 | frame size                                  |
| `cost`     | INT64 | estimated execution cost                     |
| `tracecov` | INT64 | trace coverage                               |
| `is_noreturn` | INT | 1 if the function never returns              |
| `is_pure`  | INT   | 1 if radare2 considers it pure               |
| `is_recursive` | INT | 1 if the function calls itself              |

```sql
-- leaf-ish, cheap, pure helpers worth inlining mentally
SELECT name, ninstrs FROM funcs WHERE is_pure = 1 AND cc = 1 ORDER BY ninstrs;

-- self-recursive functions, and functions that never come back
SELECT name FROM funcs WHERE is_recursive = 1 OR is_noreturn = 1;

-- big stack frames are where the buffers live
SELECT name, stackframe FROM funcs ORDER BY stackframe DESC LIMIT 10;
```

`UPDATE funcs SET prototype = 'int parse(hdr_t *h, int len)' WHERE addr = …`
applies a C function signature via `afs`. A trailing `;` is stripped (r2's
command separator); an empty/NULL prototype is rejected (r2 has no
clear-signature primitive — an empty `afs` mangles the name).

`UPDATE funcs SET calltype = 'ms' WHERE addr = …` sets the calling convention
via `afc`. Only a name `SELECT name FROM calling_conventions` already reports
for this session is accepted — `afc` itself gives no usable signal on a
rejected name (its own output is empty on both success and failure), so an
unrecognized value is rejected up front rather than silently no-op'd.

Every `funcs` write (rename, set-signature, set-calltype, undefine, define) is
address-scoped,
so on the in-process backend each one dispatches through a structural
command-dispatch path that never evaluates r2's own command separators at all
— a second, independent layer beneath the name/signature validation above (the
same mechanism `comments` writes already use). The pipe backend is unaffected:
it always uses the plain command form.

`name`'s rename stays on that command path (`afn`) on **both** flavors —
deliberately not ported to a direct C-API call, unlike `flags`/`locals`
(below). `afn`'s command handler also renames the function's backing flag and
its stored signature metadata, side effects the raw C-API rename function
does not reproduce; calling it directly would desync `funcs.name` from
`flags.name` for that address.

```sql
-- 20 largest functions
SELECT printf('0x%x', addr) AS at, name, size, cc, nbbs
FROM funcs ORDER BY size DESC LIMIT 20;

-- auto-named (unanalyzed) functions
SELECT printf('0x%x', addr) AS at, name FROM funcs WHERE name LIKE 'fcn.%';

-- abnormally complex functions
SELECT name, cc FROM funcs WHERE cc > 30 ORDER BY cc DESC;
```

#### `calling_conventions` (read-only)
Source `afclj` (dispatched through `tcc`), which iterates radare2's per-target
calling-convention database — the **exact same** underlying state
`funcs.calltype`/`funcs.stackframe` are already driven by. Where `funcs`
tells you which convention a specific function was assigned, this table
tells you what that convention actually *means*: its argument registers,
return register(s), and overflow-argument location. A **static** reference
table for the current session's `(arch, bits)` — not derived from the
binary's own bytes, and typically single digits of rows on a real target
(e.g. `amd64`, `ms`, `swift`, `p9`, `dlang`, `reg`). No pushdown — the whole
set is cheap and small enough that a full scan is the only query shape that
makes sense.

| Column | Type | Notes                                                            |
|--------|------|-------------------------------------------------------------------|
| `name` | TEXT | convention name (`ms`, `amd64`, `swift`, `p9`, `dlang`, `reg`, …)  |
| `args` | TEXT | comma-joined argument registers, in position order (`rcx,rdx,r8,r9`) |
| `ret`  | TEXT | primary return-value register (radare2's `ret0`); NULL if undefined |
| `rets` | TEXT | comma-joined **full** return-register list (`ret0`, `ret1`, …) — **not always the same as `ret`**: a genuine multi-return-register convention (e.g. `dlang` on x86, which returns a second value in `edx`/`rdx`) has more entries here than the single `ret` column carries |
| `argn` | TEXT | location for every argument PAST the last position named in `args` — i.e. where overflow arguments go. **Not an argument value or a count, despite the name.** Radare2's compact location syntax: `^` = ascending stack, `^-` = descending/reversed stack push order, or (rarely, on some non-x86 ABIs) a plain register name reused for overflow args. NULL when the convention defines no args past its named positions |

```sql
-- what does "ms" actually look like on this target?
SELECT args, ret, rets, argn FROM calling_conventions WHERE name = 'ms';

-- every convention radare2 knows for this session
SELECT name, args, ret FROM calling_conventions ORDER BY name;

-- cross-check a function's assigned convention against its real definition
SELECT f.name, f.calltype, cc.args, cc.ret
FROM funcs f JOIN calling_conventions cc ON cc.name = f.calltype
WHERE f.addr = 0x401000;
```

**Data-dir cliff:** `funcs.calltype`/`funcs.stackframe` and this table read
the same SDB, and both were affected by the same failure mode — an
in-process consumer not run from the analysis engine's own install location
used to load a synthetic single-entry fallback convention (name `reg`, built
straight from the register profile) instead of the real per-arch table,
**silently and with no log signal**: every function reported a plausible
but factually wrong calling convention rather than an empty/missing one.
That gap has since been closed by an explicit cache-busting reload keyed off
the build's own configured prefix. If it ever regresses, this table
degrades the same visible way `funcs.calltype` used to: exactly one row
named `reg`, not zero rows — `SELECT COUNT(*) FROM calling_conventions` was
`1` when it happened, `7`+ once fixed.

No `signature` column: `afclj`'s JSON also carries a rendered
`"ret name (arg0, ..., argn);"` text field, but that is display text
radare2's own renderer already produced — the same rendered-vs-structured
split `funcs.prototype` documents against `funcs`'s other columns — and is
redundant with the structured `args`/`ret`/`rets`/`argn` fields above.

#### `locals` (writable)
Source per-function `afvj @ <func_addr>` on the pipe-only flavor; `r2xsql-full`
reads `fcn->vars` directly instead of running that command — identical rows,
one command per function replaced by none on a full scan. One row per local
variable/argument, keyed on `(func_addr, name)`. Both `name` and `type` are
writable on both flavors: `r2xsql-full` calls `r_anal_var_rename`/
`r_anal_var_set_type` directly (measured 78-150x over `afvn`/`afvt` on a bulk
rename/retype workload, exact parity); the pipe-only flavor still issues
`afvn`/`afvt`. On the in-process (libr) flavor, whenever that C-API leg is
unavailable, the command-path fallback (also the pipe-only flavor's only
path) dispatches `afvn`/`afvt` through the same structural no-eval command
path every other address-scoped write uses — see "Structural no-eval
dispatch" below.

| Column        | Type  | Notes                                          |
|---------------|-------|------------------------------------------------|
| `func_addr`   | INT64 | owning function's address                      |
| `name`        | TEXT  | variable/argument name (**writable** ⇒ rename via `afvn`) |
| `kind`        | TEXT  | `reg` / `arg` / `var`                           |
| `storage`     | TEXT  | `reg` / `stack` (sp-relative) / `spv` (bp-relative) |
| `storage_ref` | TEXT  | `rcx` for a register; `rsp+0x20` for a stack slot |
| `type`        | TEXT  | variable type (**writable** ⇒ retype via `afvt`) |
| `size`        | INT64 | `0` (afvj carries no size)                      |

```sql
-- list a function's locals and args
SELECT name, kind, storage_ref, type FROM locals WHERE func_addr = 0x401000;

-- rename a local, then give it a type (r2 takes a bare type — do NOT quote it)
UPDATE locals SET name = 'key_len' WHERE func_addr = 0x401000 AND name = 'var_20h';
UPDATE locals SET type = 'int'     WHERE func_addr = 0x401000 AND name = 'key_len';
```

Locals are analysis-derived — no INSERT/DELETE. r2 reflects a rename/retype
immediately, so the next read returns the new value.

#### `blocks` (read-only)
Source per-function `afbj @ <addr>` on the pipe-only flavor; `r2xsql-full`
reads `fcn->bbs` directly (see "Basic blocks" above). Filter by `func_addr`.

| Column      | Type  | Notes                |
|-------------|-------|----------------------|
| `addr`      | INT64 | block start          |
| `size`      | INT64 | block size in bytes  |
| `func_addr` | INT64 | owning function      |

```sql
SELECT printf('0x%x', addr) AS at, size
FROM blocks WHERE func_addr = 0x401000 ORDER BY addr;
```

#### `instructions` (read-only)
Source per-function `pdfj @ <addr>`. **Filter by `func_addr`** — an unfiltered
scan disassembles every function. A second, independent filter reads an
arbitrary address range instead of a function: `WHERE start_addr = X AND
count = N` (both required together) issues `pdj N @ X` — useful for
disassembling data-adjacent code, gaps, or any address that isn't a
function's own entry. It is **not** a substitute for `func_addr`: it walks
linearly from `X` and cannot reach a block below its own function's entry
(non-contiguous functions are real), and it doesn't know which function (if
any) owns the addresses it walks, so `func_addr` is always `0` on rows from
this path.

**Performance: what you SELECT changes how this table is filled, on the
in-process (`r2xsql-full`) connection.** `disasm` and `mnemonic` are
*rendered text* — radare2's own disassembly renderer, no exported C-API
entry point — so a query that selects either always runs the full command
path (`pdfj`/`pdj`, same as always). Every other column (`addr`, `size`,
`bytes`, `func_addr`, `esil`, `op_type`, `family`, plus the client-computed
`seq`/`canonical_op`) is *reported data*, and a query that selects **none**
of `disasm`/`mnemonic` reads it straight from radare2's analysis state
instead — measured 4-9x faster end to end, with exact field parity, on every
one of this table's three shapes (full scan, `func_addr` pushdown,
`start_addr`/`count` pushdown). This applies to `r2xsql-full` only — the
pipe-only `r2xsql` connection always uses the command path, since it spawns
a separate radare2 process with no in-process state to read. In practice:
`SELECT addr, op_type, esil FROM instructions WHERE func_addr = X` is the
fast shape; adding `disasm` or `mnemonic` to that same query switches it back
to the command path — not a bug, and not something to avoid when you
actually need the rendered text, just something to know when tuning a
wide scan.

| Column         | Type  | Notes                                          |
|----------------|-------|------------------------------------------------|
| `addr`         | INT64 | instruction address                            |
| `size`         | INT64 | instruction length in bytes                    |
| `func_addr`    | INT64 | owning function (`0` for `start_addr`/`count` rows) |
| `seq`          | INT64 | per-scan ordinal (0-based, in `addr` order)    |
| `mnemonic`     | TEXT  | opcode (`call`, `mov`, `jmp`, …)               |
| `disasm`       | TEXT  | full disassembled text                         |
| `bytes`        | TEXT  | hex-encoded bytes (e.g. `4889e5`)              |
| `esil`         | TEXT  | radare2's stack-based IL (same `pdfj`/`pdj` op; empty when r2 doesn't lift it) |
| `op_type`      | TEXT  | radare2 semantic op type (`add`, `call`, `cjmp`, …) |
| `canonical_op` | TEXT  | cross-tool canonical P-code-style op (`INT_ADD`, `CALL`, `CBRANCH`, …); empty when no clean canonical |
| `family`  | TEXT  | radare2 instruction family (`cpu`, `fpu`, `sse`, `priv`, `virt`, …) — find floating-point / vector / privileged code without matching mnemonic text |
| `start_addr`, `count` | INT64 | hidden, input-only — the range pushdown; both required together |

```sql
-- disassemble one function
SELECT printf('0x%x', addr) AS at, mnemonic, disasm
FROM instructions WHERE func_addr = 0x401000 ORDER BY addr;

-- every call in a function
SELECT printf('0x%x', addr) AS at, disasm
FROM instructions WHERE func_addr = 0x401000 AND mnemonic = 'call';

-- semantic op classification (radare2 + canonical)
SELECT printf('0x%x', addr) AS at, op_type, canonical_op, esil
FROM instructions WHERE func_addr = 0x401000 ORDER BY seq;

-- disassemble 10 instructions starting at an arbitrary address (not a function entry)
SELECT printf('0x%x', addr) AS at, disasm
FROM instructions WHERE start_addr = 0x401050 AND count = 10 ORDER BY addr;

-- where are the syscall instructions in this binary? -- already answered
-- here, no separate table needed (see `syscalls` below for the *reference*
-- name/number lookup, which is a different question)
SELECT printf('0x%x', addr) AS at, disasm
FROM instructions WHERE func_addr = 0x401000 AND op_type = 'swi' ORDER BY addr;
```

#### `instruction_operands` (read-only)
One row per decoded instruction operand, from `aoj` (`opex.operands`). **Filter by
`addr`** (one instruction → `aoj 1 @ X`) **or `func_addr`** (whole function →
block-scoped `aoj` reads over the exact `afbj.instrs` addresses). Canonical
cross-tool schema; the block walk preserves non-contiguous function bodies.

| Column          | Type  | Notes                                            |
|-----------------|-------|--------------------------------------------------|
| `addr`          | INT64 | instruction address                              |
| `func_addr`     | INT64 | owning function                                  |
| `operand_index` | INT64 | 0-based operand position                         |
| `text`          | TEXT  | rendered operand (`rax`, `0x10`, `[rbp - 0x4]`)  |
| `type_name`     | TEXT  | `register` / `immediate` / `memory` / …          |
| `value`         | INT64 | immediate value (0 when not an immediate)        |
| `size`          | INT64 | operand size in bytes                            |

```sql
-- operands of one instruction
SELECT operand_index, text, type_name, value
FROM instruction_operands WHERE addr = 0x401000 ORDER BY operand_index;
```

#### `esil_ops` / `esil_operands` (read-only — the tokenized ESIL op stream)
`esil_ops` runs radare2's **ESIL** (a postfix stack IL) through a tokenizer to rebuild a
finer canonical op stream — **multiple ops per instruction** (e.g. `sub rsp, 0x40` yields
`INT_SUB` + the flag arithmetic). Columns: `func_addr`, `seq` (per-function esil-op index),
`addr` (source instruction), `op` (canonical), `native_op` (the ESIL operator token or the
control-flow op type). Control flow (CALL/BRANCH/RETURN) is NOT an ESIL op — it is emitted
from the instruction's semantic `op.type`, so the stream is complete. **Filter by `func_addr`.**

`esil_operands` — the 5-kind value operands (one row per op input/output): `func_addr`,
`op_seq` (joins `esil_ops.seq`), `operand_index`, `role` (`in`|`out`), `kind`
(`reg`|`imm`|`mem`|`var`|`result`), `text` (the ESIL token). Structural control/stack-juggle
tokens (`?{`, `}`, `GOTO`, `DUP`, …) are excluded — r2 is the **PARTIAL / lowest-fidelity** leg.

#### `ir_ops` / `ir_v_*` / `ir_operands` / `ir_maturities` (read-only views — cross-tool low-IR)
Canonical low-IR over **`esil_ops`** (a fidelity upgrade — the finer tokenized stream, not
the coarse one-op-per-instruction path), sharing the same names/columns as the other family
tools. r2 is the **lowest-fidelity leg** — **no SSA**, single rung. **Filter by `func_addr`.**

`ir_ops` columns: `func_addr`, `seq`, `addr`, `op` (canonical), `native_op` (ESIL/type
token), `is_ssa` (always `0`), `maturity` (always `esil`), `stage` (always `final`).
The semantic views `ir_v_calls` / `ir_v_mem_writes` / `ir_v_mem_reads` / `ir_v_branches` /
`ir_v_arith` each expose `func_addr`, `seq`, `addr`, `op`. **`ir_operands`** projects
`esil_operands` (join `op_seq = ir_ops.seq`); **`ir_maturities`** advertises the single
`esil` rung.

```sql
-- canonical low-IR op stream for a function (the tokenized ESIL ops)
SELECT seq, printf('0x%x', addr) AS at, op, native_op
FROM ir_ops WHERE func_addr = 0x401000 ORDER BY seq;

-- each op with its operands
SELECT o.seq, o.op, p.role, p.kind, p.text
FROM ir_ops o JOIN ir_operands p ON p.func_addr = o.func_addr AND p.op_seq = o.seq
WHERE o.func_addr = 0x401000 ORDER BY o.seq, p.operand_index;
```

#### `sections` / `segments` (read-only)
Source `iSj` / `iSSj` on the pipe-only flavor; `r2xsql-full` reads
`RBinSection` directly instead (see "Sections vs segments vs io_maps" above).

| Column  | Type  | Notes                          |
|---------|-------|--------------------------------|
| `start_addr` | INT64 | virtual address (canonical)    |
| `end_addr`   | INT64 | `start_addr + vsize`        |
| `vsize` | INT64 | virtual size                   |
| `paddr` | INT64 | physical (file) offset         |
| `size`  | INT64 | raw size                       |
| `name`  | TEXT  | `.text`, `.rdata`, …           |
| `perm`  | TEXT  | permission string (`r-x`, …)   |

```sql
-- executable sections
SELECT name, perm, vsize, printf('0x%x', start_addr) AS at
FROM sections WHERE perm LIKE '%x%';
```

#### `io_maps` (writable — r2's memory map)
Source `omj`. radare2 IO maps: the live, editable address space (distinct from the
read-only binary `sections`/`segments`). INSERT issues `om`, DELETE issues `om-<id>`.

| Column  | Type  | Notes                          |
|---------|-------|--------------------------------|
| `start_addr` | INT64 | map virtual start (`from`)     |
| `end_addr`   | INT64 | exclusive end (`to` + 1)       |
| `perm`  | TEXT  | permission string (`rw-`, …)   |
| `name`  | TEXT  | map name                       |
| `paddr` | INT64 | physical offset (`delta`)      |
| `map_id`| INT64 | radare2 map id (for DELETE)    |
| `fd`    | INT64 | backing file descriptor        |

```sql
-- Add an SRAM region to a raw firmware image's memory map
INSERT INTO io_maps(start_addr, end_addr, perm, name)
  VALUES (0x20000000, 0x20002800, 'rw-', 'SRAM');
DELETE FROM io_maps WHERE name = 'SRAM';
```

### Data

#### `patches` (writable — `io.cache` byte-patch overlay)
Source `wcj`. A revertible byte-patch overlay, distinct from a direct
`bytes.value` overwrite: a staged patch lives only in radare2's in-process
write cache (`io.cache`) until explicitly committed, and an uncommitted patch
can be undone.

| Column           | Type  | Notes                                                |
|------------------|-------|-------------------------------------------------------|
| `addr`           | INT64 | patch address                                        |
| `size`           | INT64 | patch size in bytes (derived from `patched_bytes` on INSERT) |
| `original_bytes` | TEXT  | hex, the bytes as they were **before** this patch     |
| `patched_bytes`  | TEXT  | hex, the bytes **after** this patch (**writable on INSERT**) |
| `asm_text`       | TEXT  | INSERT-only, write-only: an assembly mnemonic, assembled AT `addr` (same mechanism as `assemble`) — never stored/read back, always empty on SELECT |
| `committed`      | INT   | 0 = staged only, 1 = written through to the file (**writable, `1` only**) |

```sql
INSERT INTO patches(addr, patched_bytes) VALUES(0x140001d70, '90909090');  -- wx
SELECT patched_bytes, committed FROM patches WHERE addr = 0x140001d70;     -- committed=0
UPDATE patches SET committed = 1 WHERE addr = 0x140001d70;                 -- wci
DELETE FROM patches WHERE addr = 0x140001d70;                              -- wcu (uncommitted only)

-- patch_asm(addr, asm): assemble-then-write in one INSERT. Exactly one of
-- patched_bytes/asm_text is required (not both, not neither).
INSERT INTO patches(addr, asm_text) VALUES(0x140001d70, 'nop');
```

**`UPDATE patches SET committed = 1` commits EVERY pending patch in the
session, not just the row matched by `WHERE`.** radare2's write cache has no
selective or ranged commit — its ranged form (`wc+ <from> <to>`) is a
confirmed upstream memory-safety defect, so the only commit primitive this
table ever issues is `wci` (commit-all). If you need to keep some patches
uncommitted while committing others, `DELETE` the ones you don't want
committed first, then commit the rest. `SET committed = 0` is rejected —
there is no verified "uncommit" primitive for an already-committed patch.

`DELETE` only undoes an **uncommitted** patch, and only when it is the
**most-recently-staged** one: radare2's undo (`wcu`) always undoes whatever
was staged last, with no address targeting at all. Deleting an older
still-pending patch while a newer one is also pending is refused with an
explanatory error — delete the newer one(s) first. INSERT accepts raw hex
(`patched_bytes`) OR an assembly mnemonic (`asm_text`, assembled AT `addr`
via the same `pa`-based mechanism as `assemble`) — exactly one of the two;
either way the result still goes through `wx`, never `wa`/`wz`.

INSERT's `wx` is address-scoped, so on the in-process (libr) backend it
dispatches through the same structural no-separator-evaluating command path
every other writable table's address-scoped write uses — a second,
independent layer beneath the hex-charset validation above (which, on its
own, already keeps this argument free of every r2 command metacharacter).
`wci`/`wcu` (the UPDATE/DELETE primitives above) are fixed commands with no
user-controlled text in them at all — nothing to dispatch differently — so
they stay on the plain command path, unchanged. The pipe backend is
unaffected on all three writes.

#### `bytes` (writable: UPDATE only — direct byte overwrite)
Source `omj`/`p8`/`iSj` for reads (see *Raw bytes* above); `value` is writable
via `wx`, one byte at a time. **This is NOT the `patches` table.** `patches`
stages a *revertible* change into radare2's `io.cache` overlay (undoable via
`DELETE`, committed via `UPDATE ... SET committed = 1`); `UPDATE bytes SET
value = X WHERE addr = Y` is a *direct, immediate, permanent* overwrite with
no staged/pending state at all — it bypasses `io.cache` entirely (disabling
it for the duration of the write, then restoring it to whatever it was
before, even if a `patches` row is mid-flight elsewhere) so this table's
writes can never be mistaken for, or interfere with, a `patches` entry.
There is no undo; if you want a revertible change, use `patches` instead.

| Column           | Type  | Notes                                                |
|------------------|-------|-------------------------------------------------------|
| `addr`           | INT64 | byte address (read-only)                              |
| `value`          | INT   | 0-255, or NULL if unmapped/uninitialized (**writable**) |
| `is_initialized` | INT   | 1 if file-backed, 0 if BSS/unbacked (read-only)        |

```sql
UPDATE bytes SET value = 0x90 WHERE addr = 0x140001d70;  -- wx 90 @ 0x140001d70
SELECT value FROM bytes WHERE addr = 0x140001d70;        -- reads back 144 immediately
```

`value` must be an integer 0-255 — anything outside that range (or `NULL`) is
rejected before any radare2 command runs, the same up-front validation
`funcs.calltype` uses. Only a currently-**initialized** byte (`is_initialized
= 1`) can be written: a BSS/unbacked address is refused up front, because
this table's `is_initialized` classification comes from static section
metadata and never changes from a write — writing there would leave `value`
reading `NULL` forever afterward with no way to read the write back through
this table. No INSERT or DELETE: a byte can't be created or removed, only
changed. `addr`/`is_initialized` stay read-only.

#### `strings` (read-only)
Source `izj` on the pipe-only flavor; `r2xsql-full` reads `r_bin_get_strings`
directly instead — identical rows (that command handler already calls the
same function internally). (The `content` column is skipped at build time
when you don't select it — so `COUNT(*)` / length histograms over `strings`
are cheap on both flavors.)

| Column    | Type  | Notes                              |
|-----------|-------|------------------------------------|
| `addr`    | INT64 | string address                     |
| `length`  | INT64 | length                             |
| `section` | TEXT  | containing section                 |
| `type`    | TEXT  | `ascii` / `utf8` / `utf16le` / …   |
| `content` | TEXT  | the string contents                |
| `paddr`   | INT64 | file offset (`addr` is the virtual address) — use it to carve or patch on disk |

```sql
-- find a substring (case-insensitive via LIKE)
SELECT printf('0x%x', addr) AS at, content FROM strings WHERE content LIKE '%password%';

-- longest strings (often format strings / embedded blobs)
SELECT length, type, content FROM strings ORDER BY length DESC LIMIT 20;
```

#### `data_items` (read-only)
Defined data items, canonical cross-tool schema. The honest r2 maximum: strings
(`izj`) UNION non-FUNC data symbols (`isj`), deduped by `addr`. On a stripped PE
this is effectively the string set; on an ELF-with-symtab it also carries `OBJECT`
globals — r2 has no rich typed-global model, so nothing is synthesized. Full-scan.

| Column           | Type  | Notes                                                        |
|------------------|-------|--------------------------------------------------------------|
| `addr`           | INT64 | item address                                                 |
| `name`           | TEXT  | data-symbol name, or NULL (strings have no `isj` name)       |
| `data_type`      | TEXT  | symbol `type`, or `string` for strings; NULL if unknown      |
| `size`           | INT64 | byte size                                                    |
| `value_repr`     | TEXT  | string contents for strings, else NULL                       |
| `segment_name`   | TEXT  | containing section when known                                |
| `is_string`      | INT   | 1 when a string starts at `addr`                             |
| `is_initialized` | INT   | 0 for a known BSS item, otherwise 1                          |

```sql
-- all defined data, strings first
SELECT printf('0x%x', addr) AS at, data_type, size, value_repr
FROM data_items ORDER BY is_string DESC, size DESC LIMIT 20;
```

#### `imports` (read-only)
Source `iij` on the pipe-only flavor; `r2xsql-full` reads `RBinImport`
directly instead (via the same `r_bin_name_tostring`/`r_bin_demangle`/
`r_core_bin_impaddr` helpers the command emitter itself calls) — identical
rows, no command dispatch.

| Column    | Type  | Notes                          |
|-----------|-------|--------------------------------|
| `addr`    | INT64 | IAT slot address               |
| `ordinal` | INT64 | import ordinal                 |
| `bind`    | TEXT  | binding                        |
| `type`    | TEXT  | symbol type                    |
| `name`    | TEXT  | imported symbol name           |
| `module` | TEXT  | source library / DLL           |

```sql
-- imports grouped by library
SELECT module, COUNT(*) AS n FROM imports GROUP BY module ORDER BY n DESC;

-- crypto API surface
SELECT name, module FROM imports
WHERE name LIKE 'Crypt%' OR name LIKE 'BCrypt%'
   OR name LIKE '%AES%'  OR name LIKE '%SHA%' OR name LIKE '%RC4%';
```

`imports.addr` is the IAT slot, not the resolved external — pivot through
`xrefs` to find code that calls through it.

#### `entries` (read-only)
Sources `iej` (program entry points) plus `iEj` (exports), deduplicated by address,
on the pipe-only flavor; `r2xsql-full` reads `RBinAddr`/`RBinSymbol` directly
instead and merges them the same way — identical rows. Executables normally
have at least their loader entry point even when they export no symbols. Note
`entries.name` is the ORIGINAL symbol name, never demangled, on either flavor.

| Column | Type  | Notes               |
|--------|-------|---------------------|
| `addr` | INT64 | entry/export address |
| `size` | INT64 | size                |
| `type` | TEXT  | symbol type         |
| `bind` | TEXT  | binding             |
| `name` | TEXT  | entry/export name    |

```sql
SELECT name, printf('0x%x', addr) AS at, type FROM entries ORDER BY name;
```

### Relationships

#### `xrefs` (read-only)
Source per-function `afxj @ <fn>`. Point lookups push down: `to_addr = X` ⇒
`axtj @ X`, `from_addr = X` ⇒ `axfj @ X`. An unfiltered scan enumerates `afxj`
across every function.

**`r2xsql-full` reads this table straight from radare2's in-process analysis
state instead of running those commands** — same rows, roughly an order of
magnitude faster on a large binary, where an unfiltered scan would otherwise be
one command per function. The pipe-only `r2xsql` drives a separate radare2
process, so it uses the commands above. (`funcs`, `byte_search`, `locals`,
`flags`, the `blocks`/`cfg_edges`/`switch_tables`/`dominators`/
`post_dominators`/`loops` cluster, and `strings`/`sections`/`segments`/
`imports`/`entries` use the same in-process path; every other table runs
commands on both flavors.)

| Column      | Type  | Notes                                  |
|-------------|-------|----------------------------------------|
| `from_addr` | INT64 | source address                         |
| `to_addr`   | INT64 | target address                         |
| `type`      | TEXT  | `CALL`/`CODE`/`JUMP`/`ICOD`/`DATA`/`STRN`/`UNKN`/`NULL` |
| `from_func` | INT64 | **address** of the function the ref originates in; NULL outside any function — join it to `funcs.addr` |
| `is_code`   | INT   | 1 for `CALL`/`CODE`/`JUMP`/`ICOD`      |
| `is_data`   | INT   | 1 for `DATA`/`STRN`                    |
| `kind`      | TEXT  | `call`/`jump`/`code`/`data`/`unknown` — see the deviation note below |

`from_func` is an address, not a name: join it against `funcs.addr` to get the
caller's name. `is_code`/`is_data` save you from spelling out radare2's type
strings, and a ref is neither when its type is `UNKN`/`NULL`.

**`kind` is r2xsql's OWN small vocabulary, not a family standard.** It is a
free normalization of `type` — computed from the value already fetched for
that column, no new radare2 command — into `call`/`jump`/`code`/`data`/
`unknown`: `CALL`→`call`, `JUMP`→`jump`, `CODE`/`ICOD`→`code`, `DATA`/`STRN`→
`data`, everything else (`UNKN`/`NULL`/absent)→`unknown`. This is a
deliberate, owner-approved deviation, not a quiet claim of family-wide
portability — no shared vocabulary has been agreed across the tool family
yet for `xrefs`. Never assume a sibling tool's `kind` spelling matches these
values.

**Prefer the `callers` / `callees` / `string_refs` views** (below) for
call-graph questions — they do these joins for you and are portable across the
family. Come to this table for data references, a specific `type`, or an edge
whose target is neither a function nor an import.

Two things to know when you do query it directly. `WHERE from_func = X` is
scoped (`afxj @ X`) but `X` must be a function's **start** address, since that
is what the column holds. And a full scan enumerates references per analyzed
function, so it cannot see one whose source is outside every function, while a
`WHERE to_addr = X` lookup can — those rows have `from_func IS NULL`, so add
`AND from_func IS NOT NULL` when you need the phrasing not to matter.

```sql
-- who calls / references this address?
SELECT printf('0x%x', x.from_addr) AS frm, f.name AS in_func, x.type
FROM xrefs x LEFT JOIN funcs f ON f.addr = x.from_func
WHERE x.to_addr = 0x401000;

-- callers of every crypto import (join imports ⨝ xrefs ⨝ funcs)
SELECT DISTINCT f.name AS caller, i.name AS import
FROM imports i
JOIN xrefs x ON x.to_addr = i.addr
LEFT JOIN funcs f ON f.addr = x.from_func
WHERE i.name LIKE 'Crypt%';

-- every code-flow edge, without naming a single type string
SELECT from_addr, to_addr FROM xrefs WHERE is_code = 1;
```

Indirect calls (`call qword [rip+…]`) may resolve to the IAT **slot** rather
than the final target; re-run deeper analysis (`aaaa` / emulation `aae`) for
more edges.

#### `names` (read-only view)
Every named address radare2 knows. radare2 has no separate symbol table — its
flags **are** the name table — so this is a projection of `flags`, and
`namespace` is radare2's real flagspace (`imports`, `strings`, `functions`,
`relocs`, `registers`, …).

| Column | Type | Notes |
|---|---|---|
| `addr` | INT64 | address |
| `name` | TEXT | the name radare2 carries |
| `realname` | TEXT | demangled/original form when radare2 has one |
| `namespace` | TEXT | radare2's flagspace |

**Uncurated on purpose** — the ~800 `strings` and the CPU `registers` are here
too, because deciding which flagspaces "count as names" is a classification
radare2 never made. Filter instead:

```sql
SELECT name, realname FROM names WHERE namespace = 'imports';
SELECT addr, name FROM names WHERE namespace NOT IN ('strings','registers');
```

#### `callers` / `callees` / `string_refs` (read-only views)
The call graph with names already resolved. These carry the same names and
columns in every tool of this family, so a query written against them is
portable. They are plain SQL over `xrefs`/`funcs`/`imports`/`strings`, so
`WHERE func_addr = X` still reaches a scoped radare2 command.

| View | One row per | Columns |
|---|---|---|
| `callers` | edge into a function | `func_addr`, `caller_addr`, `caller_name`, `caller_func_addr` |
| `callees` | edge out of a function | `func_addr`, `func_name`, `callee_addr`, `callee_name` |
| `string_refs` | code → string reference | `string_addr`, `string_value`, `string_length`, `ref_addr`, `func_addr`, `func_name` |

An edge is a **code** reference (so a tail call, which compiles to a jump,
counts) whose target is a function **or an import** — in radare2 an import is
not a function, and calls into imports are usually what you are looking for.
The `*_name` columns never return NULL; an unresolvable name falls back to
`sub_<ADDR>`. References belonging to no function are excluded.

```sql
-- who calls this function, by name
SELECT caller_name, printf('0x%x', caller_addr) FROM callers WHERE func_addr = 0x401000;

-- what it calls, imports included
SELECT callee_name FROM callees WHERE func_addr = 0x401000;

-- which functions touch a suspicious string
SELECT DISTINCT func_name, string_value FROM string_refs
WHERE string_value LIKE '%password%';

-- API usage by function, in one join
SELECT c.func_name, c.callee_name
FROM callees c JOIN imports i ON i.addr = c.callee_addr
WHERE i.name LIKE 'Crypt%';
```

### Search

#### `grep` (read-only)
A composite over `funcs`, `flags`, `imports`, `entries`, `sections`,
`comments` — search named entities of every kind in one query.

| Column        | Type  | Notes                                            |
|---------------|-------|--------------------------------------------------|
| `kind`        | TEXT  | `func` / `flag` / `import` / `export` / `section` / `comment` |
| `name`        | TEXT  | short name                                       |
| `full_name`   | TEXT  | qualified name                                   |
| `parent_name` | TEXT  | namespace / flagspace / library                  |
| `addr`        | INT64 | address (`0` if not location-bound)              |
| `pattern`     | TEXT  | **input-only** pseudo-column                     |

`pattern` filters by `name`/`full_name`: a value with no `%`/`_` is a
case-insensitive substring; with `%`/`_` it's an anchored SQL-`LIKE` glob.

```sql
-- everything mentioning "decrypt"
SELECT kind, name, printf('0x%x', addr) AS at FROM grep WHERE pattern = '%decrypt%';

-- only function symbols starting with "fcn."
SELECT kind, name FROM grep WHERE pattern = 'fcn.%' AND kind = 'func';

-- match counts by kind
SELECT kind, COUNT(*) AS n FROM grep WHERE pattern = '%http%' GROUP BY kind;
```

#### `entities` (read-only view)
A thin projection of `grep` under the name the sibling analysis tools (idasql/
bnsql/ghidrasql) use for "every named thing, classified" — same rows, same
`kind`/`name`/`full_name`/`parent_name`/`addr` columns, minus the input-only
`pattern` pseudo-column (use `grep` directly for the pattern pushdown).

**Deviation, not a family standard — read this before assuming portability.**
`kind` here is r2xsql's OWN, already-shipped vocabulary — `func` / `flag` /
`import` / `export` / `section` / `comment` — the exact same values `grep`
emits. It is **not** any sibling tool's `kind` spelling for their own
`entities`-shaped surface, and no vocabulary has been agreed across the tool
family yet. This view exists so a query that expects a table *named*
`entities` finds one; it does **not** mean `WHERE kind = 'function'` (or
`symbol`/`segment`/`string`/`type`) written against another tool in this
family will match anything here — those spellings return zero rows. Always
use r2xsql's own values (`WHERE kind = 'func'`, not `'function'`).

```sql
-- every named entity, r2xsql's own classification
SELECT kind, name, addr FROM entities ORDER BY kind, name;

-- functions only, using r2xsql's spelling (NOT 'function')
SELECT name, addr FROM entities WHERE kind = 'func';
```

For pattern-filtered lookups (`WHERE pattern = '...'`), query `grep` directly
— `entities` does not carry that pseudo-column.

#### `byte_search` (read-only)
Canonical cross-tool byte-pattern search (matches idasql/bnsql/ghidrasql). Backed
by r2's `/xj <hex>`. **Requires** `WHERE pattern = '<r2 hex pattern>'` — a bare scan
errors (`matched_hex` is an output column, not the input). Optional bounds via the
hidden `start_addr`/`end_addr`/`max_results` columns or an `addr` range predicate.

| Column          | Type  | Notes                                              |
|-----------------|-------|----------------------------------------------------|
| `addr`          | INT64 | match address                                      |
| `matched_hex`   | TEXT  | matched bytes, spaced lowercase (e.g. `48 89`)     |
| `matched_bytes` | BLOB  | matched bytes                                      |
| `size`          | INT   | match length                                       |
| `pattern`       | TEXT  | *hidden input* — r2 `/x` hex (`4889`, wildcards ok)|
| `start_addr`, `end_addr`, `max_results` | INT | *hidden inputs* — optional bounds / cap |

```sql
-- find a byte pattern, first 10 hits
SELECT printf('0x%x', addr) AS at, matched_hex FROM byte_search
WHERE pattern = '4889' AND max_results = 10;

-- bounded to a range
SELECT addr FROM byte_search
WHERE pattern = 'cccc' AND start_addr = 0x401000 AND end_addr = 0x402000;

-- search_first(pat): first match only. max_results = 1 (not just LIMIT 1)
-- skips the N+1 full-match re-read for every hit after the first -- this
-- table collects the whole result set in its generator's constructor before
-- any row is returned, so LIMIT 1 alone still pays that cost for every hit.
SELECT addr, matched_hex, size FROM byte_search
WHERE pattern = '4889' AND max_results = 1;
```

#### `assemble` (read-only)
One row per query: encodes an assembly-mnemonic string to bytes via `pa`.
Verified against the current radare2 source (`cmd_print.inc.c`'s `cmd_pa`) —
no JSON mode exists for `pa` (`paj` is not a real subcommand: it parses as
`pa` with asm text `"j ..."`), and radare2 prints **nothing to stdout** on a
bad mnemonic (its "Cannot assemble '<asm>' at line 1" diagnostic is
stderr-only) — a failed assemble reads back as an empty `hex` with a
populated `error`, never as a SQL error.

| Column | Type | Notes                                                      |
|--------|------|-------------------------------------------------------------|
| `hex`  | TEXT | assembled bytes, lowercase hex (empty iff assembly failed) |
| `bytes`| BLOB | same bytes, decoded                                        |
| `size` | INT  | byte length                                                |
| `error`| TEXT | empty iff `hex` is non-empty                               |
| `asm`  | TEXT | *hidden input* — the mnemonic to assemble (required)       |
| `addr` | INT64| *hidden input* — encode as if placed here (default 0); matters for pc-relative instructions (`pa` calls `r_asm_set_pc(core->rasm, core->addr)` before assembling) |

```sql
SELECT hex, size FROM assemble WHERE asm = 'mov eax, 1';
SELECT hex FROM assemble WHERE asm = 'jmp 0x401010' AND addr = 0x401000;
```

`asm` is charset-validated (letters, digits, space, and
`,.+-*/[]():%#_$`) BEFORE it is ever spliced into a command — real assembly
text never needs `;`/`@`/`|`/backtick/quotes, so this alone makes the
argument injection-safe; `Backend::cmd_noeval` is layered on top for
defense-in-depth on the libr backend (same "wired in anyway, not because a
real gap was found here" posture `patches`' `wx` write already has).

#### `search_asm` (read-only)
Assembles `asm` and searches for the resulting bytes via the plain
(non-JSON) `/a <asm>` command. **`/aj <asm>` is NOT this command's JSON
form** — verified live: appending `j` right after `/a` misroutes to the
UNRELATED `/at` (search-by-instruction-**type**) family instead (`/aj push
rbp` returns `{"cmd":"/atj","arg":"push rbp","result":[]}`; `/aj mov rdi,
rsi` matches by TYPE "mov", never assembling the literal text at all) — a
real radare2 command-dispatch collision, not a bug in this table. So this
table parses the plain-text `<hex addr> <hitN_M> <hex bytes>` line format
instead (confirmed stable across single- and multi-byte matches).

| Column        | Type  | Notes                                          |
|---------------|-------|--------------------------------------------------|
| `addr`        | INT64 | match address                                   |
| `matched_hex` | TEXT  | matched bytes, contiguous lowercase hex          |
| `asm`         | TEXT  | *hidden input* — the mnemonic to assemble-and-search (required) |
| `max_results` | INT64 | *hidden input* — client-side cap                |

```sql
SELECT printf('0x%x', addr) AS at, matched_hex FROM search_asm
WHERE asm = 'push rbp' AND max_results = 20;
```

Sets `search.in=io.maps.x` for the duration of its own search and restores
`io.maps` afterward, in ONE `Backend::cmd()` call — the same atomic
set/search/restore idiom `rop_gadgets` uses, and for the same reason
(`search.in` is session-global config that leaks past the command that set
it, shared across concurrent interactive callers). Does **not** use
`Backend::cmd_noeval` — the atomic three-command chain is structurally
incompatible with cmd_noeval's single no-eval-command dispatch, so `asm`'s
charset allowlist (same validator as `assemble`) is what makes this safe on
its own, the identical trade-off `rop_gadgets` already made for its own
`pattern` input. Command-path only; pair-tested identical on both backends
(11/11 hits for `asm = 'push rbp'` against the same fixture on pipe and
libr).

#### `demangle` (read-only)
One row per query: demangles an ARBITRARY mangled name via `iD`/`iDj`.
Distinct from `funcs.name`/`imports.name`, which already demangle
automatically (gated on `bin.demangle`) for symbols radare2 already knows
from the loaded binary — `demangle` answers the same question for a string
that isn't necessarily any table's row.

| Column      | Type | Notes                                                  |
|-------------|------|----------------------------------------------------------|
| `demangled` | TEXT | empty iff demangling failed (a real symbol is never legitimately empty) |
| `error`     | TEXT | empty iff `demangled` is non-empty                        |
| `mangled`   | TEXT | *hidden input* — the mangled name (required)               |
| `lang`      | TEXT | *hidden input*, optional — always ADVISORY (see caveat)    |

```sql
SELECT demangled FROM demangle WHERE mangled = '_ZN3Foo3barEv';
SELECT demangled, error FROM demangle WHERE mangled = '?foo@@YAHXZ' AND lang = 'msvc';
```

`lang` never gates the call: `r_bin_demangle` auto-detects the actual
demangler from the mangled text's OWN prefix (`_Z`/`__Z`/`?`/…) regardless of
what `lang` says — verified live that an unrecognized `lang` string does not
abort demangling, it just falls through to auto-detection. `mangled` is NOT
charset-restricted the way `assemble`/`search_asm`'s `asm` is: MSVC manglings
use `?`/`@`/`$` throughout, which a disassembly-text allowlist would reject.
Instead this table dispatches through `Backend::cmd_noeval`, seeked to a
fixed anchor (0, unobserved by `iD`'s handler either way — same shape as
`types`' addr-less `td`/`t-` dispatch), falling back to the
`json_utils::r2_quote`-wrapped plain command on every backend that reports
cmd_noeval unsupported. Verified live that the injection risk is real: `iDj
cxx foo; ?e INJECTED` spliced through a plain `Backend::cmd()` call DOES
execute the injected `?e` as a second command, while `cmd_noeval` reaches
`iD`'s argument parser with the whole string, `;` included, treated as
opaque data.

#### Point-lookup recipes: `name_at` / `section_at` / `string_at`

These three are NOT tables — each convenience point-lookup resolves to a
plain `WHERE` against an existing table, verified live against a real
fixture rather than assumed:

```sql
-- name_at(addr): every flag (radare2's own name table) at an address.
-- MULTI-ROW: radare2's flags are not single-valued per address (a symbol
-- and a register can legitimately share one, e.g. entry0 + rip on a
-- 64-bit PE) -- filter on namespace to disambiguate.
SELECT name, namespace FROM names WHERE addr = 0x140001d70;
SELECT name FROM names WHERE addr = 0x140001d70 AND namespace = 'symbols';

-- section_at(addr): the section containing an address (range containment).
SELECT name FROM sections WHERE start_addr <= 0x140001d70 AND end_addr > 0x140001d70;

-- string_at(addr): the detected string starting exactly at an address.
-- Only matches a `strings` row's own START address -- see read_cstr below
-- for an arbitrary (e.g. mid-string) address `strings` has no row for.
SELECT content FROM strings WHERE addr = 0x1400173f0;
```

#### `read_cstr` (read-only)
One row per query: reads a null-terminated string starting at an
**arbitrary** address via `pszj`, NOT limited to addresses `strings`'
detection heuristics (`izj`) already flagged. This is genuinely different
from `string_at` above:
`strings` only has a row at a detected string's own START address, so a
mid-string offset, a string radare2's heuristics never flagged, or any other
caller-chosen address has no `strings` row to find at all. Confirmed live on
a 64-bit PE: the detected string at `0x1400173f0` ("press any key to
exit...\n") has ZERO `strings` rows at `addr+6` (`0x1400173f6`), but
`read_cstr` resolves the tail ("any key to exit...\n") there directly.

| Column      | Type  | Notes                                                    |
|-------------|-------|-----------------------------------------------------------|
| `content`   | TEXT  | the string up to the first NUL found within `max_len` (may legitimately be empty) |
| `length`    | INT64 | bytes consumed before the NUL, or `max_len` if none was found |
| `section`   | TEXT  | containing section name, or `"unknown"`                   |
| `type`      | TEXT  | `ascii` / `wide` / `utf` / `unknown` (radare2's own classification) |
| `truncated` | INT   | `1` iff `length = max_len` — no NUL found in the scanned window |
| `error`     | TEXT  | non-empty iff this row carries no usable result            |
| `addr`      | INT64 | *hidden input* — the address to read from (required)      |
| `max_len`   | INT64 | *hidden input*, optional — read window, default 128 (matches `pso`'s own one-shot default; NOT `core->blocksize`, which is session-mutable ambient config) |

```sql
SELECT content, length FROM read_cstr WHERE addr = 0x1400173f6;
SELECT content, truncated FROM read_cstr WHERE addr = 0x401000 AND max_len = 512;
```

`max_len = 0` is rejected client-side before any command is issued —
verified against the current radare2 source that `pszj`'s whole body is
gated `else if (l > 0)`, so an explicit `0` prints nothing at all. `truncated
= 1` means only "no NUL found inside the scanned window" — it does NOT by
itself distinguish "this string is genuinely longer than max_len" from "this
address was never mapped/meaningful in the first place": confirmed live at
address 0 that an out-of-range/unmapped read still returns a FULL
`max_len`-byte string of radare2's own unmapped-fill byte, with
`section = "unknown"` and `type = "unknown"` — the same three-field
combination a genuinely long, un-terminated run of printable bytes would
also produce. This table does not guess at an `is_mapped` check to
disambiguate (same "don't guess" posture as the syscall-resolution refusal)
— cross-check `bytes` for a stronger mapped/unmapped guarantee. `max_len`
is a plain validated integer with no free-text argument anywhere on this
table's surface, so there is no charset-allowlist injection surface to
defend (unlike `assemble`/`demangle`); `Backend::cmd_noeval` is still wired
in for defense-in-depth and consistency with every other address-scoped
read on the libr backend. Command-path only, identical on both backends (one
full-scan-equivalent command, no C-API producer needed).

### Exploitation

#### `rop_gadgets` / `rop_gadget_instructions` (read-only)
ROP/JOP/COP gadget search, backed by r2's `/g` gadget-search family. Two
tables, family-conventional parent/child: `rop_gadgets` is one summary row
per gadget; `rop_gadget_instructions` is one row per constituent instruction,
keyed back by `gadget_addr`. No predicate is required on either table — an
unfiltered scan is a real, bounded answer (a few hundred ms on a typical
binary), scoped by default to executable memory only (`io.maps.x`, **not**
r2's own CLI default of `io.maps`, which also matches non-code data).

`rop_gadgets`:

| Column     | Type  | Notes                                                |
|------------|-------|-------------------------------------------------------|
| `addr`     | INT64 | address of the gadget's first instruction              |
| `retaddr`  | INT64 | address of the gadget's own *terminating* instruction — **not** a resolved branch target (r2's field name is misleading) |
| `size`     | INT64 | total byte length (sum of every instruction's size)     |
| `classes`  | TEXT  | comma-joined r2 gadget-klass vocabulary (e.g. `ret,pivot,mov,ldconst,arithm,arithm_ct`) — free, always computed |
| `ninstrs`  | INT64 | instruction count                                       |
| `pattern`  | TEXT  | *hidden input* — opstring substring match (validated before use) |
| `terminator` | TEXT | *hidden input* — `ret` / `call` / `jmp` / `any` (default), selects `/gRj`/`/gCj`/`/gJj`/`/gj` |
| `klass`    | TEXT  | *hidden input* — one of r2's own klass names (see below); matched client-side against `classes`, never issues `/gk` (see caveats) |
| `max_results` | INT | *hidden input* — client-side cap on result count      |

`klass` vocabulary (r2's own, used verbatim — never invent a parallel one):
`ret`, `jop`, `cop`, `cond.always`, `cond.controlled`, `syscall`, `pivot`,
`memread`, `memwrite`, `www`, `rww`, `signal`, `mov`, `ldconst`, `arithm`,
`logic`, `shift`, `cmp`, `nop`, `arithm_ct`.

`rop_gadget_instructions`:

| Column        | Type  | Notes                                              |
|---------------|-------|------------------------------------------------------|
| `gadget_addr` | INT64 | FK to `rop_gadgets.addr`                              |
| `seq`         | INT64 | 0-based ordinal within the gadget, address order      |
| `addr`        | INT64 | this instruction's address                            |
| `size`        | INT64 | this instruction's byte length                        |
| `opcode`      | TEXT  | rendered disassembly text (same renderer as `instructions.disasm`) |
| `type`        | TEXT  | r2's own op-type classification (same vocabulary as `instructions.op_type`) |
| `pattern`, `terminator`, `klass`, `max_results` | | *hidden inputs* — same meaning as on `rop_gadgets` |

```sql
-- every return-terminated gadget mentioning "pop"
SELECT printf('0x%x', addr) AS at, classes, ninstrs FROM rop_gadgets
WHERE terminator = 'ret' AND pattern = 'pop';

-- gadgets that pivot the stack
SELECT printf('0x%x', addr) AS at, retaddr, classes FROM rop_gadgets
WHERE klass = 'pivot';

-- drill into one gadget's instructions (same filters on both sides —
-- see the caveat below on why an unfiltered/differently-filtered join
-- across the two tables is not reliable)
SELECT seq, printf('0x%x', addr) AS at, opcode, type FROM rop_gadget_instructions
WHERE gadget_addr = 0x140001284 AND terminator = 'ret' ORDER BY seq;
```

**Caveats:**
- `klass` is **not** implemented via `/gkj`: that command queries a separate,
  disabled-by-default (`gadget.sdb`, off), differently-shaped cache, not a
  live search — using it would need a second leaking global config and
  wouldn't have the `opcodes` data this table needs anyway. `klass` instead
  filters the already-free `classes` field from a normal search.
- **The unfiltered ("any" terminator) gadget set is not a strict superset of
  a terminator-filtered one, address for address** — r2's gadget construction
  walks backward from qualifying end instructions and marks consumed start
  bytes per pass, so a start address one search finds is not guaranteed to
  also start a gadget in a differently-filtered pass. A query that joins
  `rop_gadgets` and `rop_gadget_instructions` (or compares results across
  two separate queries) must apply the **same** `pattern`/`terminator`/
  `klass` values to both, or the results will not correspond.
- A JOIN across MANY `rop_gadgets` rows at once (e.g. every gadget's
  instructions in one statement) re-runs the underlying search once per
  outer row — there is no r2 primitive that resolves a single gadget by
  address, so neither table can push an address-equality join down. Prefer
  querying `rop_gadget_instructions` directly with the filters you want (it
  already carries `gadget_addr`) over joining it against many `rop_gadgets`
  rows.

#### `syscalls` (read-only)
A **static** per-`(arch,bits,cpu,os)` syscall name/number reference table,
backed by `asj` (**not** `aslj` — that command does not exist). This is a
lookup dictionary keyed purely by the current target's architecture/OS —
**not** a per-binary occurrence list and **not** derived from the binary's
bytes at all. It answers "what is syscall number 60 called on this target",
not "which syscalls does this binary actually make" (see the caveat below
for that question). No predicate is required or useful — the whole table is
small (hundreds of rows) and one `asj` call away; there is no pushdown to
speak of.

| Column | Type  | Notes                                                    |
|--------|-------|-----------------------------------------------------------|
| `name` | TEXT  | syscall name (`write`, `exit`, `NtCreateFile`, …)         |
| `num`  | INT64 | syscall number for this target's `(arch, bits, os)`       |
| `arch` | TEXT  | echoes `asm.arch` at query time (informational — the table is already scoped to the current session's single target) |
| `os`   | TEXT  | echoes `asm.os` at query time                              |

```sql
-- look up a syscall by number
SELECT name FROM syscalls WHERE num = 60;

-- look up a syscall's number by name
SELECT num FROM syscalls WHERE name = 'write';
```

**Caveats:**
- **"Where are the syscall instructions in this binary" is a different
  question, already answered for free** — see `instructions WHERE op_type =
  'swi'` above. Nothing here needs to be joined to `instructions` to answer
  that; `syscalls` only ever tells you what a number/name means for the
  current target, never where a syscall site is.
- **"Which syscall does a specific `swi` instruction make" is explicitly NOT
  supported.** radare2's own static emulation cannot reliably resolve the
  syscall number at a call site in realistic compiler-generated code (the
  number is typically set in a caller and reloaded across a function-call
  boundary into a syscall wrapper, which single-function emulation cannot
  follow) — resolving it would require new interprocedural analysis this
  project does not build, and a column that is sometimes right and silently
  wrong on failure is worse than no column at all. Do not attempt to derive
  this by joining `syscalls` to `instructions`/`esil_ops`; there is no
  reliable value to join on.

### Decompiler

#### `pseudocode` (read-only, runtime-gated)
Registered **only** when a decompiler is detected at session start. **Always
filter by `func_addr`** (pushdown to `<decompiler> @ X`).

| Column      | Type  | Notes                          |
|-------------|-------|--------------------------------|
| `func_addr` | INT64 | function to decompile          |
| `text`      | TEXT  | decompiled C-like pseudocode   |

```sql
-- pseudocode for one function
SELECT text FROM pseudocode WHERE func_addr = 0x401000;

-- decompile functions matching a name (bounded set!)
SELECT f.name, p.text
FROM funcs f JOIN pseudocode p ON p.func_addr = f.addr
WHERE f.name LIKE 'aes_%';
```

### Types

#### `types` (writable: DELETE, INSERT)
Source `tk*` enriched with `tj` / `tsj` / `tuj`.

| Column    | Type  | Notes                                                            |
|-----------|-------|------------------------------------------------------------------|
| `ordinal` | INT64 | read-only, 0-based position in the name-sorted row set — a plain running counter, not a persistent per-type identity (see below) |
| `name`    | TEXT  | fully qualified type name                                        |
| `kind`    | TEXT  | `atomic` / `struct` / `union` / `enum` / `typedef` / `func` / `type` |
| `size`    | INT64 | byte size; `-1` for unsized/opaque/pointer-like                  |
| `format`  | TEXT  | radare2 `pf` format string when applicable                       |

`ordinal` is recomputed on every query (this table has no cross-query cache,
since the type database is mutable): it agrees for a given name across two
queries only while the type set is unchanged in between — an intervening
INSERT/DELETE/`r2xsql_type_define` shifts the alphabetical position of every
name that sorts after the change. Never derived from any address.

`DELETE FROM types WHERE name = 'X'` ⇒ `t- X`.
`INSERT INTO types (name, kind) VALUES ('X', 'struct')` creates an **empty**
struct/union/enum shell (`kind` must be one of those three — an atomic type,
typedef, or func needs more than a bare name to exist). For a **full**
declaration (members, an underlying primitive, a signature), use
`r2xsql_type_define('<one-line C decl>')`, which the empty-shell INSERT is
itself built on.

Neither `td` nor `t-` is address-scoped (a type definition isn't tied to any
address, and `t-` deletes purely by name) — unlike every other writable
table's commands, which are anchored on a real row address. On the in-process
(libr) backend both still dispatch through the structural no-eval path
(`Backend::cmd_noeval`), seeked to a fixed anchor address (0) instead of a row
address, since neither command ever consults the current seek. This is the
same additional, structural layer every other writable table's commands get
— on top of, never instead of, the existing name/declaration validation
below; the pipe backend is unaffected.

```sql
SELECT name, kind, size FROM types WHERE kind = 'struct' ORDER BY size DESC LIMIT 20;
INSERT INTO types (name, kind) VALUES ('Header', 'struct');
SELECT r2xsql_type_define('struct hdr { int magic; int size; char name[16]; }');
```

The full type set (e.g. the thousands of Windows API typedefs) lives in
radare2's `share/fcnsign/types-*.sdb`. The **r2pipe** backend always loads it.
The **libr** backend (`r2xsql-full`) loads it only when run from radare2's `bin/`
directory; otherwise `types` collapses to a few built-ins (r2xsql warns).

#### `types_members` (read-only)
Per-type `tsj` / `tuj` / `tej`.

| Column        | Type  | Notes                                            |
|---------------|-------|--------------------------------------------------|
| `type_name`   | TEXT  | parent type name                                 |
| `parent_kind` | TEXT  | `struct` / `union` / `enum`                       |
| `member_name` | TEXT  | field name (struct/union) or constant (enum)     |
| `member_type` | TEXT  | field type; empty for enum constants             |
| `offset`      | INT64 | byte offset (`0` for union/enum)                 |
| `size`        | INT64 | element size (`0` for enum constants)            |
| `array_size`  | INT64 | `1` scalar, `N` for `T[N]`, `0` for enum const   |
| `value`       | INT64 | enum constant value (`0` for struct/union)       |

```sql
SELECT member_name, member_type, offset, size
FROM types_members WHERE type_name = 'IMAGE_DOS_HEADER' ORDER BY offset;
```

### C++ Classes / Vtables (RTTI)

#### `classes` / `class_methods` (read-only)
C++ class/vtable/RTTI recovery, backed by radare2's **anal-side** class
database (`aclj` — **not** `icj`, and **not** `acj`). This is a genuinely
different concept from `icj`/`RBinClass`: that command reads bin-format class
tables (Java `.class`, Objective-C, .NET) populated at load time by the
matching bin plugin, and is **structurally empty for every native PE/ELF
binary regardless of content** — never use it for C++ class recovery. There
is also no `acj` command; the JSON list verb is `aclj` (`ac` + `l` + `j`).

The anal-side class database is populated by `avrr` (vtable search + MSVC/
Itanium RTTI parsing), which radare2's own `aaa` already runs **once**,
internally, at file-open/analysis time. **`avrr` is confirmed NOT
idempotent** — a second explicit call duplicates every already-recovered
class under a `_1`-suffixed name (`Animal` → `Animal`, `Animal_1`, …). r2xsql
never issues `avrr` (or the raw `av` vtable search) itself, on any code path
— these two tables only ever read whatever `aaa` already recovered, via
`aclj`. If a session's `aaa` has not run yet, both tables read as **honestly
empty**, never a trigger to recover anything.

`classes`:

| Column        | Type  | Notes                                                |
|---------------|-------|-------------------------------------------------------|
| `name`        | TEXT  | class name, as RTTI reports it — demangled (`Dog`) or still-mangled, depending on RTTI coverage |
| `base_name`   | TEXT  | **first** direct base class name, or `NULL` for a root class — see the multiple-inheritance caveat below |
| `vtable_addr` | INT64 | address of this class's own vtable, or `NULL`         |

`class_methods`:

| Column          | Type  | Notes                                             |
|-----------------|-------|------------------------------------------------------|
| `class_name`    | TEXT  | FK to `classes.name`                                  |
| `name`          | TEXT  | method name                                          |
| `addr`          | INT64 | method address                                        |
| `vtable_offset` | INT64 | offset within the vtable, or `NULL` for a non-virtual method the recovery still attributed to the class |

```sql
-- every recovered class and its direct base
SELECT name, base_name FROM classes ORDER BY name;

-- a class hierarchy's virtual methods, in vtable-slot order
SELECT name, printf('0x%x', addr) AS at, vtable_offset
FROM class_methods WHERE class_name = 'Dog' ORDER BY vtable_offset;

-- join to see every class with its method count
SELECT c.name, c.base_name, COUNT(m.name) AS n_methods
FROM classes c LEFT JOIN class_methods m ON m.class_name = c.name
GROUP BY c.name ORDER BY c.name;

-- filter out CRT-internal noise client-side (see caveat)
SELECT name, base_name FROM classes
WHERE name NOT LIKE 'std::%' AND name <> 'type_info';
```

**Caveats:**
- **Uncurated by design.** Every class `aclj` reports is visible here,
  including CRT-internal recoveries from a statically-linked runtime
  (`type_info`, `std::exception`, `std::bad_alloc`, `std::bad_array_new_length`,
  …). This mirrors how the family-shared `names` view stays uncurated — r2xsql
  does not invent a curation boundary radare2 itself does not draw. Filter
  client-side (`WHERE name NOT LIKE 'std::%' AND name <> 'type_info'`, etc.)
  if you only want a program's own classes.
- **Multiple inheritance is not fully modeled.** `base_name` is a single
  nullable column holding only the *first* direct base from `aclj`'s
  `bases[]` array. A class with more than one direct base loses every base
  past the first from this column — not corrupted (the first base is
  correct), just narrower than the raw data. There is no `classes_bases`
  junction table in this version.
- **Itanium (GCC/Clang, ELF) recovers materially less than MSVC — measured.**
  Same C++ source, same radare2 6.1.7, compiled both ways: MSVC/PE gives 3
  classes with `Dog`→`Animal` and `Bird`→`Animal` base links and 3 methods
  each; Itanium/ELF gives only **2 classes** (the abstract base `Animal` is
  missing), **no `base_name` links at all**, and 4 methods each. This is
  radare2's `avrr` recovery, not an r2xsql defect — both backends agree with
  each other on both platforms. On GCC/Clang targets: **do not rely on
  `base_name` to reconstruct a hierarchy, and do not treat a missing class as
  proof it is absent**; cross-check `vtable_addr` and raw `acllj`. MSVC
  targets carry the full ground truth.
- **Never issue `avrr`/`av` yourself via raw command passthrough while
  expecting `classes`/`class_methods` to stay correct** — that duplication
  bug is real and lives in radare2 itself, not something r2xsql can prevent
  once you're driving `avrr` directly.

### Registers, Relocations & Libraries

#### `registers` (read-only)
A **static** per-`(arch,bits)` register PROFILE reference table — which
registers this target's architecture defines, their name/size/bit-offset/kind
— backed by `arpj`. **Not** `arj`: that command exists too, but it reports
LIVE register VALUES (`{"rax":0,"rbx":0,...}`), which read as all-zero on
every target, because r2xsql is a static-analysis tool — it never runs the
binary, so there is no CPU state to report. `registers` answers "what
registers does this architecture have and how are they shaped", never "what
is currently in `rax`". No pushdown — the whole profile is small (~130-140
rows on a real x86-64 target) and one `arpj` call away; it also has **no
data-dir dependency** (the profile is compiled into the arch plugin itself,
unlike `types`/`syscalls`/`calling_conventions`).

| Column   | Type  | Notes                                                        |
|----------|-------|----------------------------------------------------------------|
| `name`   | TEXT  | register name (`rax`, `eax`, `xmm0`, …)                        |
| `type`   | TEXT  | register kind: `gpr` / `fpu` / `flg` / `seg` / `drx` / `vec128` / … |
| `size`   | INT64 | width in **bits**                                              |
| `offset` | INT64 | bit offset within radare2's internal per-type register arena — **not a memory address** |
| `role`   | TEXT  | comma-joined alias role(s) this register serves (`PC`, `SP`, `BP`, `A0`-`A7`, `R0`, `SN`, …), or NULL if it has none — a register can carry more than one role at once (e.g. x86-64's `rax` is both `R0` and `SN`) |
| `arch`   | TEXT  | echoes `asm.arch` at query time (informational)                |
| `bits`   | TEXT  | echoes `asm.bits` at query time (informational)                |

```sql
-- the stack pointer and program counter, whatever they're called on this arch
SELECT name, size FROM registers WHERE role LIKE '%SP%';
SELECT name, size FROM registers WHERE role LIKE '%PC%';

-- every general-purpose register width
SELECT name, size FROM registers WHERE type = 'gpr' ORDER BY size DESC;

-- the argument-passing registers, arch-agnostic
SELECT name, role FROM registers WHERE role LIKE '%A_%' OR role LIKE 'A%' ORDER BY role;
```

**Caveats:**
- **Not a live-debugger surface.** There is no companion "set a register
  value" write path, and none is planned — r2xsql analyzes, it does not
  execute.
- **The dedupe some other tools' register enumeration needs does not apply
  here.** `arpj`'s own emission is already partitioned one register per
  type, so no register name ever appears twice in this table.

#### `relocs` (read-only)
The binary's relocation table, backed by `irj`.

| Column      | Type  | Notes                                                    |
|-------------|-------|------------------------------------------------------------|
| `addr`      | INT64 | relocation's virtual address                             |
| `paddr`     | INT64 | relocation's file offset                                  |
| `type`       | TEXT  | rendered `SET_<width>` / `ADD_<width>` / `UNKNOWN` (width ∈ {1,2,4,8,16,24,32,48,64}) — **not** a raw enum |
| `ntype`     | INT64 | raw, **format-specific** relocation type code (PE `IMAGE_REL_BASED_*`, ELF `R_<arch>_*`, …) — its vocabulary depends on the target's own file format/architecture, not a portable r2xsql enum |
| `name`      | TEXT  | the import's or symbol's name this reloc targets, or NULL |
| `demname`   | TEXT  | `name` demangled, or NULL when there's nothing to demangle or no name at all |
| `sym_vaddr` | INT64 | the resolved symbol's own address, only when this reloc targets a genuine symbol (as opposed to an import); NULL otherwise |
| `is_ifunc`  | INT   | 1 if this is a GNU IFUNC resolver relocation (ELF-only mechanism) |

```sql
-- every reloc that patches in a named import (a real PE's IAT fixups)
SELECT printf('0x%x', addr) AS at, name, type FROM relocs WHERE name IS NOT NULL;

-- reloc width distribution
SELECT type, COUNT(*) AS n FROM relocs GROUP BY type ORDER BY n DESC;
```

**Caveats:**
- **No `addend` column.** The underlying C struct has one, but `irj`'s own
  JSON never emits it, and this table is command-path-only (no C-API
  producer) — adding it would read NULL forever rather than the real value.
- `demname`/`sym_vaddr`/`is_ifunc = 1` are real fields in `irj`'s emission
  but were not observed non-trivially on any Windows PE fixture available
  when this table was built (pure-import PE relocation tables, C linkage
  only) — don't assume they're dead columns, just that they're unexercised
  here.

#### `libs` (read-only)
The binary's linked/imported library list, backed by `ilj` — a bare list of
library names (`kernel32.dll`, `libc.so.6`, …), one column, matching the
actual command shape (no ordinal, load-order index, or resolved path exists
to surface).

| Column | Type | Notes                          |
|--------|------|---------------------------------|
| `name` | TEXT | linked/imported library name    |

```sql
SELECT name FROM libs ORDER BY name;
```

### Annotations (writable)

#### `flags` (writable)
Source `fj` (full dump) + one `fs <space>; fj; fs *` per flagspace on the
pipe-only flavor, to attribute radare2's real flagspace onto each flag by
name; `r2xsql-full` reads `r_flag_foreach` directly instead — identical rows,
the per-flagspace enumeration replaced by one pass with no `fs`
select/restore at all. Named addresses.

| Column     | Type  | Notes                          |
|------------|-------|--------------------------------|
| `addr`     | INT64 | address                        |
| `size`     | INT64 | flag size                      |
| `name`     | TEXT  | flag name (**writable**)       |
| `realname` | TEXT  | demangled / original name; empty unless radare2 actually gave the flag a distinct one |
| `space`    | TEXT  | radare2's real flagspace — `imports`, `strings`, `functions`, `relocs`, `registers`, `sections`, … NOT the flag name's prefix: `sym.imp.X` is in `imports`, `str.X` in `strings`, and `fcn.*`/`sub.*` are both `functions`. Empty when radare2 puts the flag in no space |

```sql
INSERT INTO flags (addr, name) VALUES (0x401000, 'aes_sbox');     -- f
UPDATE flags SET name = 'aes_init' WHERE addr = 0x401000;         -- fr
DELETE FROM flags WHERE addr = 0x401000;                          -- f-
```

INSERT (`f`) and DELETE (`f-`) are address-scoped, so on the in-process (libr)
backend both dispatch through the same structural no-separator-evaluating
command path `comments`/`funcs` writes already use — a second, independent
layer beneath the name validation above. `name`'s rename calls radare2's C API
directly on `r2xsql-full` (`r_flag_get` + `r_flag_rename`, no address needed
at all — measured 48-62x over `fr` on a bulk-rename workload, exact parity);
the pipe backend still issues `fr` (seeked to the flag's own address, which
`fr` never consults — a harmless anchor, not an input into the rename).

#### `comments` (writable)
Source `CCj` on the pipe-only flavor; `r2xsql-full` reads radare2's meta
interval tree directly instead — identical rows (a single full-scan command,
not a per-function loop, so the win is skipping a json round trip).

| Column | Type  | Notes                          |
|--------|-------|--------------------------------|
| `addr` | INT64 | address                        |
| `type` | TEXT  | always the literal string `CCu` (radare2's own comment-type tag; not a description of the comment) |
| `text` | TEXT  | comment text (**writable**); a newline/tab/quote/backslash or non-ASCII byte reads back escaped (e.g. a real newline as the two characters `\n`) |

```sql
INSERT INTO comments (addr, text) VALUES (0x401000, 'crypto init');  -- CCu base64:
UPDATE comments SET text = 'crypto init v2' WHERE addr = 0x401000;   -- CCu base64:
DELETE FROM comments WHERE addr = 0x401000;                          -- CC-
```

On `r2xsql-full`, `text`'s set/update calls `r_meta_set_string` directly
(measured 30-40x over `CCu` on a bulk-set workload, exact parity) — including
reproducing `CCu`'s own dedup quirk: a write whose new text is already a byte
substring of the EXISTING comment is silently skipped (no-op), matching
production behavior on both flavors. The pipe backend still sends
`CCu base64:<b64>`, so spaces, quotes, and `@` are stored verbatim and cannot
inject extra radare2 commands; on the in-process backend that same
base64-encoded command path remains the fallback whenever the C-API leg is
unavailable, additionally dispatched through a structural
no-separator-evaluating command path so a `;`/`@`/`|`/backtick in the argument
can never chain into a second command even in principle.

#### `bookmarks` (writable)
Flags inside a dedicated `bookmarks` flagspace; every write saves/restores the
active flagspace so other spaces are untouched.

| Column | Type  | Notes                          |
|--------|-------|--------------------------------|
| `id`   | INT64 | synthetic id (ignored on write)|
| `addr` | INT64 | address                        |
| `name` | TEXT  | bookmark name (**writable**)   |

```sql
INSERT INTO bookmarks (addr, name) VALUES (0x401000, 'loop_start');  -- f (bookmarks space)
UPDATE bookmarks SET name = 'loop_head' WHERE addr = 0x401000;       -- fr
DELETE FROM bookmarks WHERE addr = 0x401000;                          -- f-
```

INSERT (`f`) and DELETE (`f-`) are address-scoped, so on the in-process (libr)
backend both dispatch through the same structural no-separator-evaluating
command path `comments`/`funcs`/`flags` writes already use — a second,
independent layer beneath the name validation above and the flagspace
save/select/restore. `name`'s rename (`fr`) carries no address in its own
grammar at all (same as `flags`' rename), but still gets the same dispatch:
seeked to the bookmark's own address first, which `fr` never consults, so
that seek is a harmless anchor, not an input into the rename. The pipe
backend is unaffected on all three writes: it always uses the plain command
form.

### Persistence

#### `projects` (writable: DELETE)
Source `Plj` — radare2's saved projects.

| Column | Type | Notes              |
|--------|------|--------------------|
| `name` | TEXT | saved project name |

```sql
SELECT name FROM projects;                       -- list
DELETE FROM projects WHERE name = 'old_triage';  -- P-  (delete on disk)
```

Saving/opening is an action, not a row — use the scalar functions below.

---

## Writable Tables & Mutation (CRUD)

r2xsql exposes create/update/delete wherever radare2 has a write verb and the
table is an editable annotation. Each affected row issues one radare2 command.

| Table       | INSERT             | UPDATE                       | DELETE        |
|-------------|--------------------|------------------------------|---------------|
| `funcs`     | `af @ <addr>` (+`afn`) | `name` ⇒ `afn <name> @ <addr>` (rename); `prototype` ⇒ `afs <sig> @ <addr>` (set-signature); `calltype` ⇒ `afc <cc> @ <addr>` (set calling convention) | `af- <addr>` (undefine) |
| `flags`     | `f <name> @ <addr>`| `name` ⇒ `fr <old> <new>` (in-place rename, any flagspace) | `f- @ <addr>` |
| `comments`  | `CCu base64:<b64> @ <addr>` | `text` ⇒ `CCu base64:<b64> @ <addr>` | `CC- @ <addr>` |
| `bookmarks` | `f <name> @ <addr>` (bookmarks space) | `name` ⇒ `fr <old> <new>` | `f- @ <addr>` |
| `locals`    | — | `name` ⇒ `afvn <new> <old>`; `type` ⇒ `afvt <name> <type>` | — |
| `types`     | `td "<kind> <name> {};"` (empty struct/union/enum shell only; a full declaration needs `r2xsql_type_define`) | — | `t- <name>`   |
| `projects`  | — (use `r2xsql_project_save`) | —                 | `P- <name>`   |
| `io_maps`   | `om $d <vaddr> <size> <paddr> <perm> <name>` (add region) | — | `om-<map_id>` (remove map) |
| `patches`   | `wx <hex> @ <addr>` (stage) — `patched_bytes` (raw hex) or `asm_text` (assembled via `pa` first, exactly one required) | `committed` ⇒ `1` only: `wci` (commits **ALL** pending patches, never row-selective — see the table's own section) | `wcu` (uncommitted **and** most-recently-staged row only) |
| `bytes`     | —                   | `value` ⇒ `wx <hex> @ <addr>`, **direct/immediate** — NOT staged, bypasses `io.cache` entirely (see the table's own section for how this differs from `patches`) | —             |
| `runtime_settings` | —          | `value` ⇒ UPDATE (validated) | —       |

All other tables and views (`binary`, `bininfo`, `blocks`, `cfg_edges`,
`switch_tables`, `function_frames`, `dominators`, `post_dominators`, `loops`,
`data_items`, `byte_search`, `instructions`, `instruction_operands`, `esil_ops`,
`esil_operands`, `ir_*`, `xrefs`, `strings`, `imports`, `entries`, `sections`,
`segments`, `grep`, `entities`, `pseudocode`, `types_members`, `rop_gadgets`,
`rop_gadget_instructions`, `syscalls`, `calling_conventions`, `classes`,
`class_methods`, `registers`, `relocs`, `libs`, `assemble`, `search_asm`,
`demangle`, `read_cstr`) are **read-only** — they
reflect file/analysis state, not user-editable rows. Writes to them are rejected.
(`runtime_settings` above only accepts an `UPDATE value`; `timeout_push`/
`timeout_pop` remain PRAGMA verbs. `bytes` above only accepts an `UPDATE
value`; `addr`/`is_initialized` are read-only, and there is no INSERT/DELETE.)

Rules and gotchas:

- **Name validation:** function / flag / bookmark / project names must match
  `[A-Za-z0-9._$]` — no spaces or radare2 metacharacters (prevents injection).
  Comment text has no such limit (it's base64-encoded).
- **Renames:** the obvious `UPDATE funcs SET name = '…' WHERE addr = …` fixes
  the auto-generated `fcn.<addr>` names.
- **`funcs.calltype`** (`UPDATE funcs SET calltype = 'ms' WHERE addr = …`) only
  accepts a name radare2 itself already knows for this session's `(arch,bits)`
  — check `SELECT name FROM calling_conventions` first. `afc` (the underlying
  command) is silent on both a successful set AND a rejected, made-up name, so
  an unknown value is rejected before the command ever runs rather than
  passed through to fail invisibly.
- **Sequencing:** writes are applied one radare2 command per matched row. For a
  predicate matching thousands of rows, **chunk** it (e.g. by address range) to
  keep each statement bounded.
- **Persistence:** mutations live in the radare2 session and vanish on exit
  **unless** you opened with `-w` and saved (`--project NAME`, or
  `r2xsql_project_save` mid-session). See below.
- **`patches` commit is table-wide, not row-selective.** `UPDATE patches SET
  committed = 1 WHERE addr = X` commits every currently-pending patch in the
  session, not just the row at `X` — radare2's write cache has no
  selective/ranged commit primitive (its ranged form is unsafe; see the
  table's own section above). Undo (`DELETE`) is the opposite scope: it only
  ever affects the single most-recently-staged pending patch.
- **`bytes.value` vs `patches`: pick the right one.** Want a change you can
  inspect, undo, or commit later? Use `patches`. Want a permanent overwrite
  right now with nothing left pending? Use `UPDATE bytes SET value = ...`.
  The two never interfere: `bytes.value`'s write disables `io.cache` for the
  duration of the `wx`, so it can never be staged into the overlay `patches`
  reads, then restores `io.cache` to its exact prior state — even mid-flight
  around an unrelated pending `patches` row.
- **Structural no-eval dispatch is now on every write with real
  user-controlled text.** On the in-process (libr) backend, every
  address-scoped write in this table (`funcs`, `flags`, `comments`,
  `bookmarks`, `patches`' INSERT, `bytes`' UPDATE, `locals`' `name`/`type`
  whenever the C-API leg is unavailable) and the addr-less `types` writes
  dispatch through a command path that never evaluates radare2's own
  `;`/`@`/`|`/backtick chaining grammar — a second, independent layer beneath
  the name/hex/signature/declaration validation each table already does.
  This is complete: every write-capable table has been examined (`locals`
  was the last one — its command-path fallback was missed in the original
  sweep and closed afterward). The exceptions (`patches`' `wci`/`wcu`, and
  `bytes`' own `io.cache` save/set/restore calls, which must stay on the
  plain, evaluating command path because they bracket the write rather than
  carry user text through it) are fixed literal commands / config toggles
  with no user-controlled text in them, so there was nothing to harden there
  — left on the plain command path deliberately, not overlooked.
  `bytes.value`'s actual injection defense is its strict 0-255 integer
  validation, which leaves no free-text argument at all. The pipe backend is
  unaffected everywhere: it always uses the original command form.

```sql
-- bulk annotate: mark every init-like function for review
UPDATE comments SET text = 'TODO: review init logic'
WHERE addr IN (SELECT addr FROM funcs WHERE name LIKE '%init%');
```

---

## Persistence & Projects

Edits (renames, comments, flags, types) accumulate in the radare2 core and are
written to disk only when a **project** is saved.

```sql
SELECT r2xsql_project_save('triage1');   -- Ps: save the session as a project, no exit
SELECT name FROM projects;              -- Plj: list saved projects
SELECT r2xsql_project_open('triage1');   -- P:  load a project mid-session
DELETE FROM projects WHERE name = 'x';  -- P-: delete a project on disk
```

Two ways to persist:

- **Mid-session:** `SELECT r2xsql_project_save('name')` whenever you want.
- **On exit:** open with `-w --project NAME`; the session saves automatically
  when the process ends.

Resume later with `--project NAME` (CLI) or `r2xsql_project_open('NAME')`. Using
a project also skips re-analysis — the warm path for iterative work.

```bash
# annotate and persist
r2xsql -w --project demo -s ./malware.exe -q "
  UPDATE funcs    SET name = 'aes_init'    WHERE addr = 0x401000;
  UPDATE comments SET text = 'crypto init' WHERE addr = 0x401000;
"
# reopen — the rename + comment are still there
r2xsql --project demo -s ./malware.exe -q "
  SELECT name FROM funcs WHERE addr = 0x401000;
"
```

Both `-q` statements above run — `-q` (like `-f`) executes every `;`-terminated
statement in the string, not just the first.

---

## Runtime Settings (`runtime_settings` table + timeout PRAGMAs)

Per-session runtime controls live in the **writable** `runtime_settings` table;
read with `SELECT`, change with `UPDATE`. Settings are per-session: each open
binary has its own state.

#### `runtime_settings` (writable)
One row per runtime setting, reflecting the **current** value.

| Column  | Type | Notes                                             |
|---------|------|---------------------------------------------------|
| `key`   | TEXT | setting name                                      |
| `value` | TEXT | live value (int as decimal, bool as `1`/`0`) — writable |
| `type`  | TEXT | `int` or `bool`                                   |
| `scope` | TEXT | `common` (a setting) or `action` (a PRAGMA verb)  |

Keys: `query_timeout_ms` (int; per-query timeout ms, drives execution),
`queue_admission_timeout_ms` (int), `max_queue` (int), `hints_enabled` (bool);
`timeout_stack_depth` / `max_timeout_stack_depth` (int, read-only);
`timeout_push` / `timeout_pop` (action verbs).

```sql
SELECT key, value, type, scope FROM runtime_settings;                    -- discover
SELECT value FROM runtime_settings WHERE key='query_timeout_ms';
UPDATE runtime_settings SET value='5000' WHERE key='query_timeout_ms';   -- 5s per-query timeout
```

Only the `value` column is writable, and only for value settings;
`key`/`type`/`scope`, the read-only rows, and the action verbs reject writes;
`INSERT`/`DELETE` are rejected.

#### Timeout verbs (PRAGMA)
The scoped-timeout stack is driven by the two imperative verbs — the only r2xsql
PRAGMAs. The stack is bounded at 64 entries.

```sql
PRAGMA r2xsql.timeout_push = 30000;      -- scope a longer timeout for one heavy query
-- ... run the heavy query ...
PRAGMA r2xsql.timeout_pop;               -- restore the prior timeout
```

The `timeout_push` stack is bounded (64 entries) so a client cannot grow it
without limit.

---

## SQL Functions

### r2xsql-registered

| Function                       | Returns | Effect (radare2)                                     |
|--------------------------------|---------|------------------------------------------------------|
| `regexp(pattern, text)`        | INT     | ECMAScript-regex match; backs `text REGEXP 'pat'`    |
| `r2xsql_project_save('name')`   | TEXT    | save the session as a project — `Ps name`            |
| `r2xsql_project_open('name')`   | TEXT    | load a project into the session — `P name`           |
| `r2xsql_type_define('<C decl>')`| TEXT    | define a type from a one-line C decl — `td <decl>`   |

```sql
-- regex on names (the registered regexp())
SELECT printf('0x%x', addr) AS at, name FROM funcs WHERE name REGEXP '^aes_(enc|dec)_';
```

### SQLite built-ins worth remembering

`LIKE` / `GLOB` (patterns), `INSTR` / `SUBSTR` / `LENGTH` (string slicing),
`LOWER` / `UPPER`, `COALESCE` / `IIF` / `CASE`, `CAST`, `JSON_EXTRACT`, plus
aggregates (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `GROUP_CONCAT`).

### Hex & address formatting

| Expression              | Result        | Note                                         |
|-------------------------|---------------|----------------------------------------------|
| `printf('0x%x', addr)`  | `0x401000`    | idiomatic pretty address                     |
| `hex(addr)`             | `34303130…`   | SQLite `hex()` is hex of the **bytes**, not `0x…` |
| `unhex('4889e5')`       | BLOB          | decode `instructions.bytes` to raw bytes (SQLite 3.41+) |

```sql
SELECT printf('0x%x', addr) AS at, name FROM funcs LIMIT 5;
SELECT printf('0x%x', addr) AS at, bytes FROM instructions WHERE func_addr = 0x401000;
```

---

## Performance Rules

1. **Use constraint pushdown.** Filter `blocks`/`instructions`/`pseudocode` by
   `func_addr`, and `xrefs` by `to_addr`/`from_addr`. Without it these tables
   walk every function.
2. **Always filter the decompiler.** An unfiltered `pseudocode` scan decompiles
   the entire binary — slow.
3. **Project only what you need.** `strings.content` is skipped at build time when
   not selected, so `SELECT COUNT(*) FROM strings` and length aggregates are
   cheap.
4. **Filter on integers/addresses,** not on stringified disassembly where you
   can avoid it.
5. **Reuse a live session.** Tables rebuild per query (no persistent cache) — for
   repeated drilling, keep the session warm with the `-i` REPL or the in-r2 plugin with the
   in-r2 plugin.
6. **Materialize repeated broad scans.** If you need an unfiltered `xrefs` set
   several times in a session, snapshot it:

   ```sql
   CREATE TEMP TABLE callers_of_x AS SELECT * FROM xrefs WHERE to_addr = 0x401000;
   ```

---

## Common Query Patterns

### Most-called functions
```sql
SELECT f.name, COUNT(*) AS callers
FROM funcs f JOIN xrefs x ON x.to_addr = f.addr
WHERE x.type = 'CALL'
GROUP BY f.addr ORDER BY callers DESC LIMIT 15;
```

### Functions that call a specific API
```sql
SELECT DISTINCT f.name
FROM imports i
JOIN xrefs x ON x.to_addr = i.addr
JOIN funcs f ON f.addr = x.from_func
WHERE i.name = 'CreateFileW' AND x.type = 'CALL';
```

### String cross-reference analysis
```sql
WITH s AS (SELECT addr FROM strings WHERE content = 'license check failed')
SELECT f.name AS in_func, printf('0x%x', x.from_addr) AS frm, x.type
FROM xrefs x
JOIN s ON x.to_addr = s.addr
LEFT JOIN funcs f ON f.addr = x.from_func;
```

### Complexity hotspots
```sql
SELECT name, cc, nbbs, size FROM funcs WHERE cc > 25 ORDER BY cc DESC;
```

### Triage: API surface by category
```sql
-- crypto
SELECT name, module FROM imports
WHERE name LIKE 'Crypt%' OR name LIKE 'BCrypt%' OR name LIKE '%AES%' OR name LIKE '%SHA%';

-- network
SELECT name, module FROM imports
WHERE module IN ('WS2_32.dll','WINHTTP.dll','WININET.dll','URLMON.dll','DNSAPI.dll');

-- anti-debug
SELECT name FROM imports
WHERE name IN ('IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess');

-- persistence
SELECT name, module FROM imports
WHERE name LIKE 'Reg%Set%' OR name LIKE 'Create%Service%'
   OR name LIKE '%Schedule%' OR name = 'WinExec' OR name LIKE 'ShellExecute%';
```

### Suspicious string anchors
```sql
SELECT printf('0x%x', addr) AS at, content FROM strings
WHERE content LIKE 'http%' OR content LIKE 'cmd.exe%' OR content LIKE 'powershell%'
   OR content LIKE '%HKEY_%' OR content LIKE 'C:\%' OR content LIKE '\Run\%';
```

### Decompile by name
```sql
SELECT f.name, p.text
FROM funcs f JOIN pseudocode p ON p.func_addr = f.addr
WHERE f.name LIKE 'parse_%';
```

### Two-hop reverse call graph ("who reaches X?")
`from_func` and `funcs.addr`/`to_addr` are the same key, so the whole walk stays
in address space and names resolve once, at the end.
```sql
WITH direct AS (
  SELECT DISTINCT from_func AS fn FROM xrefs
  WHERE to_addr = 0x401000 AND type = 'CALL' AND from_func IS NOT NULL
)
SELECT DISTINCT f.name AS caller_of_caller
FROM xrefs x
JOIN direct d ON d.fn = x.to_addr
JOIN funcs  f ON f.addr = x.from_func
WHERE x.type = 'CALL';
```

---

## Workflows

### Triage pass
1. **Orient** — `SELECT key, value FROM binary` (format, arch, counts).
2. **Surface APIs** — crypto / network / anti-debug / persistence (above).
3. **Find anchors** — notable `strings`.
4. **Pivot** — `xrefs` from a string/import up to its callers.
5. **Annotate** — rename functions, add comments/flags as you learn.

Import-based triage misses dynamically resolved APIs
(`LoadLibrary`/`GetProcAddress`) — hunt strings and pivot through `xrefs` to
catch them. High `cc` alone isn't "interesting" — combine it with API/string
anchors.

### Bottom-up "re-source" loop
Open with `-w --project NAME` so every note persists. Then repeat:
1. **Anchor** on a unique data leaf (a one-off string, a distinctive import).
2. **Walk back** via `xrefs` (`to_addr = <leaf>` → caller, then caller's caller).
3. **Name & comment** each hop (`UPDATE funcs SET name = …`,
   `UPDATE comments SET text = …`).
4. **Repeat** with the next un-named anchor — named functions become the next
   round's anchors, so each `xrefs` walk lands on something meaningful.

```sql
SELECT addr FROM strings WHERE content = 'license check failed';   -- (1) anchor
-- (2) one hop back; from_func is the owning function's ADDRESS, ready to rename
SELECT from_addr, from_func FROM xrefs WHERE to_addr = 0x412ab0;
UPDATE funcs    SET name = 'license_fail_log'           WHERE addr = 0x401a10; -- (3)
UPDATE comments SET text = 'logs license-check failure' WHERE addr = 0x401a10;
```

### Emulation / custom analysis via r2js
For ESIL emulation or anything SQL can't express, run radare2 / r2js and bridge
the result back through flags or comments, then read it with SQL:

```text
.aei; .aeim; .aeip          -- raw: init ESIL (over -q/REPL, leading '.')
```
An r2js script that sets a flag or writes a comment becomes visible to SQL:
```sql
SELECT name, printf('0x%x', addr) AS at FROM flags WHERE name LIKE 'sym.complex_%';
SELECT text FROM comments WHERE text LIKE 'ESIL:%';
```

### Type reconstruction
Browse `types` / `types_members`; define new ones with
`r2xsql_type_define('<C decl>')`; apply a type at an address with a raw command
(`.tl <TYPENAME> @ <addr>`).

---

## Raw radare2 Access

When the table surface can't express the question, reach the engine directly:

- **CLI `-q` / REPL:** a line beginning with `.` runs raw radare2 (the `.` is
  stripped): `r2xsql -s a.bin -q ".pdf @ entry0"`.
- **In-r2 plugin:** you're already in the radare2 shell.
- **r2js:** scripts run *inside* radare2 (`r2cmd("aflj")` returns JSON); they
  don't see the SQL database — bridge results back via flags/comments.

Raw passthrough (`Session::raw_cmd`) bypasses the table layer: no schema, no
parsing, no pushdown. **You** parse the output.

---


### In-r2 plugin
After loading the plugin inside radare2 (`L core_r2xsql.dll`):
```text
sql <SQL>            run one query against the host RCore
sql.?                list the sql.* subcommands
```

---

## Decompiler Setup

`pseudocode` exists only if a decompiler is installed. r2xsql probes at startup in
order and uses the first that responds:

| Probe   | Provided by            | Command issued     |
|---------|------------------------|--------------------|
| `pdg?`  | r2ghidra (recommended) | `pdg @ <addr>`     |
| `pdd?`  | r2dec                  | `pdd @ <addr>`     |
| `pdc?`  | radare2 built-in (basic)| `pdc @ <addr>`    |

Install one:
```bash
r2pm -ci r2ghidra
```
Check whether a decompiler is active — the `pseudocode` table is registered only
when one is detected:
```sql
SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'pseudocode';
-- one row ⇒ a decompiler is available; empty ⇒ install one
```
Decompilers differ wildly in output — avoid brittle string-matching downstream.
Decompilation is slow and not cached across sessions; keep analysis warm with a
project. Thunks/leaf/unanalyzable functions may decompile to a stub.

---

## Quick Start Examples

### "What does this binary do?"
```sql
SELECT key, value FROM binary WHERE key IN ('format','arch','bits','os','func_count','string_count','import_count');
SELECT module, COUNT(*) AS n FROM imports GROUP BY module ORDER BY n DESC LIMIT 10;
SELECT name, cc FROM funcs ORDER BY cc DESC LIMIT 10;
```

### "Find security-relevant code"
```sql
-- mitigation posture in one row: is this stripped of the usual protections?
SELECT has_nx, has_canary, has_pi, has_va FROM bininfo;
SELECT name, module FROM imports
WHERE name LIKE 'Crypt%' OR module LIKE 'WS2_32%' OR name LIKE '%Alloc%' OR name LIKE 'WinExec';
SELECT printf('0x%x', addr) AS at, content FROM strings WHERE content LIKE '%password%' OR content LIKE 'http%';
```

### "Understand a specific function"
```sql
SELECT name, size, cc, nbbs FROM funcs WHERE addr = 0x401000;
SELECT printf('0x%x', addr) AS at, disasm FROM instructions WHERE func_addr = 0x401000 ORDER BY addr;
SELECT text FROM pseudocode WHERE func_addr = 0x401000;          -- if a decompiler is present
SELECT DISTINCT f.name FROM xrefs x                              -- callers
  JOIN funcs f ON f.addr = x.from_func WHERE x.to_addr = 0x401000;
```

### "Find all uses of a string"
```sql
WITH s AS (SELECT addr FROM strings WHERE content LIKE '%secret%')
SELECT f.name AS in_func, printf('0x%x', x.from_addr) AS frm
FROM xrefs x
JOIN s ON x.to_addr = s.addr
LEFT JOIN funcs f ON f.addr = x.from_func;
```

---

## Summary: When to Use What

| You want…                                  | Use                                            |
|--------------------------------------------|------------------------------------------------|
| Binary format / arch / quick counts        | `binary`                                        |
| Binary metadata as ONE typed row (incl. mitigation flags) | `bininfo`                       |
| Function list / sizes / complexity         | `funcs`                                          |
| Disassembly of a function                  | `instructions WHERE func_addr = X`              |
| Basic-block layout                         | `blocks WHERE func_addr = X`                     |
| Readable C-like view                       | `pseudocode WHERE func_addr = X` (decompiler)    |
| Callers / callees / data refs              | `xrefs` (`to_addr`/`from_addr`)                  |
| Strings / imports / entry points / exports | `strings` / `imports` / `entries`                |
| Bytes / defined data / byte patterns       | `bytes` / `data_items` / `byte_search`           |
| Assemble a mnemonic / find where it occurs | `assemble` / `search_asm`                        |
| Demangle a C++/Rust/Swift/MSVC symbol name | `demangle`                                       |
| Memory layout                              | `sections` / `segments` / `io_maps`              |
| Find any named entity by pattern           | `grep WHERE pattern = '…'`                        |
| Every named entity, classified (r2xsql's own `kind` vocabulary — not portable) | `entities`         |
| Types / struct layout                      | `types` / `types_members`                        |
| Register profile / relocations / linked libs | `registers` / `relocs` / `libs`                |
| Rename / comment / flag / bookmark         | writable tables (`funcs`/`comments`/`flags`/`bookmarks`) |
| Save / resume work                         | projects + `r2xsql_project_save`/`_open`          |
| Something SQL can't express                | raw radare2 (`.`-prefix, `.r2cmd`, r2js)         |

---

## Error Handling / Caveats

- **Empty `funcs`/`xrefs`:** analysis hasn't run. Open without `--no-analyze`,
  open a `--project`, or run deeper analysis (`.aaaa` raw) for more edges.
- **Indirect calls** may resolve to the IAT slot, not the final target —
  emulate (`.aae`) or run `.aaaa` for more.
- **`funcs.size = 0`** for some thunks/externs — filter with `size > 0` when
  measuring real code.
- **No `pseudocode` table:** no decompiler detected — install one (see above).
- **Sparse `types` / unresolved ordinal imports** with `r2xsql-full`: it isn't
  running from radare2's `bin/` (the `share/` data dir isn't found). Run it from
  the radare2 install directory, or use the pipe-only `r2xsql` (which always has
  the full data dir).
- **Write didn't stick** after exit: you didn't open with `-w` / didn't save a
  project. Use `-w --project NAME` or `r2xsql_project_save`.
