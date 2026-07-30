# r2sql Agent Guide

You are working with **r2sql**, a live SQL interface over a radare2 analysis
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

r2sql turns that surface into SQL tables. Instead of memorizing radare2 command
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
  interactive drilling, **start a server once and query repeatedly** (see
  *Server Modes*) rather than re-launching the CLI per query.
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
default r2sql runs radare2's auto-analysis (`aaa`) at startup; pass
`--no-analyze` to skip it (faster open, but `funcs`/`xrefs` will be sparse until
you analyze). Reusing a `--project` skips re-analysis entirely.

Always know **what binary** you are looking at before reasoning about results:

```sql
SELECT key, value FROM binary ORDER BY key;
```

### Invocation modes

```bash
# one-shot query (multiple statements separated by ;)
r2sql -s ./target.exe -q "SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10"

# run a SQL script file
r2sql -s ./target.exe -f ./audit.sql

# interactive REPL
r2sql -s ./target.exe -i

# HTTP server (query repeatedly with no per-query startup cost)
r2sql -s ./target.exe --http 8080
# then: curl -X POST http://127.0.0.1:8080/query --data "SELECT * FROM binary"

# MCP server (for an MCP client / agent)
r2sql -s ./target.exe --mcp 9876
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
| `--http [port]`     | Start HTTP REST server (no port ⇒ random in **8100–8999**)       |
| `--mcp [port]`      | Start MCP SSE server (no port ⇒ random in **9000–9999**)         |
| `--bind <addr>`     | Bind address for `--http` / `--mcp` (default `127.0.0.1`)        |
| `--token <tok>`     | Require a Bearer token on HTTP endpoints                         |
| `--version`         | Print version and exit                                           |
| `-h`, `--help`      | Print help and exit                                              |

### Two flavors, four backends

r2sql ships as **two executables built from one codebase**:

| Binary       | Backend     | Notes                                                       |
|--------------|-------------|------------------------------------------------------------|
| `r2sql`      | r2pipe      | **Pipe-only, always built.** Portable single binary; spawns `radare2` over a pipe. Needs `radare2` on `PATH`. Deploy anywhere. |
| `r2sql-full` | libr        | **In-process** (links radare2's libraries). Fastest, no spawn. Run it from the radare2 install `bin/` directory so it finds the DLLs and the `share/` data dir. |

Backend selection at a glance:

| Backend       | When to use                                                       |
|---------------|------------------------------------------------------------------|
| **r2pipe**    | `r2sql` (or `--r2pipe`). Portable; spawns `radare2 -q0`. Always has the full data dir, since the spawned radare2 resolves its own `share/`. |
| **libr**      | `r2sql-full`. In-process, fastest. Type DB / ordinal imports degrade unless run from radare2's `bin/`. |
| **in-r2 plugin** | Already inside radare2: `L core_r2sql.dll` then `sql <SQL>`.   |
| **mock**      | Embedding/testing: a canned `{cmd → response}` map, no live radare2. |

Pick `r2sql` for portability, `r2sql-full` for throughput on large binaries or
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

The same `.`-prefix works with `-q` (`r2sql -s a.bin -q ".ij"`). Over HTTP, use
a body that begins with `.r2cmd ` (see *Server Modes*).

### Performance strategy

A one-shot `-q` pays the full open+analyze cost every invocation. For anything
interactive or scripted with many queries, **open once as a server** and send
queries over HTTP/MCP — the session (and its analysis) stays warm.

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
with a `type`: `CALL` (call), `CODE` (jump/branch), `DATA` (read/write), or
`STRING`. "Who calls X?" is `to_addr = X`; "what does X reference?" is
`from_addr = X`.

### Sections vs segments vs io_maps
`sections` (`.text`, `.rdata`, `.data`, …) describe the file's logical layout;
`segments` describe the loader's memory view. Both carry `start_addr`,
`end_addr`, `vsize`, `paddr`, `size`, `name`, `perm` (a permission string like
`r-x`) — and both are read-only.
`io_maps` is r2's **writable** memory map (radare2 IO maps): INSERT a region,
DELETE it, query it. Use `io_maps` to add an SRAM region or rebase a raw image;
`sections`/`segments` are the binary's static headers.

### Basic blocks
Within a function, **basic blocks** (`blocks`) are straight-line code runs with
a single entry and exit — the unit of control-flow analysis.

### Control-flow edges
`cfg_edges` is the intra-function control-flow graph: one row per edge between two
basic blocks — `func_addr`, `from_addr`, `to_addr` (source/target block start
addresses), and `edge_type` (`normal`, `true`, `false`). Always filter by
`func_addr` (pushdown → `afbj @ X`). Branch points are blocks with >1 successor;
find them with `SELECT from_addr, COUNT(*) FROM cfg_edges WHERE func_addr = X
GROUP BY from_addr HAVING COUNT(*) > 1`.

### Dominators / post-dominators / loops
Canonical cross-tool CFG-graph tables (aligned with ghidrasql). Each maps a
function's `afbj @ X` basic blocks onto opaque node ids and runs the generic
`xsql::graph` module. Always filter by `func_addr` (pushdown → `afbj @ X`).

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

17 base tables, plus `pseudocode` when a decompiler is present. Columns below
are authoritative; full detail lives in the per-topic skills.

### Orientation

#### `binary` (read-only)
Key/value binary metadata — `(key TEXT, value TEXT, type TEXT)`, one row per
fact, `type ∈ {string, hex, bool, int}`; the shape and canonical key names are
shared across the tool family, and the `summary` row is emitted first. Carries
radare2's raw bin-info fields (`arch`, `bits`, `bintype`, `os`, `baddr`,
`endian`, `compiler`, `lang`, …) plus r2sql identity/entry/count keys AND
canonical family synonyms of the raw facts. Counts are JSON-array lengths, so
they match the corresponding tables exactly.

| Column  | Type | Notes                                        |
|---------|------|----------------------------------------------|
| `key`   | TEXT | field name                                   |
| `value` | TEXT | string representation                        |
| `type`  | TEXT | value type tag: string / hex / bool / int    |

Notable keys: `r2sql_version`, `file`, `entry`, `entry_name`, `func_count`,
`string_count`, `import_count`, `section_count`, `segment_count`,
`symbol_count`, `summary`.

Canonical family keys (same names on idasql/bnsql/ghidrasql; values alias the
raw radare2 facts): `tool_name` (`r2sql`), `tool_version`, `processor` (=arch),
`filetype` (=bintype), `image_base` (=baddr, hex), `entry_point` (=entry),
`is_64bit`, `endianness`, `filename` (=file), and `min_addr`/`max_addr` derived
from the section/segment maps (omitted when unmapped). `bits` doubles as the
canonical bits key. No `md5`/`sha256` (best-effort core; radare2 hashing is
unreliable).

```sql
-- everything at a glance
SELECT key, value FROM binary ORDER BY key;

-- just format / arch / bits
SELECT key, value FROM binary
WHERE key IN ('format','bintype','arch','bits','os','endian','class');
```

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
| `cc`       | INT64 | cyclomatic complexity                       |
| `type`     | TEXT  | `fcn` / `sym` / `loc`                        |
| `calltype` | TEXT  | `cdecl` / `stdcall` / `fastcall` / …         |
| `prototype`| TEXT  | C signature (**writable** ⇒ `afs` set-signature); read from `aflj` `signature` |

`UPDATE funcs SET prototype = 'int parse(hdr_t *h, int len)' WHERE addr = …`
applies a C function signature via `afs`. A trailing `;` is stripped (r2's
command separator); an empty/NULL prototype is rejected (r2 has no
clear-signature primitive — an empty `afs` mangles the name).

```sql
-- 20 largest functions
SELECT printf('0x%x', addr) AS at, name, size, cc, nbbs
FROM funcs ORDER BY size DESC LIMIT 20;

-- auto-named (unanalyzed) functions
SELECT printf('0x%x', addr) AS at, name FROM funcs WHERE name LIKE 'fcn.%';

-- abnormally complex functions
SELECT name, cc FROM funcs WHERE cc > 30 ORDER BY cc DESC;
```

#### `locals` (writable)
Source per-function `afvj @ <func_addr>`. One row per local variable/argument,
keyed on `(func_addr, name)`. Both `name` and `type` are writable.

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
Source per-function `afbj @ <addr>`. Filter by `func_addr`.

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
scan disassembles every function.

| Column         | Type  | Notes                                          |
|----------------|-------|------------------------------------------------|
| `addr`         | INT64 | instruction address                            |
| `size`         | INT64 | instruction length in bytes                    |
| `func_addr`    | INT64 | owning function                                |
| `seq`          | INT64 | per-function ordinal (0-based, in `addr` order)|
| `mnemonic`     | TEXT  | opcode (`call`, `mov`, `jmp`, …)               |
| `disasm`       | TEXT  | full disassembled text                         |
| `bytes`        | TEXT  | hex-encoded bytes (e.g. `4889e5`)              |
| `esil`         | TEXT  | radare2's stack-based IL (same `pdfj` op; empty when r2 doesn't lift it) |
| `op_type`      | TEXT  | radare2 semantic op type (`add`, `call`, `cjmp`, …) |
| `canonical_op` | TEXT  | cross-tool canonical P-code-style op (`INT_ADD`, `CALL`, `CBRANCH`, …); empty when no clean canonical |

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
Source `iSj` / `iSSj`.

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

#### `strings` (read-only)
Source `izj`. (The `text` column is skipped at build time when you don't select
it — so `COUNT(*)` / length histograms over `strings` are cheap.)

| Column    | Type  | Notes                              |
|-----------|-------|------------------------------------|
| `addr`    | INT64 | string address                     |
| `length`  | INT64 | length                             |
| `section` | TEXT  | containing section                 |
| `type`    | TEXT  | `ascii` / `utf8` / `utf16le` / …   |
| `text`    | TEXT  | the string contents                |

```sql
-- find a substring (case-insensitive via LIKE)
SELECT printf('0x%x', addr) AS at, text FROM strings WHERE text LIKE '%password%';

-- longest strings (often format strings / embedded blobs)
SELECT length, type, text FROM strings ORDER BY length DESC LIMIT 20;
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
Source `iij`.

| Column    | Type  | Notes                          |
|-----------|-------|--------------------------------|
| `addr`    | INT64 | IAT slot address               |
| `ordinal` | INT64 | import ordinal                 |
| `bind`    | TEXT  | binding                        |
| `type`    | TEXT  | symbol type                    |
| `name`    | TEXT  | imported symbol name           |
| `libname` | TEXT  | source library / DLL           |

```sql
-- imports grouped by library
SELECT libname, COUNT(*) AS n FROM imports GROUP BY libname ORDER BY n DESC;

-- crypto API surface
SELECT name, libname FROM imports
WHERE name LIKE 'Crypt%' OR name LIKE 'BCrypt%'
   OR name LIKE '%AES%'  OR name LIKE '%SHA%' OR name LIKE '%RC4%';
```

`imports.addr` is the IAT slot, not the resolved external — pivot through
`xrefs` to find code that calls through it.

#### `entries` (read-only)
Sources `iej` (program entry points) plus `iEj` (exports), deduplicated by address.
Executables normally have at least their loader entry point even when they export
no symbols.

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

| Column      | Type  | Notes                                  |
|-------------|-------|----------------------------------------|
| `from_addr` | INT64 | source address                         |
| `to_addr`   | INT64 | target address                         |
| `type`      | TEXT  | `CALL` / `CODE` / `DATA` / `STRING`    |
| `from_func` | TEXT  | function the ref was enumerated from   |

```sql
-- who calls / references this address?
SELECT printf('0x%x', from_addr) AS frm, from_func, type
FROM xrefs WHERE to_addr = 0x401000;

-- callers of every crypto import (join imports ⨝ xrefs)
SELECT DISTINCT x.from_func, i.name
FROM imports i JOIN xrefs x ON x.to_addr = i.addr
WHERE i.name LIKE 'Crypt%';
```

Indirect calls (`call qword [rip+…]`) may resolve to the IAT **slot** rather
than the final target; re-run deeper analysis (`aaaa` / emulation `aae`) for
more edges.

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
```

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

#### `types` (writable: DELETE)
Source `tk*` enriched with `tj` / `tsj` / `tuj`.

| Column   | Type  | Notes                                                            |
|----------|-------|------------------------------------------------------------------|
| `name`   | TEXT  | fully qualified type name                                        |
| `kind`   | TEXT  | `atomic` / `struct` / `union` / `enum` / `typedef` / `func` / `type` |
| `size`   | INT64 | byte size; `-1` for unsized/opaque/pointer-like                  |
| `format` | TEXT  | radare2 `pf` format string when applicable                       |

`DELETE FROM types WHERE name = 'X'` ⇒ `t- X`. To **create** a type, use
`r2sql_type_define('<one-line C decl>')` (a full declaration doesn't fit the
row columns).

```sql
SELECT name, kind, size FROM types WHERE kind = 'struct' ORDER BY size DESC LIMIT 20;
SELECT r2sql_type_define('struct hdr { int magic; int size; char name[16]; }');
```

The full type set (e.g. the thousands of Windows API typedefs) lives in
radare2's `share/fcnsign/types-*.sdb`. The **r2pipe** backend always loads it.
The **libr** backend (`r2sql-full`) loads it only when run from radare2's `bin/`
directory; otherwise `types` collapses to a few built-ins (r2sql warns).

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

### Annotations (writable)

#### `flags` (writable)
Source `fj`. Named addresses.

| Column     | Type  | Notes                          |
|------------|-------|--------------------------------|
| `addr`     | INT64 | address                        |
| `size`     | INT64 | flag size                      |
| `name`     | TEXT  | flag name (**writable**)       |
| `realname` | TEXT  | demangled / original name      |
| `space`    | TEXT  | flagspace                      |

```sql
INSERT INTO flags (addr, name) VALUES (0x401000, 'aes_sbox');     -- f
UPDATE flags SET name = 'aes_init' WHERE addr = 0x401000;         -- fr / afn
DELETE FROM flags WHERE addr = 0x401000;                          -- f-
```

#### `comments` (writable)
Source `CCj`.

| Column | Type  | Notes                          |
|--------|-------|--------------------------------|
| `addr` | INT64 | address                        |
| `type` | TEXT  | comment type                   |
| `text` | TEXT  | comment text (**writable**)    |

```sql
INSERT INTO comments (addr, text) VALUES (0x401000, 'crypto init');  -- CCu base64:
UPDATE comments SET text = 'crypto init v2' WHERE addr = 0x401000;   -- CCu base64:
DELETE FROM comments WHERE addr = 0x401000;                          -- CC-
```

Comment text is sent as `CCu base64:<b64>`, so spaces, quotes, and `@` are
stored verbatim and cannot inject extra radare2 commands.

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

r2sql exposes create/update/delete wherever radare2 has a write verb and the
table is an editable annotation. Each affected row issues one radare2 command.

| Table       | INSERT             | UPDATE                       | DELETE        |
|-------------|--------------------|------------------------------|---------------|
| `funcs`     | `af @ <addr>` (+`afn`) | `name` ⇒ `afn <name> @ <addr>` (rename); `prototype` ⇒ `afs <sig> @ <addr>` (set-signature) | `af- <addr>` (undefine) |
| `flags`     | `f <name> @ <addr>`| `name` ⇒ `fr <old> <new>` / `afn` | `f- @ <addr>` |
| `comments`  | `CCu base64:<b64> @ <addr>` | `text` ⇒ `CCu base64:<b64> @ <addr>` | `CC- @ <addr>` |
| `bookmarks` | `f <name> @ <addr>` (bookmarks space) | `name` ⇒ `fr <old> <new>` | `f- @ <addr>` |
| `locals`    | — | `name` ⇒ `afvn <new> <old>`; `type` ⇒ `afvt <name> <type>` | — |
| `types`     | — (use `r2sql_type_define`) | —                  | `t- <name>`   |
| `projects`  | — (use `r2sql_project_save`) | —                 | `P- <name>`   |
| `io_maps`   | `om $d <vaddr> <size> <paddr> <perm> <name>` (add region) | — | `om-<map_id>` (remove map) |
| `runtime_settings` | —          | `value` ⇒ UPDATE (validated) | —       |

All other tables and views (`binary`, `blocks`, `bytes`, `cfg_edges`,
`switch_tables`, `function_frames`, `dominators`, `post_dominators`, `loops`,
`data_items`, `byte_search`, `instructions`, `instruction_operands`, `esil_ops`,
`esil_operands`, `ir_*`, `xrefs`, `strings`, `imports`, `entries`, `sections`,
`segments`, `grep`, `pseudocode`, `types_members`) are **read-only** — they
reflect file/analysis state, not user-editable rows. Writes to them are rejected.
(`runtime_settings` above only accepts an `UPDATE value`; `timeout_push`/
`timeout_pop` remain PRAGMA verbs.)

Rules and gotchas:

- **Name validation:** function / flag / bookmark / project names must match
  `[A-Za-z0-9._$]` — no spaces or radare2 metacharacters (prevents injection).
  Comment text has no such limit (it's base64-encoded).
- **Renames:** the obvious `UPDATE funcs SET name = '…' WHERE addr = …` fixes
  the auto-generated `fcn.<addr>` names.
- **Sequencing:** writes are applied one radare2 command per matched row. For a
  predicate matching thousands of rows, **chunk** it (e.g. by address range) to
  keep each statement bounded.
- **Persistence:** mutations live in the radare2 session and vanish on exit
  **unless** you opened with `-w` and saved (`--project NAME`, or
  `r2sql_project_save` mid-session). See below.

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
SELECT r2sql_project_save('triage1');   -- Ps: save the session as a project, no exit
SELECT name FROM projects;              -- Plj: list saved projects
SELECT r2sql_project_open('triage1');   -- P:  load a project mid-session
DELETE FROM projects WHERE name = 'x';  -- P-: delete a project on disk
```

Two ways to persist:

- **Mid-session:** `SELECT r2sql_project_save('name')` whenever you want.
- **On exit:** open with `-w --project NAME`; the session saves automatically
  when the process ends.

Resume later with `--project NAME` (CLI) or `r2sql_project_open('NAME')`. Using
a project also skips re-analysis — the warm path for iterative work.

```bash
# annotate and persist
r2sql -w --project demo -s ./malware.exe -q "
  UPDATE funcs    SET name = 'aes_init'    WHERE addr = 0x401000;
  UPDATE comments SET text = 'crypto init' WHERE addr = 0x401000;
"
# reopen — the rename + comment are still there
r2sql --project demo -s ./malware.exe -q "
  SELECT name FROM funcs WHERE addr = 0x401000;
"
```

---

## Runtime Settings (`runtime_settings` table + timeout PRAGMAs)

Per-session runtime controls live in the **writable** `runtime_settings` table;
read with `SELECT`, change with `UPDATE`. Settings are per-session: each open
binary / server has its own state.

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
The scoped-timeout stack is driven by the two imperative verbs — the only r2sql
PRAGMAs. The stack is bounded at 64 entries.

```sql
PRAGMA r2sql.timeout_push = 30000;      -- scope a longer timeout for one heavy query
-- ... run the heavy query ...
PRAGMA r2sql.timeout_pop;               -- restore the prior timeout
```

The `timeout_push` stack is bounded (64 entries) so a client cannot grow it
without limit.

---

## SQL Functions

### r2sql-registered

| Function                       | Returns | Effect (radare2)                                     |
|--------------------------------|---------|------------------------------------------------------|
| `regexp(pattern, text)`        | INT     | ECMAScript-regex match; backs `text REGEXP 'pat'`    |
| `r2sql_project_save('name')`   | TEXT    | save the session as a project — `Ps name`            |
| `r2sql_project_open('name')`   | TEXT    | load a project into the session — `P name`           |
| `r2sql_type_define('<C decl>')`| TEXT    | define a type from a one-line C decl — `td <decl>`   |

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
3. **Project only what you need.** `strings.text` is skipped at build time when
   not selected, so `SELECT COUNT(*) FROM strings` and length aggregates are
   cheap.
4. **Filter on integers/addresses,** not on stringified disassembly where you
   can avoid it.
5. **Reuse via a server.** Tables rebuild per query (no persistent cache) — for
   repeated drilling, run `--http`/`--mcp` once and query the warm session.
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
SELECT DISTINCT x.from_func
FROM imports i JOIN xrefs x ON x.to_addr = i.addr
WHERE i.name = 'CreateFileW' AND x.type = 'CALL';
```

### String cross-reference analysis
```sql
WITH s AS (SELECT addr FROM strings WHERE text = 'license check failed')
SELECT x.from_func, printf('0x%x', x.from_addr) AS frm, x.type
FROM xrefs x JOIN s ON x.to_addr = s.addr;
```

### Complexity hotspots
```sql
SELECT name, cc, nbbs, size FROM funcs WHERE cc > 25 ORDER BY cc DESC;
```

### Triage: API surface by category
```sql
-- crypto
SELECT name, libname FROM imports
WHERE name LIKE 'Crypt%' OR name LIKE 'BCrypt%' OR name LIKE '%AES%' OR name LIKE '%SHA%';

-- network
SELECT name, libname FROM imports
WHERE libname IN ('WS2_32.dll','WINHTTP.dll','WININET.dll','URLMON.dll','DNSAPI.dll');

-- anti-debug
SELECT name FROM imports
WHERE name IN ('IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess');

-- persistence
SELECT name, libname FROM imports
WHERE name LIKE 'Reg%Set%' OR name LIKE 'Create%Service%'
   OR name LIKE '%Schedule%' OR name = 'WinExec' OR name LIKE 'ShellExecute%';
```

### Suspicious string anchors
```sql
SELECT printf('0x%x', addr) AS at, text FROM strings
WHERE text LIKE 'http%' OR text LIKE 'cmd.exe%' OR text LIKE 'powershell%'
   OR text LIKE '%HKEY_%' OR text LIKE 'C:\%' OR text LIKE '\Run\%';
```

### Decompile by name
```sql
SELECT f.name, p.text
FROM funcs f JOIN pseudocode p ON p.func_addr = f.addr
WHERE f.name LIKE 'parse_%';
```

### Two-hop reverse call graph ("who reaches X?")
```sql
WITH direct AS (
  SELECT DISTINCT from_func FROM xrefs WHERE to_addr = 0x401000 AND type = 'CALL'
)
SELECT DISTINCT x.from_func AS caller_of_caller
FROM xrefs x JOIN funcs f ON f.addr = x.to_addr
JOIN direct d ON d.from_func = f.name
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
SELECT addr FROM strings WHERE text = 'license check failed';   -- (1) anchor
SELECT from_addr, from_func FROM xrefs WHERE to_addr = 0x412ab0; -- (2) one hop back
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
`r2sql_type_define('<C decl>')`; apply a type at an address with a raw command
(`.tl <TYPENAME> @ <addr>`).

---

## Raw radare2 Access

When the table surface can't express the question, reach the engine directly:

- **CLI `-q` / REPL:** a line beginning with `.` runs raw radare2 (the `.` is
  stripped): `r2sql -s a.bin -q ".pdf @ entry0"`.
- **HTTP:** `POST /query` with a body beginning `.r2cmd ` → `{"success":true,
  "output":"<raw output>"}`.
- **In-r2 plugin:** you're already in the radare2 shell.
- **r2js:** scripts run *inside* radare2 (`r2cmd("aflj")` returns JSON); they
  don't see the SQL database — bridge results back via flags/comments.

Raw passthrough (`Session::raw_cmd`) bypasses the table layer: no schema, no
parsing, no pushdown. **You** parse the output.

---

## Server Modes

### HTTP REST (recommended for repeated queries)
```bash
r2sql -s ./target.exe --http 8080
r2sql -s ./target.exe --http --bind 0.0.0.0 --token s3cret   # bind everywhere + auth
```
`--http` with no port picks a random port in **8100–8999**.

| Endpoint        | Method | Purpose                                                   |
|-----------------|--------|-----------------------------------------------------------|
| `/`             | GET    | banner / welcome                                          |
| `/help`         | GET    | embedded API help                                         |
| `/query`        | POST   | body = SQL, or `.r2cmd <command>` for raw radare2         |
| `/status`       | GET    | health check (`{"mode":"cli","tool":"r2sql"}`)            |
| `/shutdown`     | POST   | graceful stop                                             |

Response envelope:
```json
{ "success": true, "columns": ["name","size"], "rows": [["main","42"]], "row_count": 1 }
```
On error: `{ "success": false, "error": "<message>" }`. With `--token`, every
endpoint except `/` and `/help` requires `Authorization: Bearer <tok>` (or
`X-XSQL-Token: <tok>`).

```bash
curl -X POST http://127.0.0.1:8080/query \
  --data 'SELECT name, size FROM funcs ORDER BY size DESC LIMIT 5'
curl -X POST http://127.0.0.1:8080/query --data '.r2cmd ?V'   # raw radare2
```

### MCP (SSE / JSON-RPC)
```bash
r2sql -s ./target.exe --mcp 9876        # or --mcp for a random port in 9000-9999
```
Transport: `GET /sse` (event stream) + `POST /messages` (JSON-RPC). One tool:

| Field | Value                                                     |
|-------|-----------------------------------------------------------|
| Name  | `r2sql_query`                                             |
| Input | `{ "query": "<SQL string>" }` (required)                  |
| Result| `content:[{type:"text", text:"<JSON envelope>"}]`         |

The JSON envelope inside `text` is byte-identical to the HTTP `/query` response.
A failed SQL query is reported **in-band** (`success:false`), not as a
transport error.

### In-r2 plugin
After loading the plugin inside radare2 (`L core_r2sql.dll`):
```text
sql <SQL>            run one query against the host RCore
sql.http [port]      start / sql.http-  stop / sql.http?  status
sql.mcp  [port]      start / sql.mcp-   stop / sql.mcp?   status
```

---

## Decompiler Setup

`pseudocode` exists only if a decompiler is installed. r2sql probes at startup in
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
SELECT libname, COUNT(*) AS n FROM imports GROUP BY libname ORDER BY n DESC LIMIT 10;
SELECT name, cc FROM funcs ORDER BY cc DESC LIMIT 10;
```

### "Find security-relevant code"
```sql
SELECT name, libname FROM imports
WHERE name LIKE 'Crypt%' OR libname LIKE 'WS2_32%' OR name LIKE '%Alloc%' OR name LIKE 'WinExec';
SELECT printf('0x%x', addr) AS at, text FROM strings WHERE text LIKE '%password%' OR text LIKE 'http%';
```

### "Understand a specific function"
```sql
SELECT name, size, cc, nbbs FROM funcs WHERE addr = 0x401000;
SELECT printf('0x%x', addr) AS at, disasm FROM instructions WHERE func_addr = 0x401000 ORDER BY addr;
SELECT text FROM pseudocode WHERE func_addr = 0x401000;          -- if a decompiler is present
SELECT from_func FROM xrefs WHERE to_addr = 0x401000;            -- callers
```

### "Find all uses of a string"
```sql
WITH s AS (SELECT addr FROM strings WHERE text LIKE '%secret%')
SELECT x.from_func, printf('0x%x', x.from_addr) AS frm
FROM xrefs x JOIN s ON x.to_addr = s.addr;
```

---

## Summary: When to Use What

| You want…                                  | Use                                            |
|--------------------------------------------|------------------------------------------------|
| Binary format / arch / quick counts        | `binary`                                        |
| Function list / sizes / complexity         | `funcs`                                          |
| Disassembly of a function                  | `instructions WHERE func_addr = X`              |
| Basic-block layout                         | `blocks WHERE func_addr = X`                     |
| Readable C-like view                       | `pseudocode WHERE func_addr = X` (decompiler)    |
| Callers / callees / data refs              | `xrefs` (`to_addr`/`from_addr`)                  |
| Strings / imports / entry points / exports | `strings` / `imports` / `entries`                |
| Bytes / defined data / byte patterns       | `bytes` / `data_items` / `byte_search`           |
| Memory layout                              | `sections` / `segments` / `io_maps`              |
| Find any named entity by pattern           | `grep WHERE pattern = '…'`                        |
| Types / struct layout                      | `types` / `types_members`                        |
| Rename / comment / flag / bookmark         | writable tables (`funcs`/`comments`/`flags`/`bookmarks`) |
| Save / resume work                         | projects + `r2sql_project_save`/`_open`          |
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
- **Sparse `types` / unresolved ordinal imports** with `r2sql-full`: it isn't
  running from radare2's `bin/` (the `share/` data dir isn't found). Run it from
  the radare2 install directory, or use the pipe-only `r2sql` (which always has
  the full data dir).
- **Write didn't stick** after exit: you didn't open with `-w` / didn't save a
  project. Use `-w --project NAME` or `r2sql_project_save`.
