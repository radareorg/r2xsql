# r2xsql test suite

A small, portable smoke suite over the SQL surface, in radare2's own test
format and run by radare2's own runner, `r2r`. The exhaustive coverage lives
in the project's private suite; this is the layer a consumer can run.

## Requirements

- `radare2` and `rasm2` on `PATH` (r2r needs both)
- `r2r` on `PATH` — it installs with radare2
- a C compiler, to build the deterministic fixture from `fixture.c`
- the `core_r2xsql` plugin, either installed into radare2's plugin directory
  or in a build tree you point at

## Running

```sh
make                                          # plugin already installed
make R2XSQL_PLUGIN_DIR=/path/to/build/bin     # or point at a build tree
```

Equivalently, by hand:

```sh
cc -O0 -g -o build/fixture.bin fixture.c
R2_LIBR_PLUGINS=/path/to/build/bin r2r -u -L -C . db/extras/cmd
```

The plugin is ABI-locked to the radare2 it was built against
(`R2_ABIVERSION`), so these must be the matching pair — a mismatch shows up as
radare2 refusing to load the plugin.

## Layout

```
db/extras/cmd/core      core tables over a real compiled binary
db/extras/cmd/schema    views and sqlite_master introspection
db/extras/cmd/types     the type system (td defines, SQL reads)
db/extras/cmd/write     the writable surface and its injection guard
db/extras/cmd/format    the sql / sql, / sqlj output forms
```

**Why `db/extras/`.** r2r runs radare2 with `-NN` and `R2_NOPLUGINS` unless a
test's path contains an `extras` component — and with no plugins there is no
`sql` command to test. `extras` directories are also skipped during plain
recursion, which is why the path is named explicitly above. Each test passes
`ARGS=-N` so a developer's `.radare2rc` cannot change the result.

**Why the assertions look the way they do.** r2r compares stdout
byte-for-byte with no normalisation, so "more than zero functions" cannot be
written as an `EXPECT`. Instead the assertion goes *into* the SQL — `SELECT
count(*) > 0 FROM funcs` — and `EXPECT` pins the literal `1`. That stays
correct across compilers, architectures and radare2 versions, which a raw
count would not.

## Known issue: r2r on Windows

`r2r` hangs on Windows before running anything, including against radare2's
own `test/db`. It is not exercised by upstream CI there. These tests are
therefore verified on Linux; the suite itself is platform-neutral.
