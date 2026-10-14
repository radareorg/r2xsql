# r2xsql

[![ci status](https://github.com/radareorg/r2xsql/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/radareorg/r2xsql/actions/workflows/build.yml?query=branch%3Amain)

SQL interface for [radare2](https://github.com/radareorg/radare2), powered
by [libxsql](https://github.com/0xeb/libxsql). The `core_r2xsql` plugin exposes
the host's live analysis as SQL tables, including writable annotations.

## Using the plugin

Install radare2 first, then build and install the matching plugin with r2pm:

```sh
r2pm -U
r2pm -ci r2xsql
r2 -A ./target
```

Installed plugins load automatically. Check `Lcj` and `sql?` at the r2 prompt.
For an uninstalled build, use `r2 -i ./core_r2xsql.so -A ./target`; inside an
existing session use `L ./core_r2xsql.so`. Substitute `.dylib` or `.dll` as
appropriate. The plugin must match the host's radare2 ABI, including iaito's
engine. See [installation details](docs/usage.md#installation).

```text
sql SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10
"sql UPDATE funcs SET name='parse_header' WHERE addr=0x401000"
"sqlj SELECT name FROM funcs WHERE size > 100"
```

Use `sql` for a native r2 table, `sql,:csv` for CSV, and `sqlj` for the JSON
envelope and multiple statements. Wrap the whole command in double quotes
to protect SQL operators from r2's parser. See [SQL access](docs/sql.md).

## Analyze by asking your agent

Install the [r2xsql skills](https://github.com/radareorg/radare2-skills/tree/main/r2xsql#install)
alongside the plugin, then ask naturally:

> Open `target.exe` headlessly and show me the ten largest functions.
>
> Rename that function based on its disassembly and pseudocode.
>
> Save the project beside the executable and keep it open.

The agent uses native radare2 and curl, writes SQL for you, and reuses the
session on follow-ups. Saving preserves a native r2 project; SQL results are
computed from its analysis. See the [workflow guide](docs/usage.md).

## Tandem mode

Share an analysis session from r2's prompt, its visual/panels text interface,
or [iaito](https://github.com/radareorg/iaito). Open and analyze the binary,
check that r2xsql loaded, then enter these commands in the r2 prompt or
iaito's **View > Console**:

```text
e http.bind=127.0.0.1
e http.sandbox=false
e http.port=9090
=h&
```

Choose a free port and wait for the server banner. Tell your agent:
**Use r2xsql at http://127.0.0.1:9090 on the binary already open here.**
The background server leaves the UI available. Take turns when changing
analysis; use distinct ports for several sessions. See [tandem mode](docs/usage.md#tandem-mode).

## Fully headless

With an installed plugin, start a fresh binary in a background native process:

```sh
r2 -N -q -A -e scr.html=false -e http.bind=127.0.0.1 \
  -e http.sandbox=false -e http.port=9090 -c '=h' ./target \
  >r2.stdout.log 2>r2.stderr.log &
curl -d '"sqlj SELECT name,size FROM funcs ORDER BY size DESC LIMIT 10"' \
  http://127.0.0.1:9090/cmd/
```

Wait for readiness before querying. r2's HTTP server carries SQL and native
commands; r2xsql has no separate server. Bind to loopback: this endpoint can
change analysis and write files. Reopen a saved project with `r2 -p PROJECT`
without `-A` or a separate binary argument. The [workflow guide](docs/usage.md)
covers Windows launches, saves, reopening, shutdown and HTTP version differences.

## Documentation

- [User workflows and HTTP access](docs/usage.md)
- [SQL queries, formats and annotations](docs/sql.md)
- [Building, packaging and testing](docs/development.md)
- [Agent skills and schema reference](https://github.com/radareorg/radare2-skills/tree/main/r2xsql)

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified r2xsql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use r2xsql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by r2xsql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [radareorg/r2xsql/issues](https://github.com/radareorg/r2xsql/issues).

If r2xsql materially informs a distributed project, preserve the human origin: credit r2xsql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, radare2, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).
