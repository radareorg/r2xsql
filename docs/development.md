# Building and testing r2xsql

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

## Binary releases

The plugin release version and radare2 version are separate. A plugin release
such as `v0.0.1` contains assets named
`r2xsql-<radare2-version>-<R2PM_TRIPLET>.zip`, for example
`r2xsql-6.2.4-linux-x86-64.zip`. Each archive contains the plugin in `plugins/`.
The current CI targets Linux x64, Windows x64 and macOS ARM64 against radare2
6.2.4. A different engine ABI needs a matching build, including iaito's engine.

Pushing a `v*` tag runs the build workflow and, after all platform builds
succeed, creates a GitHub Release with the ZIPs attached. Branch builds and
manual workflow runs upload CI artifacts without publishing a release.
Keep `R2_REF` in `.github/workflows/build.yml` and the compatibility table in
[`radare2-pm/db/r2xsql`](https://github.com/radareorg/radare2-pm/blob/master/db/r2xsql)
aligned. The recipe uses `R2PM_VERSION_MAP` to map the installed radare2 version
(`R2V`) to the plugin release tag (`R2PM_VERSION`). It downloads from that exact
release, retaining `R2V` in the asset name to select the compatible build.
Add a mapping only when that release supplies a build for the engine version;
a new r2pm version alone does not make an older plugin ABI compatible.

Binary installation requires r2pm with `R2PM_VERSION_MAP` support, available in
radare2 git and planned for radare2 6.2.6. Radare2 6.2.4 introduced binary
installation, but its r2pm lacks this mapping facility. The mapped release
and matching target asset must also be published; a CI artifact alone is not
enough. With a suitable r2pm, use `r2pm -U` then `r2pm -bi r2xsql`; uninstall
with `r2pm -u r2xsql`. Unsupported versions or targets fail instead of falling
back to a source build. To install manually, copy the matching plugin to the
directory printed by `radare2 -NN -H R2_USER_PLUGINS`.

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
