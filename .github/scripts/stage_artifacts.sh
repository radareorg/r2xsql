#!/usr/bin/env bash
# Stage the r2xsql release tree from a completed build:
#   dist/plugin/  — extract ON TOP OF a radare2 install prefix:
#                     <r2-plugin-dir>/core_r2xsql.*  (r2's own plugin search dir)
#
# r2xsql ships ONE artifact, the in-r2 core plugin. There is no CLI and no
# server of its own; radare2 hosts it and carries the `sql` / `sqlj` commands
# over the console, r2pipe, `=h` and MCP alike.
#
# The plugin's relative path is derived from the installed prefix layout so the
# archive drops it exactly where this r2 looks for it — Linux uses
# <libdir>/radare2/<ver>/, Windows uses lib/plugins.
set -euo pipefail

PFX="${GITHUB_WORKSPACE}/r2prefix"
# On Windows runners GITHUB_WORKSPACE is a backslash path (D:\a\r2xsql\r2xsql),
# which find/grep/test choke on under Git-Bash. Normalize to a Unix-style path
# (cygpath exists only in Git-Bash; a no-op elsewhere).
if command -v cygpath >/dev/null 2>&1; then
  PFX="$(cygpath -u "${GITHUB_WORKSPACE}")/r2prefix"
fi

# radare2's system plugin dir, RELATIVE to the prefix, derived from the installed
# layout (we do NOT run radare2 — `radare2 -H` drops into r2pipe mode under CI
# pipes). The default meson build links the core plugins statically, so the
# plugin dir often does NOT exist on disk after install (we create it):
#   * Windows (meson): <prefix>/lib/plugins                 — and there is no
#     */radare2/<version> dir at all, so the scan below finds nothing.
#   * Unix    (meson): <prefix>/<libdir>/radare2/<version>  (libdir = lib, lib64,
#     or lib/<triplet>), reconstructed from the data-dir <version> and where
#     libr_core landed.
# `|| true` keeps an empty find from tripping pipefail+errexit (which would kill
# the script before it prints anything — exactly the Windows symptom).
#
# This derivation is now the WHOLE product: it used to be one half of a
# two-tree stage, so a bug here degraded an overlay. Now a bug here ships the
# only artifact to the wrong path.
REL_PLUGIN=""
if [ -d "${PFX}/lib/plugins" ]; then
  REL_PLUGIN="lib/plugins"
else
  VER_DIR="$(find "${PFX}" -type d -path '*/radare2/*' 2>/dev/null \
               | grep -E '/radare2/[0-9][^/]*$' | head -1 || true)"
  if [ -n "${VER_DIR}" ]; then
    R2_VER="$(basename "${VER_DIR}")"
    # Match the import/shared lib (libr_core.* on Unix, r_core.lib on Windows),
    # never the header r_core.h.
    CORE_LIB="$(find "${PFX}" -maxdepth 4 \
                  \( -name 'libr_core.*' -o -name 'r_core.lib' -o -name 'r_core.dll.a' \) \
                  2>/dev/null | head -1 || true)"
    if [ -n "${CORE_LIB}" ]; then
      REL_LIBDIR="$(dirname "${CORE_LIB}")"
      REL_LIBDIR="${REL_LIBDIR#"${PFX}/"}"
      REL_PLUGIN="${REL_LIBDIR}/radare2/${R2_VER}"
    fi
  fi
fi
# Fallback (Windows static-plugin builds expose no versioned dir): radare2 looks
# for system plugins in <prefix>/lib/plugins.
if [ -z "${REL_PLUGIN}" ]; then
  REL_PLUGIN="lib/plugins"
fi
echo "radare2 plugin dir: ${REL_PLUGIN}"

# Helper: copy the first path that exists.
copy_first() {
  local dest="$1"; shift
  local src
  for src in "$@"; do
    if [ -f "$src" ]; then cp "$src" "$dest"; return 0; fi
  done
  echo "ERROR: none of these exist: $*" >&2
  return 1
}

rm -rf dist
mkdir -p "dist/plugin/${REL_PLUGIN}"

copy_first "dist/plugin/${REL_PLUGIN}/" \
  build/bin/core_r2xsql.so build/bin/core_r2xsql.dylib build/bin/core_r2xsql.dll \
  build/bin/Release/core_r2xsql.dll build/src/plugin/core_r2xsql.so \
  build/src/plugin/Release/core_r2xsql.dll

cat > dist/plugin/README.txt <<EOF
r2xsql — SQL over a live radare2 session (in-r2 plugin)

Extract this archive ON TOP OF your radare2 install prefix (the directory
that contains bin/radare2[.exe]). It adds:

  ${REL_PLUGIN}/core_r2xsql.*    the plugin

Confirm it loaded, and check its version:

  radare2 -q -c 'Lcj' /bin/ls | grep r2xsql

Usage — two commands, inside radare2:

  sql  <SQL>     tab-separated text table (for a human)
  sqlj <SQL>     JSON envelope (for a program): multiple statements, real NULLs

  radare2 -q -A -c '"sqlj SELECT name, size FROM funcs LIMIT 5"' <file>

TWO THINGS THAT FAIL SILENTLY IF YOU MISS THEM:

  1. WRAP THE COMMAND IN DOUBLE QUOTES. radare2's parser claims '>' and '|'
     before the plugin runs, so an unquoted
         sqlj SELECT name FROM funcs WHERE size > 100
     returns NOTHING and writes a file named '100'. The single-quote form
     works at the console but still returns nothing over HTTP — use '"'.

  2. PASS -A (or run 'aaa'). radare2 does not analyze by default, so without
     it every funcs/xrefs query returns zero rows.

Serving it over HTTP is radare2's own server — there is no r2xsql port:

  radare2 -e http.sandbox=false -c 'aaa; =h 9090' <file>
  curl -X POST http://127.0.0.1:9090/cmd/ -d '"sqlj SELECT * FROM binary"'

Wait for r2's 'open http://' line on stderr before the first request. Stop it
with 'q!!' — plain 'q!' does not. Bind to 127.0.0.1 only: r2's HTTP server is
not a security boundary.

ABI: this plugin is locked to radare2 ${R2_REF} and will not load into any
other build. Rebuild it when you upgrade radare2.
EOF

echo "=== staged tree ==="
find dist -type f | sort
