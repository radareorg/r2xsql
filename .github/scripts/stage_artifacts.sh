#!/usr/bin/env bash
# Stage r2xsql release trees from a completed build:
#   dist/overlay/  — extract ON TOP OF a radare2 install prefix (libr drop-in):
#                      bin/r2xsql[.exe]            (next to radare2[.exe])
#                      <r2-plugin-dir>/core_r2xsql.*  (r2's own plugin search dir)
#   dist/pipe/     — standalone pipe-only r2xsql[.exe] (needs radare2 on PATH)
#
# The plugin's relative path is derived from the installed prefix layout so the
# overlay drops the plugin exactly where this r2 looks for it — Linux uses
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
# plugin dir often does NOT exist on disk after install (the overlay creates it):
#   * Windows (meson): <prefix>/lib/plugins                 — and there is no
#     */radare2/<version> dir at all, so the scan below finds nothing.
#   * Unix    (meson): <prefix>/<libdir>/radare2/<version>  (libdir = lib, lib64,
#     or lib/<triplet>), reconstructed from the data-dir <version> and where
#     libr_core landed.
# `|| true` keeps an empty find from tripping pipefail+errexit (which would kill
# the script before it prints anything — exactly the Windows symptom).
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
echo "radare2 plugin overlay dir: ${REL_PLUGIN}"

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
mkdir -p "dist/overlay/bin" "dist/overlay/${REL_PLUGIN}" "dist/pipe"

# Both flavors come from the SAME build tree (one configure with
# R2XSQL_BUILD_FULL=ON): r2xsql (pipe), r2xsql-full (libr CLI), core_r2xsql (plugin).

# --- overlay: full (libr) CLI + in-r2 plugin ---
copy_first "dist/overlay/bin/" \
  build/bin/r2xsql-full build/bin/r2xsql-full.exe \
  build/bin/Release/r2xsql-full.exe build/src/cli/r2xsql-full build/src/cli/Release/r2xsql-full.exe

copy_first "dist/overlay/${REL_PLUGIN}/" \
  build/bin/core_r2xsql.so build/bin/core_r2xsql.dylib build/bin/core_r2xsql.dll \
  build/bin/Release/core_r2xsql.dll build/src/plugin/core_r2xsql.so \
  build/src/plugin/Release/core_r2xsql.dll

# --- pipe-only: standalone single binary (same build tree) ---
copy_first "dist/pipe/" \
  build/bin/r2xsql build/bin/r2xsql.exe \
  build/bin/Release/r2xsql.exe build/src/cli/r2xsql build/src/cli/Release/r2xsql.exe

cat > dist/overlay/README.txt <<EOF
r2xsql-full — radare2 drop-in (overlay, embedded/libr flavor)

Extract this archive ON TOP OF your radare2 install prefix (the directory
that contains bin/radare2[.exe]). It adds:

  bin/r2xsql-full[.exe]          full CLI + HTTP/MCP server (in-process libr)
  ${REL_PLUGIN}/core_r2xsql.*    in-r2 plugin (load inside r2: L core_r2xsql.<ext>)

Because r2xsql-full then sits next to radare2[.exe], the libr backend finds
radare2's data dir (share/) automatically, so the 'types' table and
ordinal imports resolve fully.

Usage:
  r2xsql-full -s <file> -q "SELECT name FROM funcs LIMIT 5"
  radare2 <file>     then inside r2:   sql SELECT * FROM funcs

(For a portable build that needs no co-location, see the pipe-only r2xsql.)

Built against radare2 ${R2_REF}.
EOF

cat > dist/pipe/README.txt <<EOF
r2xsql — pipe-only single binary

A standalone r2xsql[.exe] with NO radare2 libraries linked. It drives
radare2 over a pipe (--r2pipe), so it only needs radare2[.exe] somewhere
on PATH at runtime. Place it anywhere.

Usage:
  r2xsql -s <file> -q "SELECT name FROM funcs LIMIT 5"

Built against radare2 ${R2_REF} (API-compatible r2 on PATH is sufficient).
EOF

echo "=== staged tree ==="
find dist -type f | sort
