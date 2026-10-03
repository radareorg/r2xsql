#!/usr/bin/env bash
# Stage the same plugins/ layout on every platform for r2pm -bi.
set -euo pipefail

# The pinned radare2 predates r2pm -H R2PM_TRIPLET.
case "${RUNNER_OS}-${RUNNER_ARCH}" in
  Linux-X64) R2PM_TRIPLET=linux-x86-64; ext=so ;;
  Windows-X64) R2PM_TRIPLET=windows-x86-64; ext=dll ;;
  macOS-X64) R2PM_TRIPLET=darwin-x86-64; ext=dylib ;;
  macOS-ARM64) R2PM_TRIPLET=darwin-arm-64; ext=dylib ;;
  *) echo "Unsupported runner: ${RUNNER_OS}-${RUNNER_ARCH}" >&2; exit 1 ;;
esac

rm -rf dist
mkdir -p dist/plugin/plugins
cp "build/bin/core_r2xsql.${ext}" dist/plugin/plugins/
cp LICENSE dist/plugin/

# Check automatic discovery of the packaged plugin, including its suffix.
result=$(R2_LIBR_PLUGINS="$PWD/dist/plugin/plugins" \
  LD_LIBRARY_PATH="$PWD/r2prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  DYLD_LIBRARY_PATH="$PWD/r2prefix/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  ./r2prefix/bin/radare2 -Nq -c 'sqlj SELECT 1 AS ok' -)
[[ "$result" == *'"rows":[["1"]]'* ]] || { echo "$result" >&2; exit 1; }

cat > dist/plugin/README.txt <<EOF
r2xsql — radare2 core plugin

Built against radare2 ${R2_REF} for ${R2PM_TRIPLET}.
Install with a matching radare2 version and a recent r2pm:

  r2pm -U
  r2pm -bi r2xsql

Or copy plugins/core_r2xsql.${ext} into the directory printed by
radare2 -NN -H R2_USER_PLUGINS (per-user) or R2_LIBR_PLUGINS (system-wide).
Remove that file to uninstall. Rebuild for a different radare2 ABI.

At the radare2 prompt:
  aaa
  sql SELECT name, size FROM funcs LIMIT 5
  sql,:csv SELECT name, size FROM funcs LIMIT 5
  "sqlj SELECT name FROM funcs WHERE size > 100; SELECT count(*) FROM strings"

sql prints a native radare2 table; sqlj returns a JSON envelope for scripts,
including SQL NULLs and one result per statement. Quote the whole command
with double quotes to preserve SQL operators and statement separators.
Analysis is explicit: run aaa or start radare2 with -A.

The plugin also works through radare2's own HTTP server:
  radare2 -e http.bind=127.0.0.1 -e http.port=9090 -c aaa -c '=h' <file>
  curl --data-binary '"sqlj SELECT name FROM funcs LIMIT 5"' http://127.0.0.1:9090/cmd/

Read the command output for errors even when HTTP returns status 200.
Save analysis with Ps NAME before exiting; binary byte writes require -w.
EOF

printf 'name=r2xsql-%s-%s\n' "$R2_REF" "$R2PM_TRIPLET" >> "$GITHUB_OUTPUT"
find dist -type f | sort
