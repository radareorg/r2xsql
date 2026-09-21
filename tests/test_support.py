# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
"""Locate the built plugin, compile a deterministic fixture, and run SQL
through radare2. Build r2xsql first; the fixture only needs a C compiler.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent  # r2xsql/


def find_r2xsql_plugin() -> Path | None:
    """Find the plugin from R2XSQL_PLUGIN or a CMake, Make, or Meson build."""
    env_path = os.environ.get("R2XSQL_PLUGIN")
    if env_path:
        path = Path(env_path).resolve()
        return path if path.is_file() else None
    for name in ("build", "build-make", "build-meson", "out"):
        for path in sorted((REPO_ROOT / name).rglob("core_r2xsql.*")):
            if path.is_file() and path.suffix in (".so", ".dylib", ".dll"):
                return path.resolve()
    return None


def _find_c_compiler() -> list[str] | None:
    # On Windows, prefer cl.exe (MSVC) first and unconditionally: Visual
    # Studio ships its own clang.exe on PATH inside a Developer/vcvars shell,
    # and shutil.which("clang") happily finds it -- but that's plain
    # clang.exe (GNU-style driver), not clang-cl, so it silently mis-parses
    # the MSVC-style /Fe:/nologo flags below rather than erroring. Checking
    # cl first avoids ever reaching that trap on the platform this project
    # actually builds on.
    if sys.platform == "win32" and shutil.which("cl"):
        return ["cl", "/nologo"]
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc):
            return [cc]
    return None


def build_fixture(out_dir: Path) -> Path:
    """Compile tests/fixture.c into a native executable under out_dir.

    Raises RuntimeError with an actionable message if no compiler is found
    (a build environment problem, not a test failure to hide).
    """
    src = TESTS_DIR / "fixture.c"
    exe = out_dir / ("r2xsql_fixture.exe" if sys.platform == "win32" else "r2xsql_fixture")
    cc = _find_c_compiler()
    if cc is None:
        raise RuntimeError(
            "no C compiler found on PATH (tried cc/gcc/clang, and cl on Windows) "
            "-- install one or run pytest from a shell with a compiler on PATH"
        )
    if cc[0] == "cl":
        # No /Zi: a plain PE carries no local function names at all regardless
        # (unlike an ELF built with `gcc -g`, which embeds a full local
        # symtab directly in the binary) -- radare2 recovers "entry0"/"main"
        # from its own CRT-startup heuristic either way, which is what every
        # by-name assertion in this suite keys off. /Zi was tried and
        # dropped: it forces MSVC's default incremental linking, which
        # produces a PE radare2 mis-reads at the entry point (0xFF filler
        # instead of the real prologue) even though the binary runs fine --
        # not worth the /link /INCREMENTAL:NO workaround for data this suite
        # doesn't otherwise need.
        cmd = cc + ["/Fe:" + str(exe), str(src)]
    else:
        cmd = cc + ["-O0", "-g", "-o", str(exe), str(src)]
    proc = subprocess.run(cmd, cwd=out_dir, capture_output=True, text=True)
    if proc.returncode != 0 or not exe.is_file():
        raise RuntimeError(
            f"failed to build fixture with {cc[0]}: rc={proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return exe


@dataclass
class QueryResult:
    """A parsed plugin response, including SQL errors printed on stdout."""

    returncode: int
    stdout: str
    stderr: str
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def column(self, name: str) -> list[str]:
        if name not in self.columns:
            return []
        idx = self.columns.index(name)
        return [r[idx] for r in self.rows]

    def contains(self, needle: str) -> bool:
        """Substring search over the raw stdout, for assertions that only need
        presence, not structure."""
        return needle in self.stdout


class R2xsqlRunner:
    """Run SQL through the plugin against a fixed fixture binary."""

    def __init__(self, r2_path: str, plugin_path: Path, fixture_path: Path):
        self.r2_path = r2_path
        self.plugin_path = plugin_path
        self.fixture_path = fixture_path

    def query(self, sql: str, *, write: bool = False) -> QueryResult:
        return self.script([sql], write=write)

    def script(self, statements: list[str], *, write: bool = False,
               setup_commands: list[str] | None = None) -> QueryResult:
        """Run statements in one session and return the last table's rows."""
        cmd = [self.r2_path, "-N", "-q", "-e", "scr.color=0",
               "-i", str(self.plugin_path), "-c", "aaa"]
        if write:
            cmd.append("-w")
        for command in setup_commands or []:
            cmd.extend(["-c", command])
        for sql in statements:
            cmd.extend(["-c", "?e R2XSQL_RESULT_BEGIN",
                        "-c", '"sql,:tsv ' + sql.replace('"', '\\"') + '"'])
        cmd.extend(["-c", "?e R2XSQL_RESULT_END"])
        cmd.append(str(self.fixture_path))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        errors = [line for line in proc.stdout.splitlines()
                  if line.startswith(("ERROR:", "EXCEPTION:"))]
        completed = proc.stdout.rstrip().endswith("R2XSQL_RESULT_END")
        columns, rows = _parse_tab_block(proc.stdout)
        return QueryResult(
            returncode=proc.returncode or int(bool(errors) or not completed),
            stdout=proc.stdout,
            stderr=proc.stderr + "\n".join(errors),
            columns=columns,
            rows=rows,
        )


def _parse_tab_block(text: str) -> tuple[list[str], list[list[str]]]:
    # Result markers delimit the last TSV table, including an empty write result.
    _, found, table = text.rpartition("R2XSQL_RESULT_BEGIN\n")
    if not found:
        return [], []
    lines = table.removesuffix("R2XSQL_RESULT_END\n").strip("\r\n").splitlines()
    if not lines:
        return [], []
    return lines[0].split("\t"), [line.split("\t") for line in lines[1:]]
