# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
"""Shared helpers for the r2xsql test-suite: locate the built CLI, build the
deterministic fixture, and run SQL queries against it.

This suite is standalone: it locates an already-built `r2xsql`/`r2xsql-full`
executable (build it yourself first, e.g. via this repo's own CMakeLists.txt)
rather than building r2xsql itself, and it compiles the fixture with whatever
C compiler is on PATH (`cc`/`gcc`/`clang` on Unix, `cl` on Windows inside a
Developer/VS shell) rather than assuming a specific build system.
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


def _candidate_binary_names() -> list[str]:
    exe = ".exe" if sys.platform == "win32" else ""
    return [f"r2xsql-full{exe}", f"r2xsql{exe}"]


def find_r2xsql_binary() -> Path | None:
    """Locate a built r2xsql CLI executable.

    Priority: the `R2XSQL_BIN` environment variable (an exact path), then a
    handful of common build-output locations under the repo root. Prefers
    `r2xsql-full` (libr, in-process) over the pipe-only `r2xsql`, since it
    exposes the complete schema (all 12 views; some builds of the pipe-only
    CLI have been observed missing the 4 `views_shared.cpp` views).
    `r2xsql-full` only resolves radare2's full data
    directory (calling conventions, syscalls, types) when the executable is
    deployed inside radare2's own install `bin/`; tests that are sensitive
    to that (see test_funcs_calltype_is_writable) are written to still be
    meaningful when it isn't.
    """
    env_path = os.environ.get("R2XSQL_BIN")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    search_dirs = [
        REPO_ROOT / "build",
        REPO_ROOT / "build" / "Release",
        REPO_ROOT / "build" / "Debug",
        REPO_ROOT / "out",
    ]
    for d in search_dirs:
        if not d.is_dir():
            continue
        for name in _candidate_binary_names():
            p = d / name
            if p.is_file():
                return p
        # one level deeper (e.g. build/<preset>/Release/r2xsql-full.exe)
        for sub in d.iterdir():
            if not sub.is_dir():
                continue
            for name in _candidate_binary_names():
                p = sub / name
                if p.is_file():
                    return p
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
    """A parsed r2xsql CLI response: tab-separated header + rows on success,
    `error: <message>` on stderr and a non-zero exit code on failure."""

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
    """Runs `-s <fixture> -q "<sql>"` against a fixed fixture binary."""

    def __init__(self, cli_path: Path, fixture_path: Path):
        self.cli_path = cli_path
        self.fixture_path = fixture_path

    def query(self, sql: str, *, write: bool = False, extra_args: list[str] | None = None) -> QueryResult:
        cmd = [str(self.cli_path), "-s", str(self.fixture_path)]
        if write:
            cmd.append("-w")
        if extra_args:
            cmd.extend(extra_args)
        cmd.extend(["-q", sql])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        columns, rows = _parse_tab_block(proc.stdout) if proc.returncode == 0 else ([], [])
        return QueryResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            columns=columns,
            rows=rows,
        )

    def script(self, statements: list[str], *, write: bool = False) -> QueryResult:
        """Run several statements in ONE session (`-i` REPL, fed via stdin),
        returning the LAST statement's result.

        `-q "a; b"` only executes/prints the FIRST statement (a libxsql
        `Session::query()` property, not an r2xsql bug) and a write from
        one `-q` call is not visible
        to a separate `-q` call (a fresh process re-opens the file from
        scratch). The REPL runs each line as its own `query()` call against
        the SAME open session, so an earlier write's effect is visible to a
        later read -- the only CLI mode that supports this today.
        """
        cmd = [str(self.cli_path), "-s", str(self.fixture_path)]
        if write:
            cmd.append("-w")
        cmd.append("-i")
        stdin = "\n".join(statements) + "\n.quit\n"
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, timeout=60
        )
        # REPL output: banner lines, then "sql> " (no trailing newline) before
        # each statement's result. Strip the banner, split on the prompt, and
        # parse the last non-empty chunk (the final statement's output).
        banner_end = proc.stdout.find("raw r2 command")
        tail = proc.stdout[proc.stdout.find("\n", banner_end) + 1:] if banner_end != -1 else proc.stdout
        chunks = [c for c in tail.split("sql> ") if c.strip()]
        last = chunks[-1] if chunks else ""
        columns, rows = _parse_tab_block(last) if proc.returncode == 0 else ([], [])
        return QueryResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            columns=columns,
            rows=rows,
        )


def _parse_tab_block(text: str) -> tuple[list[str], list[list[str]]]:
    lines = text.splitlines()
    if not lines:
        return [], []
    columns = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:] if line != ""]
    return columns, rows
