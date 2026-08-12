# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
"""pytest fixtures for the r2xsql test-suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from test_support import R2xsqlRunner, build_fixture, find_r2xsql_binary


@pytest.fixture(scope="session")
def r2xsql_bin() -> Path:
    """The built r2xsql CLI. Fails loudly (not a skip) when absent: an
    unbuilt binary is a build-environment problem to fix, not a test to
    quietly not run. Point R2XSQL_BIN at an executable to override the
    search."""
    path = find_r2xsql_binary()
    if path is None:
        pytest.fail(
            "no r2xsql/r2xsql-full binary found. Build it first (see this "
            "repo's CMakeLists.txt), or set R2XSQL_BIN to an explicit path.",
            pytrace=False,
        )
    return path


@pytest.fixture(scope="session")
def fixture_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The compiled, deterministic fixture binary (see fixture.c), built
    once per test session into a session-scoped temp directory."""
    out_dir = tmp_path_factory.mktemp("r2xsql_fixture")
    return build_fixture(out_dir)


@pytest.fixture(scope="session")
def runner(r2xsql_bin: Path, fixture_binary: Path) -> R2xsqlRunner:
    return R2xsqlRunner(r2xsql_bin, fixture_binary)
