# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
"""pytest fixtures for the r2xsql test-suite."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

import pytest

from test_support import R2xsqlRunner, build_fixture, find_r2xsql_plugin


@pytest.fixture(scope="session")
def r2_bin() -> str:
    path = os.environ.get("R2_BIN") or shutil.which("radare2") or shutil.which("r2")
    path = shutil.which(path) if path else None
    if not path:
        pytest.fail("radare2 is required; put it on PATH or set R2_BIN", pytrace=False)
    return str(Path(path).resolve())


@pytest.fixture(scope="session")
def r2xsql_plugin() -> Path:
    path = find_r2xsql_plugin()
    if path is None:
        pytest.fail(
            "no core_r2xsql plugin found. Build it first or set R2XSQL_PLUGIN "
            "to its path.", pytrace=False,
        )
    return path


@pytest.fixture(scope="session")
def fixture_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The compiled, deterministic fixture binary (see fixture.c), built
    once per test session into a session-scoped temp directory."""
    out_dir = tmp_path_factory.mktemp("r2xsql_fixture")
    return build_fixture(out_dir)


@pytest.fixture(scope="session")
def runner(r2_bin: str, r2xsql_plugin: Path, fixture_binary: Path) -> R2xsqlRunner:
    return R2xsqlRunner(r2_bin, r2xsql_plugin, fixture_binary)
