// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// runtime_settings — writable live view over the r2sql runtime controls
// (key TEXT, value TEXT, type TEXT, scope TEXT). r2sql carries only the 8 shared
// keys (scope "common" / "action"); it adds no tool-specific runtime knobs, so the
// canonical table is built directly from the shared libxsql helper over the
// session's RuntimeSettingsCore -- no per-tool definition. Change a value setting
// with `UPDATE runtime_settings SET value=... WHERE key=...`; key/type/scope, the
// read-only rows (timeout_stack_depth/max_timeout_stack_depth) and the action verbs
// (timeout_push/timeout_pop) reject writes; INSERT/DELETE are rejected.

#include <r2sql/session.hpp>
#include <r2sql/runtime_settings.hpp>

#include <xsql/runtime_settings_table.hpp>

#include "tables.hpp"

namespace r2sql {

void register_runtime_settings_table(Session& s) {
  s.db().register_and_create_cached_table(
      xsql::runtime::define_runtime_settings_table(
          s.runtime_settings().common_settings(), "r2sql"));
}

}  // namespace r2sql
