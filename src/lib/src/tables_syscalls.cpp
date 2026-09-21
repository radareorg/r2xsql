// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Native reads for libr; command fallback for r2pipe and mock.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::SyscallRow;
}  // namespace

void register_syscalls_table(Session& s) {
  auto def = xsql::cached_table<SyscallRow>("syscalls")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 512; })
    .cache_builder([be = s.backend_ptr()](std::vector<SyscallRow>& rows) {
      if (auto* api = be->direct()) {
        api->syscalls_scan(rows);
        return;
      }
      // `arch`/`os` are session config (asm.arch/asm.os), the same variables
      // `r_syscall_setup` is keyed on -- read once per build, echoed onto
      // every row rather than re-queried per row (the table is already
      // scoped to the current session's single target; no cross-arch union
      // exists to distinguish rows by).
      const std::string arch = table_utils::trim_ascii(be->cmd("e asm.arch"));
      const std::string os   = table_utils::trim_ascii(be->cmd("e asm.os"));

      auto arr = be->cmd_json("asj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        SyscallRow r;
        r.name = json_utils::str(j, "name");
        r.num  = json_utils::i64(j, "num");
        r.arch = arch;
        r.os   = os;
        rows.push_back(std::move(r));
      }
    })
    .column_text ("name", [](const SyscallRow& r) { return r.name; })
    .column_int64("num",  [](const SyscallRow& r) { return r.num; })
    .column_text ("arch", [](const SyscallRow& r) { return r.arch; })
    .column_text ("os",   [](const SyscallRow& r) { return r.os; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
