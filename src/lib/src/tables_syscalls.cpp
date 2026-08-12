// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// syscalls — a static per-(arch,bits,cpu,os) syscall name/number reference
// table, backed by `asj` (cmd_anal.inc.c -> r_syscall_list, libr/syscall/
// syscall.c). Confirmed via a standalone lab that this is a pure lookup
// table with zero dependency on the binary's actual bytes: the whole SDB is
// loaded once by `r_syscall_setup(arch, bits, cpu, os)`, keyed purely by
// that tuple. Not a per-binary occurrence list -- for "where in this binary
// are the syscalls", see `instructions` WHERE op_type = 'swi', which already
// answers that with no new table.
//
// The command is `asj` -- NOT `aslj` (that command does not exist; `asl` is
// the plain-text list, `asj` is its JSON form, per cmd_anal.inc.c's own help
// text).
//
// No pushdown: the whole table is small (hundreds of rows) and cheap (the
// SDB is already loaded when a session opens; `asj` is one command, no N+1).
//
// Deployment note (verified empirically, not assumed): the in-process
// `r2xsql-full` flavor is subject to the project's documented data-dir
// cliff for this table too, and it needed its OWN fix distinct from the
// `types`/calling-convention one -- `r_syscall_setup`'s SDB loader ignores
// `dir.prefix` (and every other core config) entirely, resolving its data
// directory purely via `r_sys_prefix(NULL)` (exe-relative on Windows, no
// override hook). See `backend_libr.cpp`'s `reload_syscall_db_from_prefix`
// for the fix; this table itself is unaffected by which backend/prefix
// resolution is in play -- it just issues `asj` and reports what comes back.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct SyscallRow {
  std::string name;
  int64_t     num = 0;
  std::string arch;
  std::string os;
};
}  // namespace

void register_syscalls_table(Session& s) {
  auto def = xsql::cached_table<SyscallRow>("syscalls")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 512; })
    .cache_builder([be = s.backend_ptr()](std::vector<SyscallRow>& rows) {
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
