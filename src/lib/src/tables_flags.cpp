// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// flags — `fj` for read; `fr <old> <new>` for renames; `f- @ <addr>` for deletes.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct FlagRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string name;
  std::string realname;
  std::string space;
};
}  // namespace

void register_flags_table(Session& s) {
  auto def = xsql::cached_table<FlagRow>("flags")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "fj~?", 4096);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<FlagRow>& rows) {
      auto arr = be->cmd_json("fj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        FlagRow r;
        r.addr     = json_utils::i64_addr(j);
        r.size     = json_utils::i64(j, "size");
        r.name     = json_utils::str(j, "name");
        r.realname = json_utils::str(j, "realname");
        auto dot = r.name.find('.');
        if (dot != std::string::npos) r.space = r.name.substr(0, dot);
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",     [](const FlagRow& r) { return r.addr; })
    .column_int64("size",     [](const FlagRow& r) { return r.size; })
    .column_text_rw("name",
      [](const FlagRow& r) { return r.name; },
      [be = s.backend_ptr()](FlagRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_flag_name(v)) {
          xsql::set_vtab_error(
              "flags: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
          return false;
        }
        // Try function rename first (afn) — covers the common case where the
        // flag is a function symbol. If that's a no-op, plain `fr` works too.
        // NOTE: per-command error-surfacing is intentionally NOT applied here:
        // this is a deliberate try-both fallback where exactly one of afn/fr is
        // expected to be a no-op (afn fails for a non-function flag; fr fails
        // when afn already renamed it), so a single command's diagnostic is not
        // a real failure. Only the single-command flag write paths (INSERT /
        // DELETE) below surface r2 errors.
        std::string afn = std::string("afn ") + v + " @ " + json_utils::hex_addr(r.addr);
        (void)be->cmd(afn);
        std::string fr = std::string("fr ") + r.name + " " + v;
        (void)be->cmd(fr);
        r.name = v;
        return true;
      })
    .column_text ("realname", [](const FlagRow& r) { return r.realname; })
    .column_text ("space",    [](const FlagRow& r) { return r.space; })
    .deletable([be = s.backend_ptr()](FlagRow& r) -> bool {
      std::string out = be->cmd("f- @ " + json_utils::hex_addr(r.addr));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("flags: DELETE failed (addr=" +
                             json_utils::hex_addr(r.addr) + "): " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns: addr(0), size(1), name(2), realname(3), space(4).
      if (argc < 3 || argv[0].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("flags: INSERT requires addr and name");
        return false;
      }
      const int64_t addr = argv[0].as_int64();
      const char* name = argv[2].as_c_str();
      if (!name || !*name) {
        xsql::set_vtab_error("flags: INSERT requires a non-empty name");
        return false;
      }
      if (!json_utils::valid_flag_name(name)) {
        xsql::set_vtab_error(
            "flags: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
        return false;
      }
      std::string out = be->cmd(std::string("f ") + name + " @ " + json_utils::hex_addr(addr));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error(std::string("flags: INSERT failed (name=") + name + "): " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql


