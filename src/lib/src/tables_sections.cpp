// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// sections — `iSj`.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct SectionRow {
  int64_t     addr = 0;
  int64_t     vsize = 0;
  int64_t     paddr = 0;
  int64_t     size = 0;
  std::string name;
  std::string perm;
};
}  // namespace

void register_sections_table(Session& s) {
  auto def = xsql::cached_table<SectionRow>("sections")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "iS~?", 64);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<SectionRow>& rows) {
      auto arr = be->cmd_json("iSj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        SectionRow r;
        r.addr  = json_utils::i64(j, "vaddr");
        r.vsize = json_utils::i64(j, "vsize");
        r.paddr = json_utils::i64(j, "paddr");
        r.size  = json_utils::i64(j, "size");
        r.name  = json_utils::str(j, "name");
        r.perm  = json_utils::str(j, "perm");
        rows.push_back(std::move(r));
      }
    })
    // Canonical address range (the cross-tool names). Clean break: the old r2
    // `addr` column is replaced by `start_addr` (no alias). `vsize`/`paddr`/
    // `size` stay as radare2-specific extras.
    .column_int64("start_addr", [](const SectionRow& r) { return r.addr; })
    .column_int64("end_addr",   [](const SectionRow& r) { return r.addr + r.vsize; })
    .column_int64("vsize", [](const SectionRow& r) { return r.vsize; })
    .column_int64("paddr", [](const SectionRow& r) { return r.paddr; })
    .column_int64("size",  [](const SectionRow& r) { return r.size; })
    .column_text ("name",  [](const SectionRow& r) { return r.name; })
    .column_text ("perm",  [](const SectionRow& r) { return r.perm; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql

