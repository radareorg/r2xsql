// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {

using direct::RelocRow;

}  // namespace

void register_relocs_table(Session& s) {
  auto def = xsql::cached_table<RelocRow>("relocs")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 512; })
    .cache_builder([be = s.backend_ptr()](std::vector<RelocRow>& rows) {
      if (auto* api = be->direct()) {
        api->relocs_scan(rows);
        return;
      }
      auto arr = be->cmd_json("irj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        if (!j.is_object()) continue;
        RelocRow r;
        r.addr  = json_utils::i64(j, "vaddr");
        r.paddr = json_utils::i64(j, "paddr");
        r.type  = json_utils::str(j, "type");
        r.ntype = json_utils::i64(j, "ntype");
        if (auto it = j.find("name"); it != j.end() && it->is_string()) {
          r.name = it->get<std::string>();
        }
        if (auto it = j.find("demname"); it != j.end() && it->is_string()) {
          r.demname = it->get<std::string>();
        }
        if (auto it = j.find("sym_va"); it != j.end() && it->is_number_integer()) {
          r.sym_vaddr = it->get<int64_t>();
        }
        r.is_ifunc = json_utils::boolean(j, "is_ifunc");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",  [](const RelocRow& r) { return r.addr; })
    .column_int64("paddr", [](const RelocRow& r) { return r.paddr; })
    .column_text ("type",  [](const RelocRow& r) { return r.type; })
    .column_int64("ntype", [](const RelocRow& r) { return r.ntype; })
    .column_text_nullable("name",    [](const RelocRow& r) { return r.name; })
    .column_text_nullable("demname", [](const RelocRow& r) { return r.demname; })
    .column("sym_vaddr", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const RelocRow& r) {
          if (r.sym_vaddr) ctx.result_int64(*r.sym_vaddr);
          else ctx.result_null();
        })
    .column_int64("is_ifunc", [](const RelocRow& r) { return r.is_ifunc ? 1 : 0; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
