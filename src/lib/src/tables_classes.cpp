// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Native reads for libr; command fallback for r2pipe and mock.

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

using direct::ClassRow;

using direct::ClassMethodRow;

}  // namespace

void register_classes_table(Session& s) {
  auto def = xsql::cached_table<ClassRow>("classes")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 64; })
    .cache_builder([be = s.backend_ptr()](std::vector<ClassRow>& rows) {
      if (auto* api = be->direct()) {
        api->classes_scan(rows);
        return;
      }
      auto arr = be->cmd_json("aclj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& c : arr) {
        if (!c.is_object()) continue;
        ClassRow r;
        r.name = json_utils::str(c, "name");

        auto bases_it = c.find("bases");
        if (bases_it != c.end() && bases_it->is_array() && !bases_it->empty() &&
            (*bases_it)[0].is_object()) {
          std::string base_name = json_utils::str((*bases_it)[0], "name");
          if (!base_name.empty()) r.base_name = std::move(base_name);
        }

        auto vt_it = c.find("vtables");
        if (vt_it != c.end() && vt_it->is_array() && !vt_it->empty() &&
            (*vt_it)[0].is_object()) {
          r.vtable_addr = json_utils::i64_addr((*vt_it)[0]);
        }

        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const ClassRow& r) { return r.name; })
    .column_text_nullable("base_name",
        [](const ClassRow& r) { return r.base_name; })
    .column("vtable_addr", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const ClassRow& r) {
          if (r.vtable_addr) ctx.result_int64(*r.vtable_addr);
          else ctx.result_null();
        })
    .build();
  s.db().register_and_create_cached_table(def);
}

void register_class_methods_table(Session& s) {
  auto def = xsql::cached_table<ClassMethodRow>("class_methods")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 256; })
    .cache_builder([be = s.backend_ptr()](std::vector<ClassMethodRow>& rows) {
      if (auto* api = be->direct()) {
        api->class_methods_scan(rows);
        return;
      }
      auto arr = be->cmd_json("aclj");
      if (!arr.is_array()) return;
      for (auto& c : arr) {
        if (!c.is_object()) continue;
        const std::string class_name = json_utils::str(c, "name");

        auto methods_it = c.find("methods");
        if (methods_it == c.end() || !methods_it->is_array()) continue;
        for (auto& m : *methods_it) {
          if (!m.is_object()) continue;
          ClassMethodRow r;
          r.class_name = class_name;
          r.name       = json_utils::str(m, "name");
          r.addr       = json_utils::i64_addr(m);
          // radare2 omits the "vtable_offset" key entirely for a non-virtual
          // method the recovery still attributed to the class (class.c only
          // emits it when meth->vtable_offset >= 0) -- absence, not a -1
          // sentinel, is how NULL is signaled here.
          auto vo_it = m.find("vtable_offset");
          if (vo_it != m.end() && vo_it->is_number_integer()) {
            r.vtable_offset = vo_it->get<int64_t>();
          }
          rows.push_back(std::move(r));
        }
      }
    })
    .column_text ("class_name", [](const ClassMethodRow& r) { return r.class_name; })
    .column_text ("name",       [](const ClassMethodRow& r) { return r.name; })
    .column_int64("addr",       [](const ClassMethodRow& r) { return r.addr; })
    .column("vtable_offset", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const ClassMethodRow& r) {
          if (r.vtable_offset) ctx.result_int64(*r.vtable_offset);
          else ctx.result_null();
        })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
