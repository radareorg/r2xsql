// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// types — radare2 type system catalog.
//
// Backed by:
//   tk*   list of `NAME=KIND` pairs (atomic|struct|union|enum|typedef|func)
//   tj    array of atomic-type records with size + pf format
//   tsj N struct definition (name, format, fields[])
//   tuj N union definition  (same shape as tsj)
//   tej N enum  definition  (name, values{key:int, ...})
//
// One row per type. Columns:
//   name      TEXT  — fully qualified type name
//   kind      TEXT  — atomic | struct | union | enum | typedef | func | type
//   size      INT64 — byte size (-1 for unsized/opaque/pointer-like)
//   format    TEXT  — pf-style format string (atomics/structs/unions); empty otherwise

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2sql {

namespace {

struct TypeRow {
  std::string name;
  std::string kind;
  int64_t     size = 0;
  std::string format;
};

}  // namespace

void register_types_table(Session& s) {
  auto def = xsql::cached_table<TypeRow>("types")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 256; })
    .cache_builder([be = s.backend_ptr()](std::vector<TypeRow>& rows) {
      auto kinds = json_utils::parse_tk_dump(be->cmd("tk*"));
      if (kinds.empty()) return;

      // Enrich atomics with size + pf format from `tj`.
      std::unordered_map<std::string, std::pair<int64_t, std::string>> atomic_info;
      auto tj = be->cmd_json("tj");
      if (tj.is_object()) {
        const auto& arr = tj.contains("types") ? tj["types"] : nlohmann::json::array();
        for (const auto& j : arr) {
          atomic_info[json_utils::str(j, "type")] =
              {json_utils::i64(j, "size", -1), json_utils::str(j, "format")};
        }
      }

      rows.reserve(kinds.size());
      for (auto& [name, kind] : kinds) {
        TypeRow r;
        r.name = name;
        r.kind = kind;
        r.size = -1;
        if (kind == "atomic" || kind == "type") {
          auto it = atomic_info.find(name);
          if (it != atomic_info.end()) {
            r.size   = it->second.first;
            r.format = it->second.second;
          }
        } else if (kind == "struct" || kind == "union") {
          auto cmd = (kind == "struct" ? std::string("tsj ") : std::string("tuj ")) + name;
          auto j = be->cmd_json(cmd);
          if (j.is_object()) {
            r.format = json_utils::str(j, "format");
            int64_t total = 0;
            int64_t max_field = 0;
            if (j.contains("fields") && j["fields"].is_array()) {
              for (const auto& f : j["fields"]) {
                int64_t sz = json_utils::i64(f, "size");
                int64_t ar = json_utils::i64(f, "array_size", 1);
                if (ar <= 0) ar = 1;
                int64_t fsize = sz * ar;
                if (kind == "struct") total += fsize;
                else if (fsize > max_field) max_field = fsize;
              }
            }
            r.size = (kind == "struct") ? total : max_field;
          }
        }
        rows.push_back(std::move(r));
      }
      std::sort(rows.begin(), rows.end(),
                [](const TypeRow& a, const TypeRow& b) { return a.name < b.name; });
    })
    .column_text ("name",   [](const TypeRow& r) { return r.name; })
    .column_text ("kind",   [](const TypeRow& r) { return r.kind; })
    .column_int64("size",   [](const TypeRow& r) { return r.size; })
    .column_text ("format", [](const TypeRow& r) { return r.format; })
    // DELETE FROM types WHERE name='X' removes the type (`t- X`). Creation
    // needs a full C declaration that doesn't fit the row columns, so it is
    // exposed via the r2sql_type_define('<C decl>') scalar function instead.
    .deletable([be = s.backend_ptr()](TypeRow& r) -> bool {
      if (r.name.empty() || !json_utils::valid_flag_name(r.name)) {
        xsql::set_vtab_error("types: refusing to delete an unsafe/empty type name");
        return false;
      }
      if (std::string e = table_utils::command_error_text(be->cmd("t- " + r.name)); !e.empty()) {
        xsql::set_vtab_error("types: DELETE failed (name=" + r.name + "): " + e);
        return false;
      }
      return true;
    })
    .build();
  (void)s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
