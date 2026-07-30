// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// types_members — fields of structs/unions and constants of enums.
//
// Columns:
//   type_name   TEXT  — parent type
//   parent_kind TEXT  — "struct" | "union" | "enum"
//   member_name TEXT  — field or enum constant name
//   member_type TEXT  — field type (empty for enum constants)
//   offset      INT64 — byte offset (0 for union members and enum constants)
//   size        INT64 — element size in bytes (0 for enum constants)
//   array_size  INT64 — array element count (1 if not an array; 0 for enum constants)
//   value       INT64 — enum constant value (0 for struct/union fields)

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2sql {

namespace {

struct MemberRow {
  std::string type_name;
  std::string parent_kind;
  std::string member_name;
  std::string member_type;
  int64_t     offset = 0;
  int64_t     size = 0;
  int64_t     array_size = 1;
  int64_t     value = 0;
};

}  // namespace

void register_types_members_table(Session& s) {
  auto def = xsql::cached_table<MemberRow>("types_members")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1024; })
    .cache_builder([be = s.backend_ptr()](std::vector<MemberRow>& rows) {
      auto kinds = json_utils::parse_tk_dump(be->cmd("tk*"));
      if (kinds.empty()) return;

      for (auto& [name, kind] : kinds) {
        if (kind != "struct" && kind != "union" && kind != "enum") continue;
        if (kind == "enum") {
          auto j = be->cmd_json("tej " + name);
          if (!j.is_object() || !j.contains("values") || !j["values"].is_object()) continue;
          for (auto it = j["values"].begin(); it != j["values"].end(); ++it) {
            MemberRow r;
            r.type_name   = name;
            r.parent_kind = "enum";
            r.member_name = it.key();
            r.array_size  = 0;
            r.value       = it.value().is_number_integer()
                                ? it.value().get<int64_t>()
                                : 0;
            rows.push_back(std::move(r));
          }
        } else {
          auto cmd = (kind == "struct" ? std::string("tsj ") : std::string("tuj ")) + name;
          auto j = be->cmd_json(cmd);
          if (!j.is_object() || !j.contains("fields") || !j["fields"].is_array()) continue;
          for (const auto& f : j["fields"]) {
            MemberRow r;
            r.type_name   = name;
            r.parent_kind = kind;
            r.member_name = json_utils::str(f, "name");
            r.member_type = json_utils::str(f, "type");
            r.offset      = json_utils::i64(f, "offset");
            r.size        = json_utils::i64(f, "size");
            r.array_size  = json_utils::i64(f, "array_size", 1);
            if (r.array_size <= 0) r.array_size = 1;
            rows.push_back(std::move(r));
          }
        }
      }
      std::sort(rows.begin(), rows.end(), [](const MemberRow& a, const MemberRow& b) {
        if (a.type_name != b.type_name) return a.type_name < b.type_name;
        return a.offset < b.offset;
      });
    })
    .column_text ("type_name",   [](const MemberRow& r) { return r.type_name; })
    .column_text ("parent_kind", [](const MemberRow& r) { return r.parent_kind; })
    .column_text ("member_name", [](const MemberRow& r) { return r.member_name; })
    .column_text ("member_type", [](const MemberRow& r) { return r.member_type; })
    .column_int64("offset",      [](const MemberRow& r) { return r.offset; })
    .column_int64("size",        [](const MemberRow& r) { return r.size; })
    .column_int64("array_size",  [](const MemberRow& r) { return r.array_size; })
    .column_int64("value",       [](const MemberRow& r) { return r.value; })
    .build();
  (void)s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
