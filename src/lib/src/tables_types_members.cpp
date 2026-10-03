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

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"

#include <string>
#include <vector>

namespace r2xsql {

namespace {

using direct::MemberRow;

}  // namespace

void register_types_members_table(Session& s) {
  auto def = xsql::cached_table<MemberRow>("types_members")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1024; })
    .cache_builder([be = s.backend_ptr()](std::vector<MemberRow>& rows) {
      if (auto* api = be->direct()) {
        api->type_members_scan(rows);
      }
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

}  // namespace r2xsql
