// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// types — native type catalog with empty struct/union/enum creation.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <r_util.h>
#include "tables.hpp"
#include "direct.hpp"

#include <string>
#include <vector>

namespace r2xsql {

namespace {

using direct::TypeRow;

}  // namespace

void register_types_table(Session& s) {
  auto def = xsql::cached_table<TypeRow>("types")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 256; })
    .cache_builder([be = s.backend_ptr()](std::vector<TypeRow>& rows) {
      if (auto* api = be->direct()) {
        api->types_scan(rows);
      }
    })
    .column_int64("ordinal", [](const TypeRow& r) { return r.ordinal; })
    .column_text ("name",   [](const TypeRow& r) { return r.name; })
    .column_text ("kind",   [](const TypeRow& r) { return r.kind; })
    .column_int64("size",   [](const TypeRow& r) { return r.size; })
    .column_text ("format", [](const TypeRow& r) { return r.format; })
    // SQL creates empty struct/union/enum shells and deletes types by name.
    // Full declarations use radare2's native td command.
    .deletable([be = s.backend_ptr()](TypeRow& r) -> bool {
      if (r.name.empty() || !r_name_check(r.name.c_str())) {
        xsql::set_vtab_error("types: refusing to delete an unsafe/empty type name");
        return false;
      }
      auto* api = be->direct();
      if (!api || !api->type_delete(r.name)) {
        xsql::set_vtab_error("types: DELETE failed (name=" + r.name + ")");
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: ordinal(0, read-only, ignored here),
      // name(1), kind(2), size(3), format(4).
      if (argc < 3 || argv[1].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("types: INSERT requires name and kind");
        return false;
      }
      const char* name_c = argv[1].as_c_str();
      const char* kind_c = argv[2].as_c_str();
      const std::string name = name_c ? name_c : "";
      const std::string kind = kind_c ? kind_c : "";
      if (name.empty() || !r_name_check(name.c_str())) {
        xsql::set_vtab_error("types: refusing to create an unsafe/empty type name");
        return false;
      }
      if (kind != "struct" && kind != "union" && kind != "enum") {
        xsql::set_vtab_error(
            "types: INSERT only creates an empty struct/union/enum shell "
            "(kind must be one of those three) -- for a real type with "
            "members, an underlying primitive, or a signature, use "
            "radare2's `td <C decl>` command instead");
        return false;
      }
      auto* api = be->direct();
      if (!api || !api->type_create(name, kind)) {
        xsql::set_vtab_error("types: INSERT failed (name=" + name + ")");
        return false;
      }
      return true;
    })
    .build();
  (void)s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
