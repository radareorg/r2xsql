// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// imports — `iij`.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct ImportRow {
  int64_t     addr = 0;
  int64_t     ordinal = 0;
  std::string bind;
  std::string type;
  std::string name;
  std::string libname;
};
}  // namespace

void register_imports_table(Session& s) {
  auto def = xsql::cached_table<ImportRow>("imports")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "ii~?", 256);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<ImportRow>& rows) {
      auto arr = be->cmd_json("iij");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        ImportRow r;
        r.addr    = json_utils::i64(j, "plt");
        r.ordinal = json_utils::i64(j, "ordinal");
        r.bind    = json_utils::str(j, "bind");
        r.type    = json_utils::str(j, "type");
        r.name    = json_utils::str(j, "name");
        r.libname = json_utils::str(j, "libname");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",    [](const ImportRow& r) { return r.addr; })
    .column_int64("ordinal", [](const ImportRow& r) { return r.ordinal; })
    .column_text ("bind",    [](const ImportRow& r) { return r.bind; })
    .column_text ("type",    [](const ImportRow& r) { return r.type; })
    .column_text ("name",    [](const ImportRow& r) { return r.name; })
    .column_text ("libname", [](const ImportRow& r) { return r.libname; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql

