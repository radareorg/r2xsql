// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// imports — `iij`.
//
// The library column is `module`, the name the rest of the family uses. It was
// `libname` here (radare2's own JSON key, which this file still reads); that
// spelling is REMOVED, not aliased, so a query using it fails loudly rather
// than quietly returning nothing.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::ImportRow;
}  // namespace

void register_imports_table(Session& s) {
  auto def = xsql::cached_table<ImportRow>("imports")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, direct::Collection::Imports, "ii~?", 256);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<ImportRow>& rows) {
      if (auto* api = be->direct()) {
        api->imports_scan(rows);
        return;
      }
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
        // radare2's JSON key stays `libname`; the COLUMN is `module`, which
        // is what the rest of the family calls it.
        r.module  = json_utils::str(j, "libname");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",    [](const ImportRow& r) { return r.addr; })
    .column_int64("ordinal", [](const ImportRow& r) { return r.ordinal; })
    .column_text ("bind",    [](const ImportRow& r) { return r.bind; })
    .column_text ("type",    [](const ImportRow& r) { return r.type; })
    .column_text ("name",    [](const ImportRow& r) { return r.name; })
    .column_text ("module",  [](const ImportRow& r) { return r.module; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql

