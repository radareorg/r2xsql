// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Native reads for libr; command fallback for r2pipe and mock.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "direct.hpp"

namespace r2xsql {

namespace {

using direct::LibRow;

}  // namespace

void register_libs_table(Session& s) {
  auto def = xsql::cached_table<LibRow>("libs")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 16; })
    .cache_builder([be = s.backend_ptr()](std::vector<LibRow>& rows) {
      if (auto* api = be->direct()) {
        api->libs_scan(rows);
        return;
      }
      auto arr = be->cmd_json("ilj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        if (!j.is_string()) continue;
        LibRow r;
        r.name = j.get<std::string>();
        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const LibRow& r) { return r.name; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
