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

namespace r2xsql {

namespace {

using direct::CallingConventionRow;

std::string join_comma(const std::vector<std::string>& parts) {
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) out += ',';
    out += parts[i];
  }
  return out;
}

}  // namespace

void register_calling_conventions_table(Session& s) {
  auto def = xsql::cached_table<CallingConventionRow>("calling_conventions")
    .estimate_rows([]() -> size_t { return 16; })
    .cache_builder([be = s.backend_ptr()](std::vector<CallingConventionRow>& rows) {
      if (auto* api = be->direct()) {
        api->calling_conventions_scan(rows);
        return;
      }
      // `afclj` emits a JSON OBJECT keyed by convention name (cmd_afcl wraps
      // the whole thing in pj_o()/pj_ko(pj, cc)), unlike most r2xsql sources,
      // which are arrays.
      auto obj = be->cmd_json("afclj");
      if (!obj.is_object()) return;
      rows.reserve(obj.size());
      for (auto& [name, cc] : obj.items()) {
        if (!cc.is_object()) continue;
        CallingConventionRow r;
        r.name = name;

        if (auto it = cc.find("ret"); it != cc.end() && it->is_string()) {
          r.ret = it->get<std::string>();
        }
        if (auto it = cc.find("rets"); it != cc.end() && it->is_array()) {
          for (auto& e : *it) {
            if (e.is_string()) r.rets.push_back(e.get<std::string>());
          }
        }
        if (auto it = cc.find("args"); it != cc.end() && it->is_array()) {
          for (auto& e : *it) {
            if (e.is_string()) r.args.push_back(e.get<std::string>());
          }
        }
        if (auto it = cc.find("argn"); it != cc.end() && it->is_string()) {
          r.argn = it->get<std::string>();
        }

        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const CallingConventionRow& r) { return r.name; })
    .column_text("args", [](const CallingConventionRow& r) { return join_comma(r.args); })
    .column_text_nullable("ret", [](const CallingConventionRow& r) { return r.ret; })
    .column_text("rets", [](const CallingConventionRow& r) { return join_comma(r.rets); })
    .column_text_nullable("argn", [](const CallingConventionRow& r) { return r.argn; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
