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
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {

using direct::RegisterRow;

}  // namespace

void register_registers_table(Session& s) {
  auto def = xsql::cached_table<RegisterRow>("registers")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 160; })
    .cache_builder([be = s.backend_ptr()](std::vector<RegisterRow>& rows) {
      if (auto* api = be->direct()) {
        api->registers_scan(rows);
        return;
      }
      const std::string arch = table_utils::trim_ascii(be->cmd("e asm.arch"));
      const std::string bits = table_utils::trim_ascii(be->cmd("e asm.bits"));

      auto obj = be->cmd_json("arpj");
      if (!obj.is_object()) return;

      // reg name -> comma-joined role_str list, built from alias_info first
      // so reg_info's single pass below can look each name up in O(1).
      std::unordered_map<std::string, std::string> roles_by_reg;
      if (auto ai = obj.find("alias_info"); ai != obj.end() && ai->is_array()) {
        for (auto& a : *ai) {
          if (!a.is_object()) continue;
          std::string reg = json_utils::str(a, "reg");
          std::string role_str = json_utils::str(a, "role_str");
          if (reg.empty() || role_str.empty()) continue;
          std::string& joined = roles_by_reg[reg];
          if (!joined.empty()) joined += ',';
          joined += role_str;
        }
      }

      auto ri = obj.find("reg_info");
      if (ri == obj.end() || !ri->is_array()) return;
      rows.reserve(ri->size());
      for (auto& j : *ri) {
        if (!j.is_object()) continue;
        RegisterRow r;
        r.name   = json_utils::str(j, "name");
        r.type   = json_utils::str(j, "type_str");
        r.size   = json_utils::i64(j, "size");
        r.offset = json_utils::i64(j, "offset");
        r.arch   = arch;
        r.bits   = bits;
        if (auto it = roles_by_reg.find(r.name); it != roles_by_reg.end()) {
          r.role = it->second;
        }
        rows.push_back(std::move(r));
      }
    })
    .column_text ("name",   [](const RegisterRow& r) { return r.name; })
    .column_text ("type",   [](const RegisterRow& r) { return r.type; })
    .column_int64("size",   [](const RegisterRow& r) { return r.size; })
    .column_int64("offset", [](const RegisterRow& r) { return r.offset; })
    .column_text_nullable("role", [](const RegisterRow& r) { return r.role; })
    .column_text ("arch",   [](const RegisterRow& r) { return r.arch; })
    .column_text ("bits",   [](const RegisterRow& r) { return r.bits; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
