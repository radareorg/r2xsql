// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#pragma once

#include <r2xsql/backend.hpp>
#include "direct.hpp"
#include "json_utils.hpp"

namespace r2xsql::table_sources {

inline std::vector<direct::SectionRow> sections(Backend* be, bool segments = false) {
  std::vector<direct::SectionRow> rows;
  if (auto* api = be->direct()) {
    api->sections_scan(segments, rows);
  } else {
    auto arr = be->cmd_json(segments ? "iSSj" : "iSj");
    if (arr.is_array()) for (const auto& j : arr) {
      rows.push_back({json_utils::i64(j, "vaddr"), json_utils::i64(j, "vsize"),
          json_utils::i64(j, "paddr"), json_utils::i64(j, "size"),
          json_utils::str(j, "name"), json_utils::str(j, "perm")});
    }
  }
  return rows;
}

inline std::vector<direct::StringRow> strings(Backend* be) {
  std::vector<direct::StringRow> rows;
  if (auto* api = be->direct()) {
    api->strings_scan(true, rows);
  } else {
    auto arr = be->cmd_json("izj");
    if (arr.is_array()) for (const auto& j : arr) {
      rows.push_back({json_utils::i64(j, "vaddr"), json_utils::i64(j, "length"),
          json_utils::str(j, "section"), json_utils::str(j, "type"),
          json_utils::str(j, "string"), json_utils::i64(j, "paddr"),
          json_utils::i64(j, "size")});
    }
  }
  return rows;
}

inline std::vector<direct::SymbolRow> symbols(Backend* be) {
  std::vector<direct::SymbolRow> rows;
  if (auto* api = be->direct()) {
    api->symbols_scan(rows);
  } else {
    auto arr = be->cmd_json("isj");
    if (arr.is_array()) for (const auto& j : arr) {
      direct::SymbolRow r;
      r.addr = json_utils::i64(j, "vaddr");
      r.size = json_utils::i64(j, "size");
      r.type = json_utils::str(j, "type");
      r.bind = json_utils::str(j, "bind");
      r.name = json_utils::str(j, "name");
      r.is_imported = json_utils::boolean(j, "is_imported");
      rows.push_back(std::move(r));
    }
  }
  return rows;
}

}  // namespace r2xsql::table_sources
