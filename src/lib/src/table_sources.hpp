// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#pragma once

#include <r2xsql/backend.hpp>
#include "direct.hpp"
#include "json_utils.hpp"

namespace r2xsql::table_sources {

inline std::vector<direct::BinaryRow> binary_info(Backend* be) {
  std::vector<direct::BinaryRow> rows;
  if (auto* api = be->direct()) {
    api->binary_info(rows);
  } else {
    auto info = be->cmd_json("iIj");
    if (info.is_object()) for (const auto& [key, value] : info.items()) {
      if (value.is_number_unsigned() && value.get<uint64_t>() >= UINT64_MAX - 1) continue;
      rows.push_back({key, value.is_string() ? value.get<std::string>() : value.dump(),
          value.is_boolean() ? "bool" : (value.is_number_integer() ? "int" : "string")});
    }
  }
  return rows;
}

inline std::string file_path(Backend* be) {
  if (auto* api = be->direct()) return api->file_path();
  auto info = be->cmd_json("ij");
  return info.is_object() && info.contains("core") ? json_utils::str(info["core"], "file") : "";
}

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

inline std::vector<direct::StringRow> strings(Backend* be, bool with_content = true) {
  std::vector<direct::StringRow> rows;
  if (auto* api = be->direct()) {
    api->strings_scan(with_content, rows);
  } else {
    auto arr = be->cmd_json("izj");
    if (arr.is_array()) for (const auto& j : arr) {
      rows.push_back({json_utils::i64(j, "vaddr"), json_utils::i64(j, "length"),
          json_utils::str(j, "section"), json_utils::str(j, "type"),
          with_content ? json_utils::str(j, "string") : "", json_utils::i64(j, "paddr"),
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
