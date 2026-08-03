// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// strings — `izj`. Each entry exposes vaddr, length, section, type, text.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct StringRow {
  int64_t     addr = 0;
  int64_t     length = 0;
  std::string section;
  std::string type;
  std::string text;
};

// `text` is column index 4. Bit 63 of colUsed is SQLite's "column >= 63 or
// unknown" catch-all — treat it as "include everything".
constexpr uint64_t kTextColBit = 1ull << 4;
constexpr uint64_t kColUsedAll = 1ull << 63;

void build_strings(Backend* be, std::vector<StringRow>& rows, bool with_text) {
  auto arr = be->cmd_json("izj");
  if (!arr.is_array()) return;
  rows.reserve(arr.size());
  for (auto& j : arr) {
    StringRow r;
    r.addr    = json_utils::i64(j, "vaddr");
    r.length  = json_utils::i64(j, "length");
    r.section = json_utils::str(j, "section");
    r.type    = json_utils::str(j, "type");
    // Skip copying the string body when the query doesn't read `text` — the
    // common case for COUNT / length-histogram / ORDER BY length queries. This
    // is a per-query build (no_shared_cache), so it never affects a later query.
    if (with_text) r.text = json_utils::str(j, "string");
    rows.push_back(std::move(r));
  }
}
}  // namespace

void register_strings_table(Session& s) {
  auto def = xsql::cached_table<StringRow>("strings")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "iz~?", 1000);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<StringRow>& rows) {
      build_strings(be, rows, /*with_text=*/true);
    })
    .projection_cache_builder([be = s.backend_ptr()](std::vector<StringRow>& rows,
                                                     uint64_t colUsed) {
      const bool with_text = (colUsed & kColUsedAll) || (colUsed & kTextColBit);
      build_strings(be, rows, with_text);
    })
    .column_int64("addr",    [](const StringRow& r) { return r.addr; })
    .column_int64("length",  [](const StringRow& r) { return r.length; })
    .column_text ("section", [](const StringRow& r) { return r.section; })
    .column_text ("type",    [](const StringRow& r) { return r.type; })
    .column_text ("text",    [](const StringRow& r) { return r.text; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql

