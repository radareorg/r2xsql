// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// strings — `izj`. Each entry exposes vaddr, length, section, type, content.
//
// The body column is `content`, the name every tool in this family uses. It was
// `text` here; that spelling is REMOVED, not aliased, so a query written against
// it fails loudly instead of quietly reading nothing.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::StringRow;

// `content` is column index 4. Bit 63 of colUsed is SQLite's "column >= 63 or
// unknown" catch-all — treat it as "include everything".
constexpr uint64_t kContentColBit = 1ull << 4;
constexpr uint64_t kColUsedAll = 1ull << 63;

void build_strings(Backend* be, std::vector<StringRow>& rows, bool with_content) {
  if (auto* api = be->direct()) {
    api->strings_scan(with_content, rows);
    return;
  }
  auto arr = be->cmd_json("izj");
  if (!arr.is_array()) return;
  rows.reserve(arr.size());
  for (auto& j : arr) {
    StringRow r;
    r.addr    = json_utils::i64(j, "vaddr");
    r.length  = json_utils::i64(j, "length");
    r.section = json_utils::str(j, "section");
    r.type    = json_utils::str(j, "type");
    r.paddr   = json_utils::i64(j, "paddr");
    // Skip copying the string body when the query doesn't read `content` — the
    // common case for COUNT / length-histogram / ORDER BY length queries. This
    // is a per-query build (no_shared_cache), so it never affects a later query.
    if (with_content) r.content = json_utils::str(j, "string");
    rows.push_back(std::move(r));
  }
}
}  // namespace

void register_strings_table(Session& s) {
  auto def = xsql::cached_table<StringRow>("strings")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, direct::Collection::Strings, "iz~?", 1000);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<StringRow>& rows) {
      build_strings(be, rows, /*with_content=*/true);
    })
    .projection_cache_builder([be = s.backend_ptr()](std::vector<StringRow>& rows,
                                                     uint64_t colUsed) {
      const bool with_content = (colUsed & kColUsedAll) || (colUsed & kContentColBit);
      build_strings(be, rows, with_content);
    })
    .column_int64("addr",    [](const StringRow& r) { return r.addr; })
    .column_int64("length",  [](const StringRow& r) { return r.length; })
    .column_text ("section", [](const StringRow& r) { return r.section; })
    .column_text ("type",    [](const StringRow& r) { return r.type; })
    .column_text ("content", [](const StringRow& r) { return r.content; })
    // Appended after `content` so that stays column index 4 — the bit
    // kContentColBit tests. The file offset, for carving or patching on disk.
    .column_int64("paddr",   [](const StringRow& r) { return r.paddr; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql

