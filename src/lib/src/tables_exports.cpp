// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// entries — program entry points (`iej`) plus exports (`iEj`), deduped by addr.

#include <map>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::EntryRow;

void merge_row(std::map<int64_t, EntryRow>& by_addr,
               const nlohmann::json& j, bool prefer_fields) {
  if (!j.is_object()) return;
  auto addr_it = j.find("vaddr");
  if (addr_it == j.end() || addr_it->is_null()) addr_it = j.find("addr");
  if (addr_it == j.end() || addr_it->is_null()) return;
  const int64_t addr =
      addr_it->is_number_unsigned()
          ? static_cast<int64_t>(addr_it->get<uint64_t>())
          : json_utils::i64(nlohmann::json{{"addr", *addr_it}}, "addr");

  EntryRow incoming;
  incoming.addr = addr;
  incoming.size = json_utils::i64(j, "size");
  incoming.type = json_utils::str(j, "type");
  incoming.bind = json_utils::str(j, "bind");
  incoming.name = json_utils::str(j, "name");

  auto [it, inserted] = by_addr.emplace(addr, incoming);
  if (inserted) return;
  EntryRow& current = it->second;
  auto merge_text = [prefer_fields](std::string& dst, const std::string& src) {
    if (!src.empty() && (prefer_fields || dst.empty())) dst = src;
  };
  if (incoming.size != 0 && (prefer_fields || current.size == 0)) {
    current.size = incoming.size;
  }
  merge_text(current.type, incoming.type);
  merge_text(current.bind, incoming.bind);
  merge_text(current.name, incoming.name);
}
}  // namespace

void register_exports_table(Session& s) {
  auto def = xsql::cached_table<EntryRow>("entries")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, direct::Collection::Entries, "ie~?", 16) +
             table_utils::quick_count(be, direct::Collection::Exports, "iE~?", 256);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<EntryRow>& rows) {
      if (auto* api = be->direct()) {
        api->entries_scan(rows);
        return;
      }
      std::map<int64_t, EntryRow> by_addr;
      auto entry_points = be->cmd_json("iej");
      if (entry_points.is_array()) {
        for (const auto& j : entry_points) merge_row(by_addr, j, false);
      }
      auto exports = be->cmd_json("iEj");
      if (exports.is_array()) {
        // Export metadata is richer at a duplicate address, so let it replace
        // the sparse entry-point fields while retaining a single row.
        for (const auto& j : exports) merge_row(by_addr, j, true);
      }
      rows.reserve(by_addr.size());
      for (auto& [addr, row] : by_addr) rows.push_back(std::move(row));
    })
    .column_int64("addr", [](const EntryRow& r) { return r.addr; })
    .column_int64("size", [](const EntryRow& r) { return r.size; })
    .column_text ("type", [](const EntryRow& r) { return r.type; })
    .column_text ("bind", [](const EntryRow& r) { return r.bind; })
    .column_text ("name", [](const EntryRow& r) { return r.name; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
