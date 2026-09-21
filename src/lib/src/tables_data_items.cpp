// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// data_items — defined data items exposed by radare2. Canonical cross-tool schema:
// addr, name, data_type, size, value_repr, segment_name, is_string, is_initialized.
// Source = strings (`izj`) UNION non-FUNC data symbols (`isj`), deduped by addr.
// r2 has no rich typed-global model; on a stripped PE this is the string set, on an
// ELF-with-symtab it also carries OBJECT globals — no surface is synthesized.

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "table_sources.hpp"

namespace r2xsql {

namespace {
struct DataItemRow {
  int64_t     addr = 0;
  std::string name;          // empty -> NULL
  bool        has_name = false;
  std::string data_type;     // empty -> NULL
  bool        has_type = false;
  int64_t     size = 0;
  bool        has_size = false;
  std::string value_repr;    // empty -> NULL
  bool        has_value = false;
  std::string segment_name;  // empty -> NULL
  bool        has_segment = false;
  int         is_string = 0;
  int         is_initialized = 1;
};

struct SectionInfo {
  int64_t start = 0;
  int64_t end = 0;
  int64_t raw_end = 0;
  std::string name;
};

int64_t saturated_end(int64_t start, int64_t length) {
  if (length <= 0) return start;
  if (start > std::numeric_limits<int64_t>::max() - length)
    return std::numeric_limits<int64_t>::max();
  return start + length;
}

std::vector<SectionInfo> load_sections(Backend* be) {
  std::vector<SectionInfo> out;
  auto secs = table_sources::sections(be);
  out.reserve(secs.size());
  for (const auto& j : secs) {
    SectionInfo s;
    s.start = j.addr;
    const int64_t raw_size =
        std::max<int64_t>(0, j.size);
    int64_t virtual_size = j.vsize;
    if (virtual_size <= 0) virtual_size = raw_size;
    if (virtual_size <= 0) continue;
    s.end = saturated_end(s.start, virtual_size);
    s.raw_end =
        saturated_end(s.start, std::min(raw_size, virtual_size));
    s.name = j.name;
    if (s.end > s.start) out.push_back(std::move(s));
  }
  return out;
}

const SectionInfo* section_at(
    const std::vector<SectionInfo>& sections, int64_t addr) {
  for (const auto& s : sections) {
    if (addr >= s.start && addr < s.end) return &s;
  }
  return nullptr;
}

// Build the deduped data-item set: data symbols first (they carry name/type/size),
// then fold in strings (they carry value/segment and set is_string).
void build_data_items(Backend* be, std::vector<DataItemRow>& rows) {
  std::map<int64_t, DataItemRow> by_addr;
  const auto sections = load_sections(be);

  // (1) Non-FUNC symbols = data objects (OBJ/OBJECT on binaries with a symtab).
  for (const auto& j : table_sources::symbols(be)) {
    const std::string type = j.type;
    if (type == "FUNC") continue;              // code lives in funcs
    if (j.is_imported) continue;  // imports table
    const int64_t addr = j.addr;
    // vaddr 0 is r2's unmapped/sentinel address; skip it. A genuine item at
    // vaddr 0 is vanishingly rare and not worth confusing with the sentinel.
    if (addr == 0) continue;
    DataItemRow r;
    r.addr = addr;
    r.name = j.name;
    r.has_name = !r.name.empty();
    r.data_type = type;
    r.has_type = !r.data_type.empty();
    r.size = j.size;
    r.has_size = true;
    if (const auto* section = section_at(sections, addr)) {
      r.segment_name = section->name;
      r.has_segment = !r.segment_name.empty();
      r.is_initialized = addr < section->raw_end ? 1 : 0;
    }
    by_addr[addr] = std::move(r);
  }

  // (2) Strings: value_repr + segment + is_string. Coincident addr keeps the
  // symbol's name/type but becomes a string with a value.
  for (const auto& j : table_sources::strings(be)) {
    const int64_t addr = j.addr;
    if (addr == 0) continue;  // r2 unmapped/sentinel address (see above)
    auto it = by_addr.find(addr);
    if (it == by_addr.end()) {
      DataItemRow r;
      r.addr = addr;
      r.data_type = "string";
      r.has_type = true;
      r.size = j.size;
      r.has_size = true;
      it = by_addr.emplace(addr, std::move(r)).first;
    }
    DataItemRow& r = it->second;
    r.is_string = 1;
    r.is_initialized = 1;
    r.value_repr = j.content;
    r.has_value = !r.value_repr.empty();
    r.segment_name = j.section;
    r.has_segment = !r.segment_name.empty();
    if (!r.has_size) { r.size = j.size; r.has_size = true; }
  }

  rows.reserve(by_addr.size());
  for (auto& kv : by_addr) rows.push_back(std::move(kv.second));  // map => addr-sorted
}
}  // namespace

void register_data_items_table(Session& s) {
  auto def = xsql::cached_table<DataItemRow>("data_items")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1000; })
    .cache_builder([be = s.backend_ptr()](std::vector<DataItemRow>& rows) {
      build_data_items(be, rows);
    })
    .column_int64("addr", [](const DataItemRow& r) { return r.addr; })
    .column("name", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const DataItemRow& r) {
              if (r.has_name) ctx.result_text(r.name); else ctx.result_null();
            })
    .column("data_type", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const DataItemRow& r) {
              if (r.has_type) ctx.result_text(r.data_type); else ctx.result_null();
            })
    .column("size", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const DataItemRow& r) {
              if (r.has_size) ctx.result_int64(r.size); else ctx.result_null();
            })
    .column("value_repr", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const DataItemRow& r) {
              if (r.has_value) ctx.result_text(r.value_repr); else ctx.result_null();
            })
    .column("segment_name", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const DataItemRow& r) {
              if (r.has_segment) ctx.result_text(r.segment_name); else ctx.result_null();
            })
    .column_int64("is_string",
                  [](const DataItemRow& r) -> int64_t { return r.is_string; })
    .column_int64("is_initialized",
                  [](const DataItemRow& r) -> int64_t { return r.is_initialized; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
