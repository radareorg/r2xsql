// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// xrefs — per-function enumeration via `afxj @ <fn>` for full scans, with
// scoped `axtj @ <addr>` / `axfj @ <addr>` pushdown for point lookups.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <memory>
#include <vector>

namespace r2sql {

namespace {
struct XrefRow {
  int64_t     from_addr = 0;
  int64_t     to_addr   = 0;
  std::string type;
  std::string from_func;
};

std::string function_name_at(Backend* be, int64_t addr) {
  auto info = be->cmd_json("afij @ " + json_utils::hex_addr(addr));
  if (info.is_array() && !info.empty() && info[0].is_object()) {
    return json_utils::str(info[0], "name");
  }
  if (info.is_object()) {
    return json_utils::str(info, "name");
  }
  return {};
}

std::vector<XrefRow> xrefs_to_addr(Backend* be, int64_t to_addr) {
  std::vector<XrefRow> rows;
  auto refs = be->cmd_json("axtj @ " + json_utils::hex_addr(to_addr));
  if (!refs.is_array()) return rows;
  rows.reserve(refs.size());
  for (const auto& j : refs) {
    XrefRow r;
    r.from_addr = json_utils::i64(j, "from");
    r.to_addr = to_addr;
    r.type = json_utils::str(j, "type");
    r.from_func = json_utils::str(j, "fcn_name");
    rows.push_back(std::move(r));
  }
  return rows;
}

std::vector<XrefRow> xrefs_from_addr(Backend* be, int64_t from_addr) {
  std::vector<XrefRow> rows;
  auto refs = be->cmd_json("axfj @ " + json_utils::hex_addr(from_addr));
  if (!refs.is_array()) return rows;

  std::string from_func;
  rows.reserve(refs.size());
  for (const auto& j : refs) {
    XrefRow r;
    r.from_addr = json_utils::i64(j, "from", from_addr);
    r.to_addr = json_utils::i64(j, "to");
    r.type = json_utils::str(j, "type");
    r.from_func = json_utils::str(j, "fcn_name");
    if (r.from_func.empty()) {
      if (from_func.empty()) from_func = function_name_at(be, from_addr);
      r.from_func = from_func;
    }
    rows.push_back(std::move(r));
  }
  return rows;
}

class XrefRowsIterator : public xsql::RowIterator {
  std::vector<XrefRow> rows_;
  size_t i_ = 0;
  bool started_ = false;

 public:
  explicit XrefRowsIterator(std::vector<XrefRow> rows) : rows_(std::move(rows)) {}

  bool next() override {
    if (!started_) started_ = true;
    else ++i_;
    return i_ < rows_.size();
  }

  bool eof() const override { return started_ && i_ >= rows_.size(); }

  void column(xsql::FunctionContext& ctx, int col) override {
    const XrefRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.from_addr); break;
      case 1: ctx.result_int64(r.to_addr); break;
      case 2: ctx.result_text(r.type); break;
      case 3: ctx.result_text(r.from_func); break;
      default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override {
    if (i_ >= rows_.size()) return 0;
    return rows_[i_].from_addr ? rows_[i_].from_addr : rows_[i_].to_addr;
  }
};
}  // namespace

void register_xrefs_table(Session& s) {
  auto def = xsql::cached_table<XrefRow>("xrefs")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "afl~?", 1000) * 10;
    })
    .cache_builder([be = s.backend_ptr()](std::vector<XrefRow>& rows) {
      auto funcs = be->cmd_json("aflj");
      if (!funcs.is_array()) return;
      for (auto& f : funcs) {
        const int64_t fa = json_utils::i64_addr(f);
        const std::string fname = json_utils::str(f, "name");
        auto refs = be->cmd_json("afxj @ " + json_utils::hex_addr(fa));
        if (!refs.is_array()) continue;
        for (auto& j : refs) {
          XrefRow r;
          // afxj reports both `from` and `to` explicitly.
          r.from_addr = json_utils::i64(j, "from");
          r.to_addr   = json_utils::i64(j, "to");
          r.type      = json_utils::str(j, "type");
          r.from_func = fname;
          rows.push_back(std::move(r));
        }
      }
    })
    .column_int64("from_addr", [](const XrefRow& r) { return r.from_addr; })
    .column_int64("to_addr",   [](const XrefRow& r) { return r.to_addr; })
    .column_text ("type",      [](const XrefRow& r) { return r.type; })
    .column_text ("from_func", [](const XrefRow& r) { return r.from_func; })
    .filter_eq("to_addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<XrefRowsIterator>(xrefs_to_addr(be, addr));
      }, 0.5, 5.0)
    .filter_eq("from_addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<XrefRowsIterator>(xrefs_from_addr(be, addr));
      }, 0.5, 5.0)
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql

