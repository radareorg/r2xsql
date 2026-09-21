// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// xrefs — per-function enumeration via `afxj @ <fn>` for full scans, with
// scoped `axtj @ <addr>` / `axfj @ <addr>` pushdown for point lookups.
//
// All three shapes have a second, faster producer that reads libr's analysis
// state through the C API instead of running the command and parsing its JSON
// (see `direct.hpp` for why that lives in another TU, and what it costs not to).
// The command path below is NOT a legacy leftover: it is the only
// implementation r2pipe can have, since that backend drives a separate radare2
// process. Each shape picks the direct producer when the backend offers one and
// runs the command otherwise; both must return the same rows, which the e2e
// suite checks row by row across the two backends.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <memory>
#include <utility>
#include <vector>

namespace r2xsql {

namespace {

using direct::XrefRow;

// Reads `key` only when it is present AND an integer. Used for the optional
// owning-function address so that "radare2 reported no owner" stays distinct
// from "the owner is at address 0" — the former is SQL NULL.
bool opt_i64(const nlohmann::json& j, const char* key, int64_t& out) {
  auto it = j.find(key);
  if (it == j.end() || !it->is_number_integer()) return false;
  out = it->get<int64_t>();
  return true;
}

std::vector<XrefRow> xrefs_to_addr(Backend* be, int64_t to_addr) {
  std::vector<XrefRow> rows;
  if (auto* api = be->direct()) {
    api->xrefs_to(to_addr, rows);
    return rows;
  }
  auto refs = be->cmd_json("axtj @ " + json_utils::hex_addr(to_addr));
  if (!refs.is_array()) return rows;
  rows.reserve(refs.size());
  for (const auto& j : refs) {
    XrefRow r;
    // `axtj` names the source "from" — not the `addr`/`offset` that `aflj` and
    // `afxj` use — and omits "type" entirely for a zero-typed ref.
    r.from_addr = json_utils::i64(j, "from");
    r.to_addr = to_addr;
    r.set_type(json_utils::str(j, "type"));
    r.has_from_func = opt_i64(j, "fcn_addr", r.from_func);
    rows.push_back(std::move(r));
  }
  return rows;
}

std::vector<XrefRow> xrefs_from_addr(Backend* be, int64_t from_addr) {
  std::vector<XrefRow> rows;
  if (auto* api = be->direct()) {
    api->xrefs_from(from_addr, rows);
    return rows;
  }
  auto refs = be->cmd_json("axfj @ " + json_utils::hex_addr(from_addr));
  if (!refs.is_array() || refs.empty()) return rows;

  int64_t owner = 0;
  const bool has_owner = table_utils::resolve_func_owner(be, from_addr, owner);

  rows.reserve(refs.size());
  for (const auto& j : refs) {
    XrefRow r;
    r.from_addr = json_utils::i64(j, "from", from_addr);
    r.to_addr = json_utils::i64(j, "to");
    r.set_type(json_utils::str(j, "type"));
    r.from_func = owner;
    r.has_from_func = has_owner;
    rows.push_back(std::move(r));
  }
  return rows;
}

// One function's outgoing references — the scan's inner step, made reachable on
// its own so `WHERE from_func = X` (which is how the `callees` view is queried)
// costs a scoped command instead of enumerating every function.
std::vector<XrefRow> xrefs_in_func(Backend* be, int64_t func_addr) {
  std::vector<XrefRow> rows;
  if (auto* api = be->direct()) {
    api->xrefs_in_func(func_addr, rows);
    return rows;
  }
  // afxj accepts interior addresses; from_func equality requires a start.
  if (!table_utils::func_addr_pushdown_ok(be, func_addr)) return rows;

  auto refs = be->cmd_json("afxj @ " + json_utils::hex_addr(func_addr));
  if (!refs.is_array()) return rows;
  rows.reserve(refs.size());
  for (const auto& j : refs) {
    XrefRow r;
    r.from_addr = json_utils::i64(j, "from");
    r.to_addr   = json_utils::i64(j, "to");
    r.set_type(json_utils::str(j, "type"));
    r.from_func     = func_addr;
    r.has_from_func = true;
    rows.push_back(std::move(r));
  }
  return rows;
}

void xrefs_scan(Backend* be, std::vector<XrefRow>& rows) {
  if (auto* api = be->direct()) {
    api->xrefs_scan(rows);
    return;
  }
  auto funcs = be->cmd_json("aflj");
  if (!funcs.is_array()) return;
  for (auto& f : funcs) {
    const int64_t fa = json_utils::i64_addr(f);
    auto refs = be->cmd_json("afxj @ " + json_utils::hex_addr(fa));
    if (!refs.is_array()) continue;
    for (auto& j : refs) {
      XrefRow r;
      // afxj reports both `from` and `to` explicitly.
      r.from_addr = json_utils::i64(j, "from");
      r.to_addr   = json_utils::i64(j, "to");
      r.set_type(json_utils::str(j, "type"));
      // The owner is the function being enumerated — no lookup needed.
      r.from_func     = fa;
      r.has_from_func = true;
      rows.push_back(std::move(r));
    }
  }
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
      case 3:
        if (r.has_from_func) ctx.result_int64(r.from_func);
        else ctx.result_null();
        break;
      case 4: ctx.result_int64(r.is_code ? 1 : 0); break;
      case 5: ctx.result_int64(r.is_data ? 1 : 0); break;
      case 6: ctx.result_text(r.kind); break;
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
      return table_utils::quick_count(be, direct::Collection::Functions, "afl~?", 1000) * 10;
    })
    .cache_builder([be = s.backend_ptr()](std::vector<XrefRow>& rows) {
      xrefs_scan(be, rows);
    })
    .column_int64("from_addr", [](const XrefRow& r) { return r.from_addr; })
    .column_int64("to_addr",   [](const XrefRow& r) { return r.to_addr; })
    .column_text ("type",      [](const XrefRow& r) { return r.type; })
    // The address of the function the reference originates in, NULL when the
    // source is not inside any function — the family convention (idasql/bnsql
    // both emit an address here). Join it against `funcs.addr`.
    .column("from_func", xsql::ColumnType::Integer,
      [](xsql::FunctionContext& ctx, const XrefRow& r) {
        if (r.has_from_func) ctx.result_int64(r.from_func);
        else ctx.result_null();
      })
    // Derived from radare2's own type vocabulary, in one place shared by both
    // producers (direct.hpp). A ref is neither when its type is UNKN/NULL.
    .column_int64("is_code", [](const XrefRow& r) { return r.is_code ? 1 : 0; })
    .column_int64("is_data", [](const XrefRow& r) { return r.is_data ? 1 : 0; })
    // r2xsql's OWN small classification of `type` (call/jump/code/data/
    // unknown) -- a deliberate, owner-approved deviation, not a quiet
    // override: no shared cross-tool vocabulary has been agreed across the
    // tool family yet for xrefs. Computed free from the already-fetched
    // `type` field in direct.hpp -- no new radare2 command.
    .column_text("kind", [](const XrefRow& r) { return r.kind; })
    .filter_eq("to_addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<XrefRowsIterator>(xrefs_to_addr(be, addr));
      }, 0.5, 5.0)
    .filter_eq("from_addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<XrefRowsIterator>(xrefs_from_addr(be, addr));
      }, 0.5, 5.0)
    // Scoping by owning function is how the `callees` view is queried; without
    // this it would enumerate every function to answer about one.
    .filter_eq("from_func",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<XrefRowsIterator>(xrefs_in_func(be, addr));
      }, 1.0, 10.0)
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
