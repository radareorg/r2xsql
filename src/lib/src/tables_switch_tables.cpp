// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// switch_tables — reconstructed switch/case jump tables, derived from each block's
// `switch_op` in `afbj @ <addr>`. Canonical cross-tool schema (func_addr,
// instr_addr, table_addr, min_case, max_case, case_count, default_addr). r2 supplies
// 6/7: only `table_addr` (the physical jump-table address) is not exposed -> NULL;
// r2 DOES give a default target (`switch_op.def_val`). A `func_addr` equality filter
// is pushed down to a single `afbj @ X`; an unfiltered scan walks `aflj`.

#include <memory>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {
struct SwitchTableRow {
  int64_t func_addr = 0;
  int64_t instr_addr = 0;
  bool has_min = false;
  bool has_max = false;
  bool has_default = false;
  int64_t min_case = 0;
  int64_t max_case = 0;
  int64_t case_count = 0;
  int64_t default_addr = 0;
};

bool json_num(const nlohmann::json& obj, const char* key, int64_t& out) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_number_integer()) return false;
  out = it->get<int64_t>();
  return true;
}

// One scoped `afbj @ <fa>` -> every switch in that function. r2 attaches a
// `switch_op` object to the block that ends in the indirect jump, with fields
// addr (the switch instruction), min_val, max_val, def_val, and cases[].
std::vector<SwitchTableRow> switches_for_func(Backend* be, int64_t fa) {
  std::vector<SwitchTableRow> out;
  auto bbs = be->cmd_json("afbj @ " + json_utils::hex_addr(fa));
  if (!bbs.is_array()) return out;
  for (auto& b : bbs) {
    auto sw = b.find("switch_op");
    if (sw == b.end() || !sw->is_object()) continue;
    SwitchTableRow r;
    r.func_addr = fa;
    int64_t v = 0;
    if (json_num(*sw, "addr", v)) r.instr_addr = v;
    else r.instr_addr = json_utils::i64(b, "addr");
    if (json_num(*sw, "min_val", v)) { r.min_case = v; r.has_min = true; }
    if (json_num(*sw, "max_val", v)) { r.max_case = v; r.has_max = true; }
    if (json_num(*sw, "def_val", v)) { r.default_addr = v; r.has_default = true; }
    auto cases = sw->find("cases");
    r.case_count =
        (cases != sw->end() && cases->is_array()) ? static_cast<int64_t>(cases->size()) : 0;
    out.push_back(std::move(r));
  }
  return out;
}

// Emit one row's columns in canonical order:
// 0 func_addr, 1 instr_addr, 2 table_addr(NULL), 3 min_case, 4 max_case,
// 5 case_count, 6 default_addr.
void emit_column(xsql::FunctionContext& ctx, int col, const SwitchTableRow& r) {
  switch (col) {
    case 0: ctx.result_int64(r.func_addr); break;
    case 1: ctx.result_int64(r.instr_addr); break;
    case 2: ctx.result_null(); break;  // table_addr not exposed by r2
    case 3: if (r.has_min) ctx.result_int64(r.min_case); else ctx.result_null(); break;
    case 4: if (r.has_max) ctx.result_int64(r.max_case); else ctx.result_null(); break;
    case 5: ctx.result_int64(r.case_count); break;
    case 6: if (r.has_default) ctx.result_int64(r.default_addr); else ctx.result_null(); break;
    default: ctx.result_null(); break;
  }
}

// Full-scan: `aflj` then `afbj @` per function, streamed one switch at a time.
class SwitchTablesGen : public xsql::Generator<SwitchTableRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<SwitchTableRow> buf_;
  size_t bi_ = 0;
  SwitchTableRow cur_;
 public:
  explicit SwitchTablesGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      buf_ = switches_for_func(be_, json_utils::i64_addr(funcs_[fi_++]));
      bi_ = 0;
    }
  }
  const SwitchTableRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.instr_addr; }
};

// Pushdown for `WHERE func_addr = <fa>`: one `afbj @ <fa>`.
class SwitchTablesInFuncIterator : public xsql::RowIterator {
  std::vector<SwitchTableRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  SwitchTablesInFuncIterator(Backend* be, int64_t fa) : rows_(switches_for_func(be, fa)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    emit_column(ctx, col, rows_[i_]);
  }
  int64_t rowid() const override { return rows_[i_].instr_addr; }
};
}  // namespace

void register_switch_tables_table(Session& s) {
  auto def = xsql::generator_table<SwitchTableRow>("switch_tables")
    .estimate_rows([]() -> size_t { return 1000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<SwitchTableRow>> {
      return std::make_unique<SwitchTablesGen>(be);
    })
    .column_int64("func_addr", [](const SwitchTableRow& r) { return r.func_addr; })
    .column_int64("instr_addr", [](const SwitchTableRow& r) { return r.instr_addr; })
    .column("table_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const SwitchTableRow&) { ctx.result_null(); })
    .column("min_case", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const SwitchTableRow& r) {
              if (r.has_min) ctx.result_int64(r.min_case); else ctx.result_null();
            })
    .column("max_case", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const SwitchTableRow& r) {
              if (r.has_max) ctx.result_int64(r.max_case); else ctx.result_null();
            })
    .column_int64("case_count", [](const SwitchTableRow& r) { return r.case_count; })
    .column("default_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const SwitchTableRow& r) {
              if (r.has_default) ctx.result_int64(r.default_addr); else ctx.result_null();
            })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<SwitchTablesInFuncIterator>(be, fa);
      }, 5.0, 4.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2sql
