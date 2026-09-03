// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// pseudocode — runtime-gated. Runs the detected decompiler command
// (pdg / pdd / pdc) per function. A `func_addr` equality filter is pushed
// down: `WHERE func_addr = X` decompiles exactly that one function, provided X
// is a function START (see `PseudoAtFuncIterator`). An
// unfiltered scan walks `aflj` and decompiles every function (expensive).

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct PseudoRow {
  int64_t     func_addr = 0;
  std::string text;
};

PseudoRow pseudo_for_func(Backend* be, const std::string& dec_cmd, int64_t fa) {
  PseudoRow r;
  r.func_addr = fa;
  r.text = be->cmd(dec_cmd + " @ " + json_utils::hex_addr(fa));
  return r;
}

class PseudoGen : public xsql::Generator<PseudoRow> {
  Backend* be_;
  std::string dec_cmd_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  PseudoRow cur_;
 public:
  PseudoGen(Backend* be, std::string dec_cmd)
      : be_(be), dec_cmd_(std::move(dec_cmd)), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
    cur_ = pseudo_for_func(be_, dec_cmd_, json_utils::i64_addr(funcs_[fi_++]));
    return true;
  }
  const PseudoRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.func_addr; }
};

// `fa` must be a function START. `<dec_cmd> @ fa` decompiles the function
// CONTAINING fa, so a mid-function address used to yield ONE row holding the
// owner's pseudocode tagged `func_addr = fa` — a row that violates the
// pushed-down constraint SQLite never re-checks (see
// `table_utils::func_addr_pushdown_ok`). Refusing yields no row at all, which
// also retires this table's old "the pushdown always emits exactly one row"
// behavior: an address no function starts at now answers with nothing rather
// than with the decompiler's prose.
//
// The UNCONDITIONAL `func_addr_is_start`, not the `_pushdown_ok` shortcut: this
// table has no direct (C-API) producer, so the decompiler command is issued on
// the full flavor exactly as on the pipe flavor and there is nothing in-process
// to self-check. Shortcutting on `be->direct()` would wave through the one case
// the gate exists to refuse.
class PseudoAtFuncIterator : public xsql::RowIterator {
  PseudoRow row_;
  bool refused_ = false;
  bool started_ = false;
  bool done_ = false;
 public:
  PseudoAtFuncIterator(Backend* be, const std::string& dec_cmd, int64_t fa) {
    if (!table_utils::func_addr_is_start(be, fa)) { refused_ = true; return; }
    row_ = pseudo_for_func(be, dec_cmd, fa);
  }
  bool next() override {
    if (refused_ || started_) { done_ = true; return false; }
    started_ = true;
    return true;
  }
  bool eof() const override { return done_; }
  void column(xsql::FunctionContext& ctx, int col) override {
    switch (col) {
      case 0: ctx.result_int64(row_.func_addr); break;
      case 1: ctx.result_text(row_.text); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return row_.func_addr; }
};
}  // namespace

void register_decompiler_table_if_available(Session& s) {
  if (!s.has_decompiler()) return;
  std::string dec_cmd(s.decompiler_command());
  auto def = xsql::generator_table<PseudoRow>("pseudocode")
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr(), dec_cmd]()
               -> std::unique_ptr<xsql::Generator<PseudoRow>> {
      return std::make_unique<PseudoGen>(be, dec_cmd);
    })
    .column_int64("func_addr", [](const PseudoRow& r) { return r.func_addr; })
    .column_text ("text",      [](const PseudoRow& r) { return r.text; })
    .filter_eq("func_addr",
      [be = s.backend_ptr(), dec_cmd](int64_t fa)
          -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<PseudoAtFuncIterator>(be, dec_cmd, fa);
      }, 5.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
