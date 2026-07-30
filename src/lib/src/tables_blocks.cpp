// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// blocks — basic blocks per function via `afbj @ <addr>`. A `func_addr`
// equality filter is pushed down: `WHERE func_addr = X` issues a single
// `afbj @ X`. An unfiltered scan walks `aflj` and enumerates every function's
// blocks lazily.

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
struct BlockRow {
  int64_t addr = 0;
  int64_t size = 0;
  int64_t func_addr = 0;
};

// One scoped `afbj @ <fa>` call → the blocks of a single function.
std::vector<BlockRow> blocks_for_func(Backend* be, int64_t fa) {
  std::vector<BlockRow> out;
  auto bbs = be->cmd_json("afbj @ " + json_utils::hex_addr(fa));
  if (!bbs.is_array()) return out;
  for (auto& b : bbs) {
    BlockRow r;
    r.addr = json_utils::i64(b, "addr");
    r.size = json_utils::i64(b, "size");
    r.func_addr = fa;
    out.push_back(std::move(r));
  }
  return out;
}

// Full-scan: `aflj` then `afbj @` per function, streamed one block at a time.
class BlocksGen : public xsql::Generator<BlockRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<BlockRow> buf_;
  size_t bi_ = 0;
  BlockRow cur_;
 public:
  explicit BlocksGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      buf_ = blocks_for_func(be_, json_utils::i64_addr(funcs_[fi_++]));
      bi_ = 0;
    }
  }
  const BlockRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

// Pushdown path for `WHERE func_addr = <fa>`: one `afbj @ <fa>`.
class BlocksInFuncIterator : public xsql::RowIterator {
  std::vector<BlockRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  BlocksInFuncIterator(Backend* be, int64_t fa) : rows_(blocks_for_func(be, fa)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const BlockRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;
      case 1: ctx.result_int64(r.size); break;
      case 2: ctx.result_int64(r.func_addr); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return rows_[i_].addr; }
};
}  // namespace

void register_blocks_table(Session& s) {
  auto def = xsql::generator_table<BlockRow>("blocks")
    // Constant estimate: the planner must never issue `aflj` just to plan
    // (that would defeat the pushdown guarantee). A large value biases it
    // toward the cheap filter whenever func_addr is constrained.
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<BlockRow>> {
      return std::make_unique<BlocksGen>(be);
    })
    .column_int64("addr",      [](const BlockRow& r) { return r.addr; })
    .column_int64("size",      [](const BlockRow& r) { return r.size; })
    .column_int64("func_addr", [](const BlockRow& r) { return r.func_addr; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<BlocksInFuncIterator>(be, fa);
      }, 5.0, 16.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2sql
