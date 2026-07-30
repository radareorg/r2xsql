// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// cfg_edges — intra-function control-flow edges between basic blocks, derived
// from `afbj @ <addr>` (each block's `jump`/`fail`/switch successors). Canonical
// cross-tool schema (func_addr, from_addr, to_addr, edge_type). A `func_addr`
// equality filter is pushed down to a single `afbj @ X`; an unfiltered scan
// walks `aflj` and enumerates every function's edges lazily.

#include <memory>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {
struct CfgEdgeRow {
  int64_t     func_addr = 0;
  int64_t     from_addr = 0;
  int64_t     to_addr = 0;
  std::string edge_type;  // "normal", "true", "false"
};

bool json_num(const nlohmann::json& obj, const char* key, int64_t& out) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_number_integer()) return false;
  out = it->get<int64_t>();
  return true;
}

// One scoped `afbj @ <fa>` call → the CFG edges of a single function. r2 reports
// each block's taken successor as `jump` and its fall-through as `fail`: both
// present = a two-way conditional (jump=true arm, fail=false arm); `jump` alone =
// an unconditional/normal edge. Jump-table cases (`switch_op.cases[].jump`) are
// emitted as `normal` edges.
std::vector<CfgEdgeRow> edges_for_func(Backend* be, int64_t fa) {
  std::vector<CfgEdgeRow> out;
  auto bbs = be->cmd_json("afbj @ " + json_utils::hex_addr(fa));
  if (!bbs.is_array()) return out;
  for (auto& b : bbs) {
    int64_t from = json_utils::i64(b, "addr");
    int64_t jump = 0, fail = 0;
    bool has_jump = json_num(b, "jump", jump);
    bool has_fail = json_num(b, "fail", fail);
    std::unordered_set<int64_t> emitted_targets;
    auto add_edge = [&](int64_t target, const char* type) {
      if (emitted_targets.insert(target).second) {
        out.push_back({fa, from, target, type});
      }
    };

    if (has_jump && has_fail) {
      add_edge(jump, "true");
      add_edge(fail, "false");
    } else if (has_jump) {
      add_edge(jump, "normal");
    } else if (has_fail) {
      add_edge(fail, "normal");
    }

    auto sw = b.find("switch_op");
    if (sw != b.end() && sw->is_object()) {
      auto cases = sw->find("cases");
      if (cases != sw->end() && cases->is_array()) {
        for (auto& c : *cases) {
          int64_t caddr = 0;
          if (json_num(c, "jump", caddr)) add_edge(caddr, "normal");
        }
      }
      int64_t default_addr = 0;
      if (json_num(*sw, "def_val", default_addr)) {
        add_edge(default_addr, "normal");
      }
    }
  }
  return out;
}

// Full-scan: `aflj` then `afbj @` per function, streamed one edge at a time.
class CfgEdgesGen : public xsql::Generator<CfgEdgeRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<CfgEdgeRow> buf_;
  size_t bi_ = 0;
  CfgEdgeRow cur_;
 public:
  explicit CfgEdgesGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      buf_ = edges_for_func(be_, json_utils::i64_addr(funcs_[fi_++]));
      bi_ = 0;
    }
  }
  const CfgEdgeRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.from_addr ^ cur_.to_addr; }
};

// Pushdown path for `WHERE func_addr = <fa>`: one `afbj @ <fa>`.
class CfgEdgesInFuncIterator : public xsql::RowIterator {
  std::vector<CfgEdgeRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  CfgEdgesInFuncIterator(Backend* be, int64_t fa) : rows_(edges_for_func(be, fa)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const CfgEdgeRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.func_addr); break;
      case 1: ctx.result_int64(r.from_addr); break;
      case 2: ctx.result_int64(r.to_addr); break;
      case 3: ctx.result_text(r.edge_type); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return rows_[i_].from_addr ^ rows_[i_].to_addr; }
};
}  // namespace

void register_cfg_edges_table(Session& s) {
  auto def = xsql::generator_table<CfgEdgeRow>("cfg_edges")
    // Constant estimate: never issue `aflj` just to plan (that would defeat the
    // pushdown guarantee). A large value biases the planner toward the cheap
    // per-function filter whenever func_addr is constrained.
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<CfgEdgeRow>> {
      return std::make_unique<CfgEdgesGen>(be);
    })
    .column_int64("func_addr", [](const CfgEdgeRow& r) { return r.func_addr; })
    .column_int64("from_addr", [](const CfgEdgeRow& r) { return r.from_addr; })
    .column_int64("to_addr",   [](const CfgEdgeRow& r) { return r.to_addr; })
    .column_text ("edge_type", [](const CfgEdgeRow& r) { return r.edge_type; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<CfgEdgesInFuncIterator>(be, fa);
      }, 5.0, 16.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2sql
