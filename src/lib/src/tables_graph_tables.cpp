// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// dominators / post_dominators / loops — canonical cross-tool CFG-graph tables,
// matching the ghidrasql reference shapes. Each maps a function's
// basic blocks (`afbj @ <fa>` jump/fail/switch successors) onto opaque node ids and
// runs the generic RE-agnostic xsql::graph module; the address mapping stays here. A
// `func_addr` filter pushes down to a single `afbj @ X`; an unfiltered scan walks
// `aflj`.

#include <algorithm>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/graph.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {

struct DominatorRow {
  int64_t func_addr = 0, node_addr = 0, idom_addr = 0;
  bool has_idom = false;
  int64_t depth = 0;
  bool is_entry = false;
};
struct PostDominatorRow {
  int64_t func_addr = 0, node_addr = 0, ipdom_addr = 0;
  bool has_ipdom = false;
  int64_t depth = 0;
  bool is_exit = false;
};
struct LoopRow {
  int64_t func_addr = 0, header_addr = 0, latch_addr = 0, start_addr = 0, end_addr = 0;
  int64_t depth = 0;
  std::string loop_kind;
  int64_t block_count = 0;
};

bool json_num(const nlohmann::json& obj, const char* key, int64_t& out) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_number_integer()) return false;
  out = it->get<int64_t>();
  return true;
}

// Build the block-level CFG of one function from `afbj @ <fa>`: a DirectedGraph over
// block ids + id->addr/end maps + the entry block id. Returns false when the function
// has no blocks.
bool build_func_graph(Backend* be, int64_t fa, xsql::graph::DirectedGraph& g_out,
                      std::vector<int64_t>& addr, std::vector<int64_t>& end_addr,
                      size_t& entry) {
  auto bbs = be->cmd_json("afbj @ " + json_utils::hex_addr(fa));
  if (!bbs.is_array() || bbs.empty()) return false;
  const size_t n = bbs.size();
  addr.assign(n, 0);
  end_addr.assign(n, 0);
  std::unordered_map<int64_t, size_t> id_of;
  id_of.reserve(n * 2);
  entry = 0;
  for (size_t i = 0; i < n; ++i) {
    int64_t a = json_utils::i64(bbs[i], "addr");
    int64_t sz = 0;
    json_num(bbs[i], "size", sz);
    addr[i] = a;
    end_addr[i] = a + sz;
    id_of[a] = i;
    if (a == fa) entry = i;
  }
  xsql::graph::DirectedGraph g(n);
  for (size_t i = 0; i < n; ++i) {
    const auto& b = bbs[i];
    int64_t t = 0;
    std::unordered_set<size_t> emitted_targets;
    auto add_to = [&](int64_t target) {
      auto it = id_of.find(target);
      if (it != id_of.end() && emitted_targets.insert(it->second).second) {
        g.add_edge(i, it->second);
      }
    };
    if (json_num(b, "jump", t)) add_to(t);
    if (json_num(b, "fail", t)) add_to(t);
    auto sw = b.find("switch_op");
    if (sw != b.end() && sw->is_object()) {
      auto cases = sw->find("cases");
      if (cases != sw->end() && cases->is_array())
        for (auto& c : *cases)
          if (json_num(c, "jump", t)) add_to(t);
      if (json_num(*sw, "def_val", t)) add_to(t);
    }
  }
  g_out = std::move(g);
  return true;
}

void collect_dominators(Backend* be, int64_t fa, std::vector<DominatorRow>& out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<int64_t> addr, end_addr;
  size_t entry = 0;
  if (!build_func_graph(be, fa, g, addr, end_addr, entry)) return;
  auto idom = xsql::graph::immediate_dominators(g, entry);
  for (size_t i = 0; i < g.node_count(); ++i) {
    if (idom[i] == xsql::graph::kNoNode) continue;
    DominatorRow r;
    r.func_addr = fa;
    r.node_addr = addr[i];
    r.is_entry = (i == entry);
    if (i == entry) {
      r.has_idom = false;
    } else {
      r.has_idom = true;
      r.idom_addr = addr[idom[i]];
      int64_t d = 0;
      size_t cur = i;
      while (cur != entry) { cur = idom[cur]; ++d; }
      r.depth = d;
    }
    out.push_back(std::move(r));
  }
}

void collect_post_dominators(Backend* be, int64_t fa, std::vector<PostDominatorRow>& out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<int64_t> addr, end_addr;
  size_t entry = 0;
  if (!build_func_graph(be, fa, g, addr, end_addr, entry)) return;
  auto ipdom = xsql::graph::immediate_post_dominators(g);
  for (size_t i = 0; i < g.node_count(); ++i) {
    PostDominatorRow r;
    r.func_addr = fa;
    r.node_addr = addr[i];
    r.is_exit = g.successors(i).empty();
    if (ipdom[i] == xsql::graph::kNoNode) {
      r.has_ipdom = false;
    } else {
      r.has_ipdom = true;
      r.ipdom_addr = addr[ipdom[i]];
      int64_t d = 0;
      size_t cur = i;
      while (ipdom[cur] != xsql::graph::kNoNode) { cur = ipdom[cur]; ++d; }
      r.depth = d;
    }
    out.push_back(std::move(r));
  }
}

void collect_loops(Backend* be, int64_t fa, std::vector<LoopRow>& out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<int64_t> addr, end_addr;
  size_t entry = 0;
  if (!build_func_graph(be, fa, g, addr, end_addr, entry)) return;
  auto loops = xsql::graph::natural_loops(g, entry);
  for (size_t li = 0; li < loops.size(); ++li) {
    const auto& lp = loops[li];
    LoopRow r;
    r.func_addr = fa;
    r.header_addr = addr[lp.header];
    r.latch_addr = addr[lp.latch];
    r.block_count = static_cast<int64_t>(lp.body.size());
    r.loop_kind = "natural";
    int64_t mn = 0, mx = 0;
    bool have = false;
    for (size_t b : lp.body) {
      if (!have || addr[b] < mn) { mn = addr[b]; have = true; }
      if (end_addr[b] > mx) mx = end_addr[b];
    }
    r.start_addr = mn;
    r.end_addr = mx;
    int64_t depth = 1;
    for (size_t lj = 0; lj < loops.size(); ++lj) {
      if (lj == li) continue;
      const auto& oth = loops[lj].body;
      if (oth.size() > lp.body.size() &&
          std::includes(oth.begin(), oth.end(), lp.body.begin(), lp.body.end()))
        ++depth;
    }
    r.depth = depth;
    out.push_back(std::move(r));
  }
}

// ---- per-table column emission (shared by generator and filter cursor) ----
void emit_column(xsql::FunctionContext& ctx, int col, const DominatorRow& r) {
  switch (col) {
    case 0: ctx.result_int64(r.func_addr); break;
    case 1: ctx.result_int64(r.node_addr); break;
    case 2: if (r.has_idom) ctx.result_int64(r.idom_addr); else ctx.result_null(); break;
    case 3: ctx.result_int64(r.depth); break;
    case 4: ctx.result_int64(r.is_entry ? 1 : 0); break;
    default: ctx.result_null(); break;
  }
}
void emit_column(xsql::FunctionContext& ctx, int col, const PostDominatorRow& r) {
  switch (col) {
    case 0: ctx.result_int64(r.func_addr); break;
    case 1: ctx.result_int64(r.node_addr); break;
    case 2: if (r.has_ipdom) ctx.result_int64(r.ipdom_addr); else ctx.result_null(); break;
    case 3: ctx.result_int64(r.depth); break;
    case 4: ctx.result_int64(r.is_exit ? 1 : 0); break;
    default: ctx.result_null(); break;
  }
}
void emit_column(xsql::FunctionContext& ctx, int col, const LoopRow& r) {
  switch (col) {
    case 0: ctx.result_int64(r.func_addr); break;
    case 1: ctx.result_int64(r.header_addr); break;
    case 2: ctx.result_int64(r.latch_addr); break;
    case 3: ctx.result_int64(r.start_addr); break;
    case 4: ctx.result_int64(r.end_addr); break;
    case 5: ctx.result_int64(r.depth); break;
    case 6: ctx.result_text(r.loop_kind); break;
    case 7: ctx.result_int64(r.block_count); break;
    default: ctx.result_null(); break;
  }
}

// Per-table rowid (dominators/post_dominators key on node_addr; loops on header).
inline int64_t row_rowid(const DominatorRow& r) { return r.node_addr; }
inline int64_t row_rowid(const PostDominatorRow& r) { return r.node_addr; }
inline int64_t row_rowid(const LoopRow& r) { return r.header_addr; }

// Full-scan generator: `aflj` then per-function collect, streamed one row at a time.
template <typename Row, typename Collect>
class GraphGen : public xsql::Generator<Row> {
  Backend* be_;
  Collect collect_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<Row> buf_;
  size_t bi_ = 0;
  Row cur_;
 public:
  GraphGen(Backend* be, Collect collect)
      : be_(be), collect_(collect), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      buf_.clear();
      collect_(be_, json_utils::i64_addr(funcs_[fi_++]), buf_);
      bi_ = 0;
    }
  }
  const Row& current() const override { return cur_; }
  int64_t rowid() const override { return row_rowid(cur_); }
};

// `WHERE func_addr = <fa>` pushdown: one afbj @ fa.
template <typename Row, typename Collect>
class GraphInFuncIterator : public xsql::RowIterator {
  std::vector<Row> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  GraphInFuncIterator(Backend* be, int64_t fa, Collect collect) {
    collect(be, fa, rows_);
  }
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    if (i_ >= rows_.size()) { ctx.result_null(); return; }
    emit_column(ctx, col, rows_[i_]);
  }
  int64_t rowid() const override { return row_rowid(rows_[i_]); }
};

}  // namespace

void register_dominators_table(Session& s) {
  using Collect = void (*)(Backend*, int64_t, std::vector<DominatorRow>&);
  auto def = xsql::generator_table<DominatorRow>("dominators")
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<DominatorRow>> {
      return std::make_unique<GraphGen<DominatorRow, Collect>>(be, &collect_dominators);
    })
    .column_int64("func_addr", [](const DominatorRow& r) { return r.func_addr; })
    .column_int64("node_addr", [](const DominatorRow& r) { return r.node_addr; })
    .column("idom_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const DominatorRow& r) {
              if (r.has_idom) ctx.result_int64(r.idom_addr); else ctx.result_null();
            })
    .column_int64("depth", [](const DominatorRow& r) { return r.depth; })
    .column_int64("is_entry", [](const DominatorRow& r) { return r.is_entry ? 1 : 0; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<GraphInFuncIterator<DominatorRow, Collect>>(be, fa, &collect_dominators);
      }, 5.0, 16.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

void register_post_dominators_table(Session& s) {
  using Collect = void (*)(Backend*, int64_t, std::vector<PostDominatorRow>&);
  auto def = xsql::generator_table<PostDominatorRow>("post_dominators")
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<PostDominatorRow>> {
      return std::make_unique<GraphGen<PostDominatorRow, Collect>>(be, &collect_post_dominators);
    })
    .column_int64("func_addr", [](const PostDominatorRow& r) { return r.func_addr; })
    .column_int64("node_addr", [](const PostDominatorRow& r) { return r.node_addr; })
    .column("ipdom_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const PostDominatorRow& r) {
              if (r.has_ipdom) ctx.result_int64(r.ipdom_addr); else ctx.result_null();
            })
    .column_int64("depth", [](const PostDominatorRow& r) { return r.depth; })
    .column_int64("is_exit", [](const PostDominatorRow& r) { return r.is_exit ? 1 : 0; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<GraphInFuncIterator<PostDominatorRow, Collect>>(be, fa, &collect_post_dominators);
      }, 5.0, 16.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

void register_loops_table(Session& s) {
  using Collect = void (*)(Backend*, int64_t, std::vector<LoopRow>&);
  auto def = xsql::generator_table<LoopRow>("loops")
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<LoopRow>> {
      return std::make_unique<GraphGen<LoopRow, Collect>>(be, &collect_loops);
    })
    .column_int64("func_addr", [](const LoopRow& r) { return r.func_addr; })
    .column_int64("header_addr", [](const LoopRow& r) { return r.header_addr; })
    .column_int64("latch_addr", [](const LoopRow& r) { return r.latch_addr; })
    .column_int64("start_addr", [](const LoopRow& r) { return r.start_addr; })
    .column_int64("end_addr", [](const LoopRow& r) { return r.end_addr; })
    .column_int64("depth", [](const LoopRow& r) { return r.depth; })
    .column_text("loop_kind", [](const LoopRow& r) { return r.loop_kind; })
    .column_int64("block_count", [](const LoopRow& r) { return r.block_count; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<GraphInFuncIterator<LoopRow, Collect>>(be, fa, &collect_loops);
      }, 5.0, 8.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2sql
