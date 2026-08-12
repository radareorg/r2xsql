// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// function_frames — per-function stack-frame layout. Canonical cross-tool schema
// (func_addr, frame_size, arg_size, local_size, saved_reg_size, stack_base_reg,
// has_frame_pointer). r2 supplies 2/7: `afij`'s `stackframe` gives `frame_size`; the
// other columns are NULL because r2 does not cleanly expose local/arg byte sizes
// (afvj vars carry offset/type but no size), saved-register size, the SP register
// name, or a frame-pointer flag. `func_addr` equality pushes down to one `afij @ X`.

#include <memory>
#include <optional>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {
struct FrameRow {
  int64_t func_addr = 0;
  bool has_frame_size = false;
  int64_t frame_size = 0;
};

// `afij @ <fa>` returns a one-element array (or object) with a `stackframe` field.
std::optional<FrameRow> frame_for_func(Backend* be, int64_t fa) {
  FrameRow r;
  r.func_addr = fa;
  auto j = be->cmd_json("afij @ " + json_utils::hex_addr(fa));
  const nlohmann::json* f = nullptr;
  if (j.is_array() && !j.empty() && j[0].is_object()) f = &j[0];
  else if (j.is_object()) f = &j;
  if (!f) return std::nullopt;
  const int64_t actual_func_addr = json_utils::i64_addr(*f);
  if (actual_func_addr != fa) return std::nullopt;
  r.func_addr = actual_func_addr;
  auto it = f->find("stackframe");
  if (it != f->end() && it->is_number_integer()) {
    r.frame_size = it->get<int64_t>();
    r.has_frame_size = true;
  }
  return r;
}

// 0 func_addr, 1 frame_size, 2 arg_size(NULL), 3 local_size(NULL),
// 4 saved_reg_size(NULL), 5 stack_base_reg(NULL), 6 has_frame_pointer(NULL).
void emit_column(xsql::FunctionContext& ctx, int col, const FrameRow& r) {
  switch (col) {
    case 0: ctx.result_int64(r.func_addr); break;
    case 1: if (r.has_frame_size) ctx.result_int64(r.frame_size); else ctx.result_null(); break;
    default: ctx.result_null(); break;  // 2..6 not exposed by r2
  }
}

class FramesGen : public xsql::Generator<FrameRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  FrameRow cur_;
 public:
  explicit FramesGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    while (funcs_.is_array() && fi_ < funcs_.size()) {
      auto row = frame_for_func(be_, json_utils::i64_addr(funcs_[fi_++]));
      if (row) {
        cur_ = std::move(*row);
        return true;
      }
    }
    return false;
  }
  const FrameRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.func_addr; }
};

class FramesInFuncIterator : public xsql::RowIterator {
  std::vector<FrameRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  FramesInFuncIterator(Backend* be, int64_t fa) {
    if (auto row = frame_for_func(be, fa)) rows_.push_back(std::move(*row));
  }
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override { emit_column(ctx, col, rows_[i_]); }
  int64_t rowid() const override { return rows_[i_].func_addr; }
};
}  // namespace

void register_function_frames_table(Session& s) {
  auto def = xsql::generator_table<FrameRow>("function_frames")
    .estimate_rows([]() -> size_t { return 1000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<FrameRow>> {
      return std::make_unique<FramesGen>(be);
    })
    .column_int64("func_addr", [](const FrameRow& r) { return r.func_addr; })
    .column("frame_size", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const FrameRow& r) {
              if (r.has_frame_size) ctx.result_int64(r.frame_size); else ctx.result_null();
            })
    .column("arg_size", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const FrameRow&) { ctx.result_null(); })
    .column("local_size", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const FrameRow&) { ctx.result_null(); })
    .column("saved_reg_size", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const FrameRow&) { ctx.result_null(); })
    .column("stack_base_reg", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const FrameRow&) { ctx.result_null(); })
    .column("has_frame_pointer", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const FrameRow&) { ctx.result_null(); })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<FramesInFuncIterator>(be, fa);
      }, 2.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
