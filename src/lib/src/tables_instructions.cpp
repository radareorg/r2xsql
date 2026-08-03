// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// instructions — per-function disassembly via `pdfj @ <addr>`. A `func_addr`
// equality filter is pushed down: `WHERE func_addr = X` issues a single
// `pdfj @ X` instead of enumerating every function. An unfiltered scan walks
// `aflj` then issues `pdfj @` per function.

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {
struct InsnRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string mnemonic;
  std::string disasm;
  std::string bytes;
  int64_t     func_addr = 0;
  std::string esil;        // radare2's stack IL for this instruction
  int         seq = 0;         // per-function instruction index (cross-tool low-IR)
  std::string op_type;         // radare2 semantic op type ("add", "call", "cjmp", ...)
  std::string canonical_op;    // cross-tool canonical P-code-style op; "" if none
};

// radare2 op `type` string -> canonical P-code-style op (cross-tool low-IR).
// r2 is the lowest-fidelity leg (disasm/ESIL, no SSA); "" for types with no clean
// canonical (stack push/pop, cmp/test flag ops, nop, trap, ...).
std::string r2_canonical_op(const std::string& t) {
  if (t == "mov" || t == "lea" || t == "cast" || t == "movs") return "COPY";
  if (t == "load") return "LOAD";
  if (t == "store") return "STORE";
  if (t == "add") return "INT_ADD";
  if (t == "sub") return "INT_SUB";
  if (t == "mul") return "INT_MULT";
  if (t == "div") return "INT_DIV";
  if (t == "mod") return "INT_REM";
  if (t == "and") return "INT_AND";
  if (t == "or")  return "INT_OR";
  if (t == "xor") return "INT_XOR";
  if (t == "shl") return "INT_LEFT";
  if (t == "shr") return "INT_RIGHT";
  if (t == "sar") return "INT_SRIGHT";
  if (t == "not" || t == "cpl") return "INT_NEGATE";
  if (t == "call" || t == "rcall" || t == "ccall") return "CALL";
  if (t == "ucall" || t == "icall" || t == "ircall" || t == "uccall") return "CALLIND";
  if (t == "jmp" || t == "rjmp") return "BRANCH";
  if (t == "ujmp" || t == "ijmp" || t == "mjmp" || t == "irjmp") return "BRANCHIND";
  if (t == "cjmp" || t == "mcjmp" || t == "rcjmp" || t == "ucjmp") return "CBRANCH";
  if (t == "ret" || t == "cret") return "RETURN";
  return "";
}

// One scoped `pdfj @ <fa>` call → the instructions of a single function.
std::string mnemonic_from_op(const nlohmann::json& op) {
  std::string text = json_utils::str(op, "opcode");
  if (text.empty()) text = json_utils::str(op, "disasm");
  if (text.empty()) return json_utils::str(op, "type");
  const size_t pos = text.find_first_of(" \t\r\n");
  return pos == std::string::npos ? text : text.substr(0, pos);
}

std::vector<InsnRow> insns_for_func(Backend* be, int64_t fa) {
  std::vector<InsnRow> out;
  auto pdf = be->cmd_json("pdfj @ " + json_utils::hex_addr(fa));
  if (!pdf.is_object()) return out;
  auto ops = pdf.find("ops");
  if (ops == pdf.end() || !ops->is_array()) return out;
  int seq = 0;
  for (auto& op : *ops) {
    InsnRow r;
    r.addr      = json_utils::i64_addr(op);
    r.size      = json_utils::i64(op, "size");
    r.mnemonic  = mnemonic_from_op(op);
    r.disasm    = json_utils::str(op, "disasm");
    r.bytes     = json_utils::str(op, "bytes");
    r.esil      = json_utils::str(op, "esil");
    r.func_addr = fa;
    r.seq       = seq++;
    r.op_type   = json_utils::str(op, "type");
    r.canonical_op = r2_canonical_op(r.op_type);
    out.push_back(std::move(r));
  }
  return out;
}

class InsnsGen : public xsql::Generator<InsnRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<InsnRow> buf_;
  size_t bi_ = 0;
  InsnRow cur_;
 public:
  explicit InsnsGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      buf_ = insns_for_func(be_, json_utils::i64_addr(funcs_[fi_++]));
      bi_ = 0;
    }
  }
  const InsnRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

class InsnsInFuncIterator : public xsql::RowIterator {
  std::vector<InsnRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  InsnsInFuncIterator(Backend* be, int64_t fa) : rows_(insns_for_func(be, fa)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const InsnRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;
      case 1: ctx.result_int64(r.size); break;
      case 2: ctx.result_text(r.mnemonic); break;
      case 3: ctx.result_text(r.disasm); break;
      case 4: ctx.result_text(r.bytes); break;
      case 5: ctx.result_int64(r.func_addr); break;
      case 6: ctx.result_text(r.esil); break;
      case 7: ctx.result_int(r.seq); break;
      case 8: ctx.result_text(r.op_type); break;
      case 9: ctx.result_text(r.canonical_op); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return rows_[i_].addr; }
};
}  // namespace

void register_instructions_table(Session& s) {
  auto def = xsql::generator_table<InsnRow>("instructions")
    .estimate_rows([]() -> size_t { return 100000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<InsnRow>> {
      return std::make_unique<InsnsGen>(be);
    })
    .column_int64("addr",      [](const InsnRow& r) { return r.addr; })
    .column_int64("size",      [](const InsnRow& r) { return r.size; })
    .column_text ("mnemonic",  [](const InsnRow& r) { return r.mnemonic; })
    .column_text ("disasm",    [](const InsnRow& r) { return r.disasm; })
    .column_text ("bytes",     [](const InsnRow& r) { return r.bytes; })
    .column_int64("func_addr", [](const InsnRow& r) { return r.func_addr; })
    // ESIL (radare2's stack IL), from the same pdfj op object — no extra r2 command.
    .column_text ("esil",      [](const InsnRow& r) { return r.esil; })
    // Cross-tool low-IR: per-function seq + radare2 semantic op type + canonical map.
    .column_int  ("seq",          [](const InsnRow& r) { return r.seq; })
    .column_text ("op_type",      [](const InsnRow& r) { return r.op_type; })
    .column_text ("canonical_op", [](const InsnRow& r) { return r.canonical_op; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<InsnsInFuncIterator>(be, fa);
      }, 5.0, 64.0)
    .build();
  s.db().register_and_create_generator_table(def);

  // NOTE: the cross-tool low-IR views (ir_ops / ir_v_* / ir_operands / ir_maturities) now
  // project from the FINER esil_ops / esil_operands stream (see tables_esil.cpp), not the
  // coarse one-op.type-per-instruction path. The coarse op_type/canonical_op columns stay on
  // `instructions` for cheap per-instruction classification.
}

}  // namespace r2xsql
