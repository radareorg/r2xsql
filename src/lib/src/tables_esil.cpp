// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// esil_ops / esil_operands — the r2 leg of the cross-tool low-IR. radare2 exposes ESIL
// (a postfix stack IL string) per instruction on the `instructions` table; this file runs
// the ESIL stack machine to rebuild a FINER canonical op stream (esil_ops, multiple ops per
// instruction) + its operands (esil_operands, 5-kind). ir_ops / ir_v_* / ir_operands project
// from these (a fidelity upgrade over the coarse one-op.type-per-instruction path).
//
// r2 is the PARTIAL / lowest-fidelity leg: flag-set idioms + stack juggling do not all reduce
// to one canonical op. maturity is the constant `esil` (r2 has one rung).

#include <cctype>
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

struct EsilOpRow {
  int64_t func_addr = 0;
  int seq = 0;             // per-function esil-op index (finer than instruction seq)
  int64_t addr = 0;        // source instruction address
  std::string op;          // canonical P-code-style op (never empty — only mapped ops emit a row)
  std::string native_op;   // the ESIL operator token (e.g. "+=", "=[8]", "^")
};

struct EsilOperandRow {
  int64_t func_addr = 0;
  int op_seq = 0;          // owning esil_op's seq (joins esil_ops.seq)
  int operand_index = 0;
  std::string role;        // "in" | "out"
  std::string kind;        // reg | imm | mem | var | result
  std::string text;        // the ESIL token text
};

// ESIL binary operator -> canonical op (pops destination/left first, then
// source/right, and pushes a result), except `==`, which only updates ESIL's
// internal comparison state.
const char* esil_binop(const std::string& t) {
  if (t == "+") return "INT_ADD";
  if (t == "-") return "INT_SUB";
  if (t == "*") return "INT_MULT";
  if (t == "/") return "INT_DIV";
  if (t == "%") return "INT_REM";
  if (t == "&") return "INT_AND";
  if (t == "|") return "INT_OR";
  if (t == "^") return "INT_XOR";
  if (t == "<<" || t == "<<<") return "INT_LEFT";
  if (t == ">>" || t == ">>>") return "INT_RIGHT";
  if (t == "==") return "INT_EQUAL";
  if (t == "<" || t == ">") return "INT_LESS";
  if (t == "<=" || t == ">=") return "INT_LESSEQUAL";
  return nullptr;
}
// Read-modify-write (dest OP= value; dest is TOS reg, role out) -> canonical of the base op.
const char* esil_rmw(const std::string& t) {
  if (t == "+=") return "INT_ADD";
  if (t == "-=") return "INT_SUB";
  if (t == "*=") return "INT_MULT";
  if (t == "/=") return "INT_DIV";
  if (t == "%=") return "INT_REM";
  if (t == "&=") return "INT_AND";
  if (t == "|=") return "INT_OR";
  if (t == "^=") return "INT_XOR";
  if (t == "<<=") return "INT_LEFT";
  if (t == ">>=") return "INT_RIGHT";
  return nullptr;
}
const char* esil_unop(const std::string& t) {
  if (t == "!") return "BOOL_NEGATE";
  if (t == "++") return "INT_ADD";
  if (t == "--") return "INT_SUB";
  return nullptr;
}
// ESIL models control flow as rip register assignments (`0x..,rip,=`), NOT distinct branch
// ops — so the canonical CALL/BRANCH/RETURN op comes from the instruction's r2 op `type`,
// emitted alongside the ESIL data ops so ir_v_calls / ir_v_branches stay non-empty.
const char* esil_control_op(const std::string& t) {
  if (t == "call" || t == "rcall" || t == "ccall") return "CALL";
  if (t == "ucall" || t == "icall" || t == "ircall" || t == "uccall") return "CALLIND";
  if (t == "jmp" || t == "rjmp") return "BRANCH";
  if (t == "ujmp" || t == "ijmp" || t == "mjmp" || t == "irjmp") return "BRANCHIND";
  if (t == "cjmp" || t == "mcjmp" || t == "rcjmp" || t == "ucjmp") return "CBRANCH";
  if (t == "ret" || t == "cret") return "RETURN";
  return nullptr;
}

bool esil_is_number(const std::string& t) {
  if (t.empty()) return false;
  size_t i = 0;
  if (t[0] == '-') { if (t.size() == 1) return false; i = 1; }
  if (t.compare(i, 2, "0x") == 0 || t.compare(i, 2, "0X") == 0) {
    if (i + 2 >= t.size()) return false;
    for (size_t j = i + 2; j < t.size(); ++j)
      if (!std::isxdigit((unsigned char)t[j])) return false;
    return true;
  }
  for (size_t j = i; j < t.size(); ++j)
    if (!std::isdigit((unsigned char)t[j])) return false;
  return true;
}
bool esil_is_flag(const std::string& t) { return !t.empty() && t[0] == '$'; }
bool esil_is_reg(const std::string& t) {
  if (t.empty() || !std::islower((unsigned char)t[0])) return false;
  for (char c : t) if (!std::islower((unsigned char)c) && !std::isdigit((unsigned char)c)) return false;
  return true;
}

// One stack entry: the token text + its 5-kind (for the operand rows the operators pop).
struct EsilStackEntry { std::string text; std::string kind; };

// Run the ESIL stack machine over one instruction's ESIL string, appending esil_ops
// (with a running per-function seq) and esil_operands.
void tokenize_esil(const std::string& esil, int64_t func_addr, int64_t addr, int& seq,
                   std::vector<EsilOpRow>& ops, std::vector<EsilOperandRow>& operands) {
  std::vector<EsilStackEntry> stack;
  auto pop = [&]() -> EsilStackEntry {
    if (stack.empty()) return {"?", "result"};
    EsilStackEntry e = stack.back();
    stack.pop_back();
    return e;
  };
  auto emit_op = [&](const char* canon, const std::string& native) -> int {
    EsilOpRow r;
    r.func_addr = func_addr;
    r.seq = seq;
    r.addr = addr;
    r.op = canon;
    r.native_op = native;
    ops.push_back(std::move(r));
    return seq++;
  };
  auto emit_operand = [&](int op_seq, int idx, const char* role, const EsilStackEntry& e) {
    EsilOperandRow r;
    r.func_addr = func_addr;
    r.op_seq = op_seq;
    r.operand_index = idx;
    r.role = role;
    r.kind = e.kind;
    r.text = e.text;
    operands.push_back(std::move(r));
  };

  size_t start = 0;
  while (start <= esil.size()) {
    size_t comma = esil.find(',', start);
    std::string tok = esil.substr(start, comma == std::string::npos ? std::string::npos
                                                                     : comma - start);
    start = (comma == std::string::npos) ? esil.size() + 1 : comma + 1;
    if (tok.empty()) continue;

    // ---- memory: [N] load, =[N] store ----
    if (tok.size() >= 2 && tok.front() == '[' && tok.back() == ']') {
      auto s = pop();
      int os = emit_op("LOAD", tok);
      emit_operand(os, 0, "in", s);
      stack.push_back({"<load>", "mem"});
      continue;
    }
    if (tok.size() >= 3 && tok.compare(0, 2, "=[") == 0 && tok.back() == ']') {
      auto addr_e = pop();
      auto val = pop();
      int os = emit_op("STORE", tok);
      emit_operand(os, 0, "in", addr_e);
      emit_operand(os, 1, "in", val);
      continue;
    }
    // ---- operators ----
    if (const char* c = esil_binop(tok)) {
      auto lhs = pop();
      auto rhs = pop();
      int os = emit_op(c, tok);
      emit_operand(os, 0, "in", lhs);
      emit_operand(os, 1, "in", rhs);
      if (tok != "==") stack.push_back({"<res>", "result"});
      continue;
    }
    if (const char* c = esil_rmw(tok)) {
      auto dest = pop();
      auto val = pop();
      int os = emit_op(c, tok);
      emit_operand(os, 0, "out", dest);
      emit_operand(os, 1, "in", val);
      continue;
    }
    if (tok == "~") {
      auto value = pop();
      auto width = pop();
      int os = emit_op("INT_SEXT", tok);
      emit_operand(os, 0, "in", value);
      emit_operand(os, 1, "in", width);
      stack.push_back({"<res>", "result"});
      continue;
    }
    if (const char* c = esil_unop(tok)) {
      auto a = pop();
      int os = emit_op(c, tok);
      emit_operand(os, 0, "in", a);
      stack.push_back({"<res>", "result"});
      continue;
    }
    if (tok == "++=" || tok == "--=" || tok == "!=") {
      auto dest = pop();
      const char* canon = tok == "!=" ? "BOOL_NEGATE"
                                       : (tok == "++=" ? "INT_ADD" : "INT_SUB");
      int os = emit_op(canon, tok);
      emit_operand(os, 0, "out", dest);
      continue;
    }
    if (tok == "=" || tok == ":=") {
      auto dest = pop();
      auto val = pop();
      int os = emit_op("COPY", tok);
      emit_operand(os, 0, "out", dest);
      emit_operand(os, 1, "in", val);
      continue;
    }
    // ---- stack/control operators that do not map to canonical rows ----
    if (tok == "?{" || tok == "POP" ||
        tok == "SETJT" || tok == "SETJTS" || tok == "SETD") {
      (void)pop();
      continue;
    }
    if (tok == "GOTO") {
      (void)pop();
      stack.clear();
      continue;
    }
    if (tok == "TRAP") {
      (void)pop();
      (void)pop();
      continue;
    }
    if (tok == "}" || tok == "}{") {
      // The two arms have different runtime stacks. Do not let values from the
      // statically tokenized first arm become operands in the other arm.
      stack.clear();
      continue;
    }
    if (tok == "STACK" || tok == "TODO") {
      continue;
    }
    if (tok == "BREAK") {
      stack.clear();
      continue;
    }
    if (tok == "CLEAR") {
      stack.clear();
      continue;
    }
    if (tok == "DUP") {
      auto value = pop();
      stack.push_back(value);
      stack.push_back(value);
      continue;
    }
    if (tok == "SWAP") {
      auto first = pop();
      auto second = pop();
      stack.push_back(first);
      stack.push_back(second);
      continue;
    }
    if (tok == "NUM") {
      auto value = pop();
      value.kind = "result";
      stack.push_back(std::move(value));
      continue;
    }
    if (tok == "$z" || tok == "$p" || tok == "$ds" ||
        tok == "$jt" || tok == "$js" || tok == "BITS") {
      stack.push_back({"<flag>", "result"});
      continue;
    }
    if (tok == "$c" || tok == "$b" || tok == "$s" || tok == "$o") {
      (void)pop();
      stack.push_back({"<flag>", "result"});
      continue;
    }
    // ---- operands (pushed) ----
    if (esil_is_number(tok)) stack.push_back({tok, "imm"});
    else if (esil_is_reg(tok)) stack.push_back({tok, "reg"});
    else if (esil_is_flag(tok)) {
      // Unknown `$...` tokens are operators or internal state references, not
      // ordinary registers. Their arity is unknown, so discard the simulated
      // stack rather than misattributing an earlier value to a later op.
      stack.clear();
    } else {
      // Custom/unknown ESIL operators have unknown stack effects. Continuing
      // with stale entries creates convincing but false operand relationships.
      stack.clear();
    }
  }
}

// Tokenize every instruction of one function into esil_ops + esil_operands (one pdfj RPC).
void esil_rows_for_func(Backend* be, int64_t fa,
                        std::vector<EsilOpRow>& ops, std::vector<EsilOperandRow>& operands) {
  auto pdf = be->cmd_json("pdfj @ " + json_utils::hex_addr(fa));
  if (!pdf.is_object()) return;
  auto it = pdf.find("ops");
  if (it == pdf.end() || !it->is_array()) return;
  int seq = 0;
  for (auto& op : *it) {
    const int64_t addr = json_utils::i64_addr(op);
    std::string esil = json_utils::str(op, "esil");
    if (!esil.empty()) tokenize_esil(esil, fa, addr, seq, ops, operands);
    // Control flow is not an ESIL op — emit it from the instruction's semantic type.
    if (const char* c = esil_control_op(json_utils::str(op, "type"))) {
      EsilOpRow r;
      r.func_addr = fa;
      r.seq = seq++;
      r.addr = addr;
      r.op = c;
      r.native_op = json_utils::str(op, "type");
      ops.push_back(std::move(r));
    }
  }
}

// ---- esil_ops table ----
class EsilOpsGen : public xsql::Generator<EsilOpRow> {
  Backend* be_;
  std::vector<int64_t> funcs_;
  size_t fi_ = 0;
  std::vector<EsilOpRow> buf_;
  std::vector<EsilOperandRow> discard_;
  size_t bi_ = 0;
  EsilOpRow cur_;
  // Monotonic per-cursor rowid: a packed (func_addr<<20)|seq can alias into the
  // func_addr bits for a >1M-op function, so hand out a collision-free running id.
  int64_t rid_ = 0;
 public:
  explicit EsilOpsGen(Backend* be) : be_(be), funcs_(table_utils::function_starts(be)) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; ++rid_; return true; }
      if (fi_ >= funcs_.size()) return false;
      buf_.clear(); discard_.clear();
      esil_rows_for_func(be_, funcs_[fi_++], buf_, discard_);
      bi_ = 0;
    }
  }
  const EsilOpRow& current() const override { return cur_; }
  int64_t rowid() const override { return rid_; }
};
class EsilOpsInFuncIterator : public xsql::RowIterator {
  std::vector<EsilOpRow> rows_;
  std::vector<EsilOperandRow> discard_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  EsilOpsInFuncIterator(Backend* be, int64_t fa) {
    if (!table_utils::func_addr_is_start(be, fa)) return;
    esil_rows_for_func(be, fa, rows_, discard_);
  }
  bool next() override { if (!started_) started_ = true; else ++i_; return i_ < rows_.size(); }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const EsilOpRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.func_addr); break;
      case 1: ctx.result_int(r.seq); break;
      case 2: ctx.result_int64(r.addr); break;
      case 3: ctx.result_text(r.op); break;
      case 4: ctx.result_text(r.native_op); break;
      default: ctx.result_null(); break;
    }
  }
  // Row index is already unique+monotonic within this single-function scan.
  int64_t rowid() const override { return static_cast<int64_t>(i_); }
};

// ---- esil_operands table ----
class EsilOperandsGen : public xsql::Generator<EsilOperandRow> {
  Backend* be_;
  std::vector<int64_t> funcs_;
  size_t fi_ = 0;
  std::vector<EsilOpRow> discard_;
  std::vector<EsilOperandRow> buf_;
  size_t bi_ = 0;
  EsilOperandRow cur_;
  // Monotonic per-cursor rowid: a packed (func_addr<<24)|(op_seq<<4)|operand_index
  // can alias into func_addr for a large function, so hand out a running id.
  int64_t rid_ = 0;
 public:
  explicit EsilOperandsGen(Backend* be) : be_(be), funcs_(table_utils::function_starts(be)) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; ++rid_; return true; }
      if (fi_ >= funcs_.size()) return false;
      discard_.clear(); buf_.clear();
      esil_rows_for_func(be_, funcs_[fi_++], discard_, buf_);
      bi_ = 0;
    }
  }
  const EsilOperandRow& current() const override { return cur_; }
  int64_t rowid() const override { return rid_; }
};
class EsilOperandsInFuncIterator : public xsql::RowIterator {
  std::vector<EsilOpRow> discard_;
  std::vector<EsilOperandRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  EsilOperandsInFuncIterator(Backend* be, int64_t fa) {
    if (!table_utils::func_addr_is_start(be, fa)) return;
    esil_rows_for_func(be, fa, discard_, rows_);
  }
  bool next() override { if (!started_) started_ = true; else ++i_; return i_ < rows_.size(); }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const EsilOperandRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.func_addr); break;
      case 1: ctx.result_int(r.op_seq); break;
      case 2: ctx.result_int(r.operand_index); break;
      case 3: ctx.result_text(r.role); break;
      case 4: ctx.result_text(r.kind); break;
      case 5: ctx.result_text(r.text); break;
      default: ctx.result_null(); break;
    }
  }
  // Row index is already unique+monotonic within this single-function scan.
  int64_t rowid() const override { return static_cast<int64_t>(i_); }
};

}  // namespace

void register_esil_tables(Session& s) {
  auto ops_def = xsql::generator_table<EsilOpRow>("esil_ops")
    .estimate_rows([]() -> size_t { return 400000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<EsilOpRow>> {
      return std::make_unique<EsilOpsGen>(be);
    })
    .column_int64("func_addr", [](const EsilOpRow& r) { return r.func_addr; })
    .column_int  ("seq",       [](const EsilOpRow& r) { return r.seq; })
    .column_int64("addr",      [](const EsilOpRow& r) { return r.addr; })
    .column_text ("op",        [](const EsilOpRow& r) { return r.op; })
    .column_text ("native_op", [](const EsilOpRow& r) { return r.native_op; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<EsilOpsInFuncIterator>(be, fa);
      }, 6.0, 96.0)
    .build();
  s.db().register_and_create_generator_table(ops_def);

  auto opnd_def = xsql::generator_table<EsilOperandRow>("esil_operands")
    .estimate_rows([]() -> size_t { return 800000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<EsilOperandRow>> {
      return std::make_unique<EsilOperandsGen>(be);
    })
    .column_int64("func_addr",     [](const EsilOperandRow& r) { return r.func_addr; })
    .column_int  ("op_seq",        [](const EsilOperandRow& r) { return r.op_seq; })
    .column_int  ("operand_index", [](const EsilOperandRow& r) { return r.operand_index; })
    .column_text ("role",          [](const EsilOperandRow& r) { return r.role; })
    .column_text ("kind",          [](const EsilOperandRow& r) { return r.kind; })
    .column_text ("text",          [](const EsilOperandRow& r) { return r.text; })
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<EsilOperandsInFuncIterator>(be, fa);
      }, 6.0, 128.0)
    .build();
  s.db().register_and_create_generator_table(opnd_def);

  // ------------------------------------------------------------------------
  // Cross-tool low-IR (ir_ops family) over the FINER esil_ops / esil_operands stream
  // (a fidelity upgrade over the coarse instructions-based path). r2 is the lowest-
  // fidelity leg: is_ssa=0, single rung maturity='esil', marked partial. Scope by
  // func_addr (pushes down to the esil generators).
  // ------------------------------------------------------------------------
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_ops AS
    SELECT
      func_addr,
      seq,
      addr,
      op,
      native_op,
      0 AS is_ssa,
      'esil' AS maturity,
      'final' AS stage
    FROM esil_ops
  )");
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_v_calls AS
    SELECT func_addr, seq, addr, op FROM esil_ops WHERE op IN ('CALL', 'CALLIND')
  )");
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_v_mem_writes AS
    SELECT func_addr, seq, addr, op FROM esil_ops WHERE op = 'STORE'
  )");
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_v_mem_reads AS
    SELECT func_addr, seq, addr, op FROM esil_ops WHERE op = 'LOAD'
  )");
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_v_branches AS
    SELECT func_addr, seq, addr, op FROM esil_ops WHERE op IN ('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN')
  )");
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_v_arith AS
    SELECT func_addr, seq, addr, op FROM esil_ops WHERE op IN (
      'INT_ADD','INT_SUB','INT_MULT','INT_DIV','INT_REM','INT_2COMP','INT_NEGATE',
      'INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_SRIGHT'
    )
  )");
  // ir_operands — the 5-kind value operand rows (join ir_ops on func_addr + op_seq = seq).
  // Same 8-column contract as the other tools; ESIL operands carry no clean value/size
  // (the token IS the text), so those are NULL for r2 (the partial leg).
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_operands AS
    SELECT func_addr, op_seq, operand_index, role, NULLIF(kind, '') AS kind, text,
           NULL AS value, NULL AS size
    FROM esil_operands
  )");
  // ir_maturities — r2 has ONE rung (ESIL). is_default=1, is_ssa=0.
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS ir_maturities AS
    SELECT 'esil' AS maturity, 'final' AS stage, 0 AS ordinal, 1 AS is_default, 0 AS is_ssa
  )");
}

}  // namespace r2xsql
