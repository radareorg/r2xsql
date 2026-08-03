// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// instruction_operands — one row per decoded instruction operand, from
// `aoj <n> @ <block>` (`opex.operands[]` gives per-operand {size, rw, type,
// value}; the rendered per-operand text is recovered by stripping the mnemonic
// from `disasm` and splitting the remainder on commas). Canonical cross-tool
// schema (addr, func_addr, operand_index, text, type_name, value, size).
// Pushdown: `WHERE addr = X` -> `aoj 1 @ X`; `WHERE func_addr = X` ->
// `afbj @ X` followed by one bounded `aoj` per basic block; an unfiltered scan
// walks `aflj` and decodes each function's operands lazily. Block-scoped reads
// are required because a function's blocks need not be contiguous in memory.

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {
struct OperandRow {
  int64_t     addr = 0;           // instruction address
  int64_t     func_addr = 0;      // containing function
  int64_t     operand_index = 0;
  std::string text;               // rendered per-operand text
  std::string type_name;          // register / immediate / memory / ...
  int64_t     value = 0;          // immediate value (0 when not an immediate)
  int64_t     size = 0;           // operand size in bytes
};

// r2 opex operand type -> canonical type_name vocabulary (register / immediate /
// memory), falling back to the raw r2 token for anything exotic.
std::string normalize_type(const std::string& t) {
  if (t == "reg") return "register";
  if (t == "imm") return "immediate";
  if (t == "mem") return "memory";
  return t.empty() ? "unknown" : t;
}

std::string trim(const std::string& s) {
  size_t b = s.find_first_not_of(" \t");
  if (b == std::string::npos) return "";
  size_t e = s.find_last_not_of(" \t");
  return s.substr(b, e - b + 1);
}

// Per-operand text: strip the leading mnemonic token from `disasm`, then split
// only top-level commas. Delimiters inside (), [] or {} belong to one rendered
// operand (notably ARM register lists such as "{r4, r5, lr}").
std::vector<std::string> split_operand_texts(const std::string& disasm) {
  std::vector<std::string> out;
  size_t sp = disasm.find(' ');
  if (sp == std::string::npos) return out;
  std::string rest = disasm.substr(sp + 1);
  size_t start = 0;
  int paren_depth = 0;
  int bracket_depth = 0;
  int brace_depth = 0;
  char quote = '\0';
  bool escaped = false;
  for (size_t i = 0; i < rest.size(); ++i) {
    const char ch = rest[i];
    if (quote != '\0') {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == quote) {
        quote = '\0';
      }
      continue;
    }
    if (ch == '\'' || ch == '"') {
      quote = ch;
    } else if (ch == '(') {
      ++paren_depth;
    } else if (ch == ')' && paren_depth > 0) {
      --paren_depth;
    } else if (ch == '[') {
      ++bracket_depth;
    } else if (ch == ']' && bracket_depth > 0) {
      --bracket_depth;
    } else if (ch == '{') {
      ++brace_depth;
    } else if (ch == '}' && brace_depth > 0) {
      --brace_depth;
    } else if (ch == ',' && paren_depth == 0 && bracket_depth == 0 &&
               brace_depth == 0) {
      std::string part = trim(rest.substr(start, i - start));
      if (!part.empty()) out.push_back(std::move(part));
      start = i + 1;
    }
  }
  std::string part = trim(rest.substr(start));
  if (!part.empty()) out.push_back(std::move(part));
  return out;
}

// Append the operands of every op in an `aoj` result array to `out`.
void decode_ops(const nlohmann::json& ops, int64_t func_addr,
                std::vector<OperandRow>& out,
                const std::unordered_set<int64_t>* allowed_addrs = nullptr,
                std::unordered_set<int64_t>* decoded_addrs = nullptr) {
  if (!ops.is_array()) return;
  for (const auto& op : ops) {
    int64_t iaddr = json_utils::i64(op, "addr");
    if (allowed_addrs && allowed_addrs->find(iaddr) == allowed_addrs->end()) {
      continue;
    }
    if (decoded_addrs && !decoded_addrs->insert(iaddr).second) continue;
    auto opex = op.find("opex");
    if (opex == op.end()) continue;
    auto operands = opex->find("operands");
    if (operands == opex->end() || !operands->is_array()) continue;
    std::vector<std::string> texts = split_operand_texts(json_utils::str(op, "disasm"));
    int64_t idx = 0;
    for (const auto& od : *operands) {
      OperandRow r;
      r.addr = iaddr;
      r.func_addr = func_addr;
      r.operand_index = idx;
      std::string t = json_utils::str(od, "type");
      r.type_name = normalize_type(t);
      r.size = json_utils::i64(od, "size");
      if (idx < static_cast<int64_t>(texts.size())) {
        r.text = texts[static_cast<size_t>(idx)];
      } else {
        // Fallback when disasm splitting under-counts (implicit/prefixed forms):
        // a register operand carries its name in `value`.
        auto v = od.find("value");
        if (t == "reg" && v != od.end() && v->is_string()) r.text = v->get<std::string>();
      }
      if (t == "imm") {
        auto v = od.find("value");
        if (v != od.end() && v->is_number_integer()) r.value = v->get<int64_t>();
      }
      out.push_back(std::move(r));
      ++idx;
    }
  }
}

// Decode a function block-by-block. `aoj <function.ninstrs> @ <function-start>`
// is incorrect for non-contiguous functions: aoj walks linear bytes, not the
// function's CFG. `afbj` supplies each block's exact instruction addresses.
std::vector<OperandRow> operands_for_func(Backend* be, int64_t fa) {
  std::vector<OperandRow> out;
  auto blocks = be->cmd_json("afbj @ " + json_utils::hex_addr(fa));
  if (!blocks.is_array()) return out;

  std::unordered_set<int64_t> decoded;
  for (const auto& block : blocks) {
    std::vector<int64_t> instruction_addrs;
    auto instrs = block.find("instrs");
    if (instrs != block.end() && instrs->is_array()) {
      instruction_addrs.reserve(instrs->size());
      for (const auto& addr : *instrs) {
        if (addr.is_number_integer()) instruction_addrs.push_back(addr.get<int64_t>());
        else if (addr.is_number_unsigned())
          instruction_addrs.push_back(static_cast<int64_t>(addr.get<uint64_t>()));
      }
    }

    int64_t count = static_cast<int64_t>(instruction_addrs.size());
    if (count <= 0) count = json_utils::i64(block, "ninstr");
    if (count <= 0) continue;
    const int64_t block_addr =
        json_utils::i64(block, "addr",
                        instruction_addrs.empty() ? fa : instruction_addrs.front());
    auto ops = be->cmd_json("aoj " + std::to_string(count) + " @ " +
                            json_utils::hex_addr(block_addr));

    if (instruction_addrs.empty()) {
      decode_ops(ops, fa, out, nullptr, &decoded);
      continue;
    }

    std::unordered_set<int64_t> allowed(instruction_addrs.begin(),
                                        instruction_addrs.end());
    decode_ops(ops, fa, out, &allowed, &decoded);

    // Decoder plugins occasionally stop a block read early. Fill only the
    // exact missing instruction addresses instead of walking into a gap.
    for (int64_t addr : instruction_addrs) {
      if (decoded.find(addr) != decoded.end()) continue;
      auto one = be->cmd_json("aoj 1 @ " + json_utils::hex_addr(addr));
      decode_ops(one, fa, out, &allowed, &decoded);
    }
  }
  return out;
}

// Resolve the function that contains `addr` (for the single-instruction path).
int64_t containing_func(Backend* be, int64_t addr) {
  auto fj = be->cmd_json("afij @ " + json_utils::hex_addr(addr));
  if (fj.is_array() && !fj.empty()) return json_utils::i64_addr(fj[0]);
  if (fj.is_object()) return json_utils::i64_addr(fj);
  return 0;
}

// Full-scan: `aflj`, then block-scoped `afbj` / `aoj` per function.
class OperandsGen : public xsql::Generator<OperandRow> {
  Backend* be_;
  nlohmann::json funcs_;
  size_t fi_ = 0;
  std::vector<OperandRow> buf_;
  size_t bi_ = 0;
  OperandRow cur_;
 public:
  explicit OperandsGen(Backend* be) : be_(be), funcs_(be->cmd_json("aflj")) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (!funcs_.is_array() || fi_ >= funcs_.size()) return false;
      const auto& f = funcs_[fi_++];
      buf_ = operands_for_func(be_, json_utils::i64_addr(f));
      bi_ = 0;
    }
  }
  const OperandRow& current() const override { return cur_; }
  int64_t rowid() const override {
    return static_cast<int64_t>(
        (static_cast<uint64_t>(cur_.addr) << 4) ^
        static_cast<uint64_t>(cur_.operand_index));
  }
};

// Pushdown for `WHERE func_addr = <fa>`: one afbj plus bounded aoj reads.
class OperandsInFuncIterator : public xsql::RowIterator {
  std::vector<OperandRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  OperandsInFuncIterator(Backend* be, int64_t fa)
      : rows_(operands_for_func(be, fa)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const OperandRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;
      case 1: ctx.result_int64(r.func_addr); break;
      case 2: ctx.result_int64(r.operand_index); break;
      case 3: ctx.result_text(r.text); break;
      case 4: ctx.result_text(r.type_name); break;
      case 5: ctx.result_int64(r.value); break;
      case 6: ctx.result_int64(r.size); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override {
    return static_cast<int64_t>(
        (static_cast<uint64_t>(rows_[i_].addr) << 4) ^
        static_cast<uint64_t>(rows_[i_].operand_index));
  }
};

// Pushdown for `WHERE addr = <ia>`: one `aoj 1 @ ia` (func_addr resolved via afij).
class OperandsAtAddrIterator : public xsql::RowIterator {
  std::vector<OperandRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  OperandsAtAddrIterator(Backend* be, int64_t ia) {
    auto ops = be->cmd_json("aoj 1 @ " + json_utils::hex_addr(ia));
    decode_ops(ops, containing_func(be, ia), rows_);
  }
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const OperandRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;
      case 1: ctx.result_int64(r.func_addr); break;
      case 2: ctx.result_int64(r.operand_index); break;
      case 3: ctx.result_text(r.text); break;
      case 4: ctx.result_text(r.type_name); break;
      case 5: ctx.result_int64(r.value); break;
      case 6: ctx.result_int64(r.size); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override {
    return static_cast<int64_t>(
        (static_cast<uint64_t>(rows_[i_].addr) << 4) ^
        static_cast<uint64_t>(rows_[i_].operand_index));
  }
};
}  // namespace

void register_operands_table(Session& s) {
  auto def = xsql::generator_table<OperandRow>("instruction_operands")
    .estimate_rows([]() -> size_t { return 200000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<OperandRow>> {
      return std::make_unique<OperandsGen>(be);
    })
    .column_int64("addr",          [](const OperandRow& r) { return r.addr; })
    .column_int64("func_addr",     [](const OperandRow& r) { return r.func_addr; })
    .column_int64("operand_index", [](const OperandRow& r) { return r.operand_index; })
    .column_text ("text",          [](const OperandRow& r) { return r.text; })
    .column_text ("type_name",     [](const OperandRow& r) { return r.type_name; })
    .column_int64("value",         [](const OperandRow& r) { return r.value; })
    .column_int64("size",          [](const OperandRow& r) { return r.size; })
    .filter_eq("addr",
      [be = s.backend_ptr()](int64_t ia) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<OperandsAtAddrIterator>(be, ia);
      }, 1.0, 3.0)
    .filter_eq("func_addr",
      [be = s.backend_ptr()](int64_t fa) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<OperandsInFuncIterator>(be, fa);
      }, 5.0, 32.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
