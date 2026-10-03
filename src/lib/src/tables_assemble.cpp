// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// assemble uses pa; search_asm uses /a and parses its text output.
// /aj selects the instruction-type search family, not a JSON form of /a.
// Search arguments bypass command expansion and search.in is restored natively.

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {

// ---------------------------------------------------------------------------
// assemble
// ---------------------------------------------------------------------------

struct AssembleRow {
  std::string hex;             // empty iff assembly failed
  std::vector<uint8_t> bytes;
  int64_t size = 0;
  std::string error;           // empty iff hex is non-empty
};

enum AssembleCol { kAHex = 0, kABytes = 1, kASize = 2, kAError = 3,
                    kAAsm = 4, kAAddr = 5 };

AssembleRow run_assemble(Backend* be, const std::string& asm_text, int64_t addr) {
  AssembleRow row;
  if (asm_text.empty()) {
    row.error = "assemble: asm must not be empty";
    return row;
  }
  if (!json_utils::valid_asm_source_text(asm_text)) {
    row.error = "assemble: asm accepts only disassembly-safe characters "
                "(letters, digits, space, and ,.+-*/[]():%#_$)";
    return row;
  }
  std::string hex;
  if (!table_utils::assemble_hex(be, addr, asm_text, &hex)) {
    row.error = "assemble: radare2 could not assemble '" + asm_text +
                "' (bad mnemonic/operands, or unsupported on this arch)";
    return row;
  }
  std::vector<uint8_t> bytes;
  if (!json_utils::hex_decode(hex, bytes)) {
    row.error = "assemble: radare2 produced non-hex output";
    return row;
  }
  row.hex = hex;
  row.bytes = std::move(bytes);
  row.size = static_cast<int64_t>(row.bytes.size());
  return row;
}

class AssembleGen : public xsql::Generator<AssembleRow> {
  AssembleRow row_;
  bool served_ = false;
 public:
  explicit AssembleGen(AssembleRow row) : row_(std::move(row)) {}
  bool next() override {
    if (served_) return false;
    served_ = true;
    return true;
  }
  const AssembleRow& current() const override { return row_; }
  int64_t rowid() const override { return 0; }
};

// ---------------------------------------------------------------------------
// search_asm
// ---------------------------------------------------------------------------

struct SearchAsmRow {
  int64_t addr = 0;
  std::string matched_hex;
};

enum SearchAsmCol { kSAddr = 0, kSHex = 1, kSAsm = 2, kSMaxResults = 3 };

// Parses one `/a <asm>` output line: "<hex addr> <hitname> <hex bytes>"
// (verified live, stable across single- and multi-byte matches, e.g.
// "0x140001131 hit0_0 55" / "0x140001c3e hit0_0 b801000000"). Returns false
// for a line that doesn't match this exact 3-token shape (defensively
// skipped rather than treated as a hard error, since a stray blank line at
// the end of output is expected).
bool parse_hit_line(const std::string& line, SearchAsmRow* row) {
  const size_t sp1 = line.find(' ');
  if (sp1 == std::string::npos) return false;
  const size_t sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string::npos) return false;
  const std::string addr_tok = line.substr(0, sp1);
  const std::string hex_tok = line.substr(sp2 + 1);
  if (addr_tok.empty() || hex_tok.empty()) return false;
  char* endp = nullptr;
  const int64_t addr = std::strtoll(addr_tok.c_str(), &endp, 0);
  if (!endp || *endp != '\0') return false;
  if (!json_utils::valid_hex_bytes(hex_tok)) return false;
  row->addr = addr;
  row->matched_hex = hex_tok;
  return true;
}

std::vector<SearchAsmRow> run_search_asm(Backend* be, const std::string& asm_text,
                                          int64_t max_results) {
  std::vector<SearchAsmRow> out;
  if (asm_text.empty() || !json_utils::valid_asm_source_text(asm_text)) return out;

  auto* api = be->direct();
  const std::string command = "/a " + asm_text;
  const std::string text = api ? api->search(command) : be->cmd("'" + command);

  size_t pos = 0;
  while (pos <= text.size()) {
    size_t nl = text.find('\n', pos);
    const std::string line = table_utils::trim_ascii(
        text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
    SearchAsmRow row;
    if (parse_hit_line(line, &row)) {
      out.push_back(row);
      if (max_results > 0 && static_cast<int64_t>(out.size()) >= max_results) break;
    }
    if (nl == std::string::npos) break;
    pos = nl + 1;
  }
  return out;
}

class SearchAsmGen : public xsql::Generator<SearchAsmRow> {
  std::vector<SearchAsmRow> rows_;
  size_t idx_ = 0;
  SearchAsmRow cur_;
 public:
  explicit SearchAsmGen(std::vector<SearchAsmRow> rows) : rows_(std::move(rows)) {}
  bool next() override {
    if (idx_ >= rows_.size()) return false;
    cur_ = rows_[idx_++];
    return true;
  }
  const SearchAsmRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

}  // namespace

void register_assemble_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<AssembleRow>> {
    std::string asm_text;
    int64_t addr = 0;
    // omit=1: SQLite does not re-check these values, so each is compared the
    // way a native column would (xsql::exact_*): a value nothing can equal
    // (10.5 for an integer, NULL, a blob) yields no rows.
    for (const auto& a : args) {
      if (a.op != xsql::ConstraintOp::Eq) continue;
      switch (a.column_index) {
        case kAAsm: {
          auto v = xsql::exact_text(a.value);
          if (!v) return nullptr;
          asm_text = std::move(*v);
          break;
        }
        case kAAddr: {
          const auto v = xsql::exact_int64(a.value);
          if (!v) return nullptr;
          addr = *v;
          break;
        }
        default: break;
      }
    }
    if (asm_text.empty()) {
      xsql::set_vtab_error("assemble requires WHERE asm = '<mnemonic>'");
      return std::make_unique<AssembleGen>(AssembleRow{});
    }
    return std::make_unique<AssembleGen>(run_assemble(be, asm_text, addr));
  };

  auto def = xsql::generator_table<AssembleRow>("assemble")
    .estimate_rows([]() -> size_t { return 1; })
    .column_text ("hex",   [](const AssembleRow& r) { return r.hex; })
    .column_blob ("bytes", [](const AssembleRow& r) { return r.bytes; })
    .column_int64("size",  [](const AssembleRow& r) { return r.size; })
    .column_text ("error", [](const AssembleRow& r) { return r.error; })
    .hidden_column_text ("asm")
    .hidden_column_int64("addr")
    .full_scan_error(
        "assemble requires WHERE asm = '<mnemonic>' "
        "(hex is an output column, not the input)")
    .constraint_filter(
        {xsql::required_eq("asm", "assemble requires WHERE asm = '<mnemonic>'"),
         xsql::optional_eq("addr")},
        make_gen, 1.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

void register_search_asm_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<SearchAsmRow>> {
    std::string asm_text;
    int64_t max_results = 0;
    // omit=1: SQLite does not re-check these values, so each is compared the
    // way a native column would (xsql::exact_*): a value nothing can equal
    // (10.5 for an integer, NULL, a blob) yields no rows.
    for (const auto& a : args) {
      if (a.op != xsql::ConstraintOp::Eq) continue;
      switch (a.column_index) {
        case kSAsm: {
          auto v = xsql::exact_text(a.value);
          if (!v) return nullptr;
          asm_text = std::move(*v);
          break;
        }
        case kSMaxResults: {
          const auto v = xsql::exact_int64(a.value);
          if (!v) return nullptr;
          max_results = *v;
          break;
        }
        default: break;
      }
    }
    if (asm_text.empty()) {
      xsql::set_vtab_error("search_asm requires WHERE asm = '<mnemonic>'");
      return std::make_unique<SearchAsmGen>(std::vector<SearchAsmRow>{});
    }
    if (!json_utils::valid_asm_source_text(asm_text)) {
      xsql::set_vtab_error(
          "search_asm: asm accepts only disassembly-safe characters "
          "(letters, digits, space, and ,.+-*/[]():%#_$)");
      return std::make_unique<SearchAsmGen>(std::vector<SearchAsmRow>{});
    }
    return std::make_unique<SearchAsmGen>(run_search_asm(be, asm_text, max_results));
  };

  auto def = xsql::generator_table<SearchAsmRow>("search_asm")
    .estimate_rows([]() -> size_t { return 16; })
    .column_int64("addr",        [](const SearchAsmRow& r) { return r.addr; })
    .column_text ("matched_hex", [](const SearchAsmRow& r) { return r.matched_hex; })
    .hidden_column_text ("asm")
    .hidden_column_int64("max_results")
    .full_scan_error(
        "search_asm requires WHERE asm = '<mnemonic>' "
        "(addr is an output column, not the search input)")
    .constraint_filter(
        {xsql::required_eq("asm", "search_asm requires WHERE asm = '<mnemonic>'"),
         xsql::optional_eq("max_results")},
        make_gen, 2.0, 64.0)
    .order_by_consumed("addr")
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
