// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// byte_search — canonical cross-tool byte-pattern search, conforming to
// the idasql reference shape. Visible: addr, matched_hex, matched_bytes(BLOB), size.
// Hidden inputs: pattern (REQUIRED), start_addr, end_addr, max_results. Backed by
// r2's `/xj <hex>` (returns [{addr, data(hex)}]); bounds + max_results are applied
// client-side so no global r2 search config is mutated.

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {
struct ByteSearchRow {
  int64_t addr = 0;
  std::vector<uint8_t> matched_bytes;
  std::string matched_hex;
};

// Column indices — keep in sync with define below. Visible first, hidden after.
enum Col { kAddr = 0, kMatchedHex = 1, kMatchedBytes = 2, kSize = 3,
           kPattern = 4, kStart = 5, kEnd = 6, kMaxResults = 7 };

struct ParsedPattern {
  std::string command_token;
  size_t byte_count = 0;
  std::string error;
};

ParsedPattern parse_pattern(const std::string& pattern) {
  ParsedPattern parsed;
  // Strip whitespace so "48 89" and "4889" both reach r2's `/x` (which wants
  // a contiguous hex/mask token). Shared with patches' hex validation.
  parsed.command_token = json_utils::compact_hex(pattern);
  if (parsed.command_token.empty()) {
    parsed.error = "byte_search: pattern must not be empty";
    return parsed;
  }

  const size_t colon = parsed.command_token.find(':');
  if (colon != std::string::npos &&
      parsed.command_token.find(':', colon + 1) != std::string::npos) {
    parsed.error = "byte_search: pattern may contain at most one mask separator";
    return parsed;
  }
  const std::string hex = parsed.command_token.substr(0, colon);
  const std::string mask =
      colon == std::string::npos ? std::string{} :
                                   parsed.command_token.substr(colon + 1);
  if (hex.empty() || (hex.size() % 2) != 0) {
    parsed.error =
        "byte_search: hex pattern must contain a non-empty even number of nibbles";
    return parsed;
  }
  for (char c : hex) {
    if (!json_utils::is_hex_digit(c) && c != '.') {
      parsed.error =
          "byte_search: pattern accepts only hex digits, '.' wildcards, and an optional mask";
      return parsed;
    }
  }
  if (colon != std::string::npos) {
    if (mask.size() != hex.size()) {
      parsed.error =
          "byte_search: mask must contain exactly one nibble per pattern nibble";
      return parsed;
    }
    for (char c : mask) {
      if (!json_utils::is_hex_digit(c)) {
        parsed.error = "byte_search: mask accepts only hex digits";
        return parsed;
      }
    }
  }
  parsed.byte_count = hex.size() / 2;
  return parsed;
}

// Space-separated lowercase 2-digit hex, matching idasql/bnsql matched_hex.
std::string spaced_hex(const std::vector<uint8_t>& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < b.size(); ++i) {
    if (i) s += ' ';
    s += d[b[i] >> 4];
    s += d[b[i] & 0xf];
  }
  return s;
}

// Exact-match hex decode (must produce exactly `expected` bytes), delegating
// to the shared strict decoder (json_utils::hex_decode) so byte_search and
// the patches table's INSERT validation can never drift apart on what
// counts as valid hex.
bool hex_to_bytes_exact(const std::string& h, size_t expected,
                        std::vector<uint8_t>& out) {
  if (!json_utils::hex_decode(h, out)) return false;
  if (out.size() != expected) { out.clear(); return false; }
  return true;
}

std::vector<uint8_t> full_match_bytes(
    Backend* be, const nlohmann::json& hit, int64_t addr, size_t expected) {
  std::vector<uint8_t> bytes;
  if (hex_to_bytes_exact(
          json_utils::compact_hex(json_utils::str(hit, "data")), expected, bytes))
    return bytes;

  // radare2 truncates `/xj`'s `data` field for long matches, so the complete
  // match has to be read back from the hit address for `size`, the BLOB and the
  // text to stay truthful. That re-read is per HIT, which is what makes this
  // the N+1 in this table.
  //
  // In-process, read it straight from radare2's IO layer: same bytes, but no
  // command, no hex rendering, and no hex parsing. The SEARCH itself stays with
  // radare2 either way — reimplementing it would mean redoing section
  // iteration, overlap de-duplication and chunk-boundary handling, and getting
  // hit ORDER right (the caller truncates at `max_results`, so a different
  // order is a different answer). Only the byte fetch moves.
  if (auto* api = be->direct()) {
    if (api->read_bytes(addr, expected, bytes) && bytes.size() == expected) {
      return bytes;
    }
    bytes.clear();
    return bytes;
  }

  const std::string raw =
      be->cmd("p8 " + std::to_string(expected) + " @ " +
              json_utils::hex_addr(addr));
  if (!hex_to_bytes_exact(json_utils::compact_hex(raw), expected, bytes)) bytes.clear();
  return bytes;
}

// Precompute every match once (pattern-search result sets are small; LIMIT still
// short-circuits via next()). Bounds/max_results applied here, client-side.
class ByteSearchGen : public xsql::Generator<ByteSearchRow> {
  std::vector<ByteSearchRow> rows_;
  size_t idx_ = 0;
  ByteSearchRow cur_;
 public:
  ByteSearchGen(Backend* be, const std::string& command_token,
                size_t pattern_size,
                int64_t start, int64_t end, int64_t max_results) {
    if (command_token.empty() || pattern_size == 0) return;
    auto hits = be->cmd_json("/xj " + command_token);
    if (!hits.is_array()) return;
    for (auto& h : hits) {
      const int64_t addr = json_utils::i64(h, "addr");
      if (start >= 0 && addr < start) continue;
      if (end >= 0 && addr >= end) continue;
      ByteSearchRow r;
      r.addr = addr;
      r.matched_bytes = full_match_bytes(be, h, addr, pattern_size);
      if (r.matched_bytes.size() != pattern_size) continue;
      r.matched_hex = spaced_hex(r.matched_bytes);
      rows_.push_back(std::move(r));
      if (max_results > 0 && static_cast<int64_t>(rows_.size()) >= max_results) break;
    }
  }
  bool next() override {
    if (idx_ >= rows_.size()) return false;
    cur_ = rows_[idx_++];
    return true;
  }
  const ByteSearchRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};
}  // namespace

void register_byte_search_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<ByteSearchRow>> {
    std::string pattern;
    int64_t start = -1, end = -1, max_results = 0;
    for (const auto& a : args) {
      if (a.op != xsql::ConstraintOp::Eq) {
        // addr range predicates (Ge/Gt lower, Lt/Le upper) tighten bounds.
        if (a.column_index == kAddr) {
          const int64_t v = a.value.as_int64();
          if (a.op == xsql::ConstraintOp::Ge) start = (start < 0) ? v : (v > start ? v : start);
          else if (a.op == xsql::ConstraintOp::Gt) {
            if (v == std::numeric_limits<int64_t>::max()) {
              start = v;
              end = v;
            } else {
              int64_t w = v + 1;
              start = (start < 0) ? w : (w > start ? w : start);
            }
          }
          else if (a.op == xsql::ConstraintOp::Lt) end = (end < 0) ? v : (v < end ? v : end);
          else if (a.op == xsql::ConstraintOp::Le &&
                   v != std::numeric_limits<int64_t>::max()) {
            int64_t w = v + 1;
            end = (end < 0) ? w : (w < end ? w : end);
          }
        }
        continue;
      }
      switch (a.column_index) {
        case kPattern: { const char* p = a.value.as_c_str(); if (p) pattern = p; break; }
        case kStart: start = a.value.as_int64(); break;
        case kEnd: end = a.value.as_int64(); break;
        case kMaxResults: max_results = a.value.as_int64(); break;
        default: break;
      }
    }
    ParsedPattern parsed = parse_pattern(pattern);
    if (!parsed.error.empty()) {
      xsql::set_vtab_error(parsed.error);
      return std::make_unique<ByteSearchGen>(
          be, std::string{}, 0, 0, 0, 0);
    }
    return std::make_unique<ByteSearchGen>(
        be, parsed.command_token, parsed.byte_count, start, end, max_results);
  };

  auto def = xsql::generator_table<ByteSearchRow>("byte_search")
    .estimate_rows([]() -> size_t { return 64; })
    .column_int64("addr", [](const ByteSearchRow& r) { return r.addr; })
    .column_text("matched_hex", [](const ByteSearchRow& r) { return r.matched_hex; })
    .column_blob("matched_bytes",
                 [](const ByteSearchRow& r) { return r.matched_bytes; })
    .column_int("size",
                [](const ByteSearchRow& r) { return static_cast<int>(r.matched_bytes.size()); })
    .hidden_column_text("pattern")
    .hidden_column_int64("start_addr")
    .hidden_column_int64("end_addr")
    .hidden_column_int("max_results")
    .full_scan_error(
        "byte_search requires WHERE pattern = '<r2 hex pattern>' "
        "(matched_hex is an output column, not the search input)")
    .constraint_filter(
        {xsql::required_eq("pattern",
             "byte_search requires WHERE pattern = '<r2 hex pattern>'"),
         xsql::optional_eq("start_addr"),
         xsql::optional_eq("end_addr"),
         xsql::optional_eq("max_results"),
         xsql::optional_ge("addr"), xsql::optional_gt("addr"),
         xsql::optional_lt("addr"), xsql::optional_le("addr")},
        make_gen, 1.0, 64.0)
    .order_by_consumed("addr")
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
