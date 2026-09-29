// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// read_cstr -- one-row-per-query, ARBITRARY-address null-terminated string
// read via radare2's `pszj` (`cmd_print.inc.c`'s `case 'z':` under the `ps`
// family). This is a genuine gap in the existing string surface:
// `strings`/`string_at` (a `strings` point-lookup recipe) only
// expose rows keyed on a detected string's START address (from `izj`'s
// heuristics), so a caller-chosen address that falls MID-STRING, inside a
// function body, or anywhere else `izj` never flagged has no existing SQL
// surface at all.
//
// Verified live against the CURRENT radare2 source and a real 64-bit PE
// binary, not assumed:
//   - `psz <len>` reads exactly `len` bytes at the current seek and reports
//     the string up to the first NUL found within that window
//     (`decode_text(core, core->addr, len, /*zeroend=*/true)` then
//     `r_str_nlen`). `pszj` is its JSON form (`print_json_string`), giving
//     `string`/`offset`/`section`/`length`/`type` -- exactly this table's
//     shape.
//   - `max_len` is NOT optional in practice: `pszj` with an explicit `0`
//     prints NOTHING at all (`cmd_print.inc.c`'s whole "psz" body is gated
//     `else if (l > 0)`) -- confirmed live -- so a caller-supplied 0 is
//     refused up front rather than silently producing an empty/garbage row.
//     A caller that omits `max_len` gets `kDefaultMaxLen` (128, the same
//     one-shot-string-read default radare2's own `pso`/`print_analstr`
//     already uses in this same command family) rather than whatever
//     `core->blocksize` happens to be configured to -- session-mutable
//     ambient config is not a good implicit input for a table whose whole
//     point is a deterministic point read.
//   - `length == max_len` (no NUL found inside the scanned window) is the
//     only "did this actually find a terminator" signal radare2's own JSON
//     provides -- surfaced as `truncated`, computed client-side from the
//     two values already in the payload, not a new radare2 capability.
//   - An address with nothing meaningful there does NOT come back as an
//     obviously-empty/error shape distinguishable from a real result:
//     confirmed live at address 0 on a 64-bit PE that an out-of-range/
//     unmapped read still returns a FULL `max_len`-byte string (radare2's
//     own unmapped-fill byte on this IO backend, 0xff) with
//     `section:"unknown"`, `type:"unknown"`, `truncated=1` -- the same
//     three-field combination a genuinely long, un-terminated run of
//     printable bytes would also produce. This table does not invent an
//     `is_mapped` check to disambiguate (the same "don't guess" posture
//     already applied to the `syscalls`-resolution refusal) -- `section`/`type`/`truncated`
//     already carry every signal radare2 itself exposes; a caller wanting a
//     stronger mapped/unmapped guarantee should cross-check `bytes`.
//   - Mid-string read confirmed live: the real detected string at
//     0x140018cb0 ("press any key to exit...\n", 25 chars, `strings.length`
//     25) has NO `strings` row at addr+6, but `read_cstr` at that address
//     returns "any key to exit...\n" (19 chars) -- the exact capability
//     `strings`/the `string_at` recipe cannot reach.
//
// Command-path-only, no C-API producer: a single read has no N-per-row cost
// to collapse, same "one full-scan-equivalent command" reasoning
// `bininfo`/`demangle`/`assemble` already documented for themselves, so both
// backends share the identical command-based implementation and cannot
// disagree.
//
// `max_len` is a plain validated positive integer -- no free-text argument
// exists on this table's surface at all, so there is no charset-allowlist
// injection surface to defend (unlike `assemble`/`search_asm`'s `asm` or
// `demangle`'s `mangled`). `Backend::cmd_noeval` is still wired in for
// defense-in-depth and consistency with every other address-scoped read/
// write in this project, not because a real gap was found here -- the same
// "wired in anyway" posture already recorded for `patches`' INSERT and
// `bytes`' UPDATE.

#include <cstdint>
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

// Matches radare2's own `pso`/`print_analstr` one-shot-string default read
// window (`cmd_print.inc.c`) -- reused here rather than inventing a new
// number, and deliberately NOT `core->blocksize` (session-mutable ambient
// config with no fixed value this table could document).
constexpr int64_t kDefaultMaxLen = 128;

struct ReadCstrRow {
  std::string content;    // may legitimately be empty (a real empty string)
  int64_t length = 0;
  std::string section;
  std::string type;
  bool truncated = false;
  std::string error;      // non-empty iff this row carries no usable result
};

enum Col { kContent = 0, kLength = 1, kSection = 2, kType = 3,
           kTruncated = 4, kError = 5, kAddr = 6, kMaxLen = 7 };

// Seeked no-eval dispatch for `pszj <max_len>`, mirroring
// table_utils::assemble_hex's exact shape (try cmd_noeval first, fall back
// to the plain `@ <addr>`-suffixed command on every backend that reports it
// unsupported) -- kept local since this table is the only user.
std::string dispatch_read_cstr(Backend* be, int64_t addr, int64_t max_len) {
  const std::string command = "pszj " + std::to_string(max_len);
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}

ReadCstrRow run_read_cstr(Backend* be, int64_t addr, int64_t max_len) {
  ReadCstrRow row;
  if (max_len <= 0) {
    row.error = "read_cstr: max_len must be a positive integer (pszj with "
                "max_len=0 produces no output at all -- verified live "
                "against the current radare2 source)";
    return row;
  }
  const std::string out = dispatch_read_cstr(be, addr, max_len);
  nlohmann::json j = nlohmann::json::parse(out, nullptr, false);
  if (j.is_discarded() || !j.is_object()) {
    row.error = "read_cstr: radare2 returned no result (pszj produced no "
                "parseable output)";
    return row;
  }
  row.content = json_utils::str(j, "string");
  row.length = json_utils::i64(j, "length");
  row.section = json_utils::str(j, "section");
  row.type = json_utils::str(j, "type");
  // No NUL found inside the scanned window -- the string may continue past
  // max_len, OR this address was never mapped/meaningful in the first place
  // (see the file header's "don't guess" note). Honest signal, not a claim.
  row.truncated = row.length >= max_len;
  return row;
}

class ReadCstrGen : public xsql::Generator<ReadCstrRow> {
  ReadCstrRow row_;
  bool served_ = false;
 public:
  explicit ReadCstrGen(ReadCstrRow row) : row_(std::move(row)) {}
  bool next() override {
    if (served_) return false;
    served_ = true;
    return true;
  }
  const ReadCstrRow& current() const override { return row_; }
  int64_t rowid() const override { return 0; }
};

}  // namespace

void register_read_cstr_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<ReadCstrRow>> {
    bool have_addr = false;
    int64_t addr = 0;
    int64_t max_len = kDefaultMaxLen;
    // omit=1: SQLite does not re-check these values, so each is compared the
    // way a native column would (xsql::exact_*): a value nothing can equal
    // (10.5 for an integer, NULL, a blob) yields no rows.
    for (const auto& a : args) {
      if (a.op != xsql::ConstraintOp::Eq) continue;
      switch (a.column_index) {
        case kAddr: {
          const auto v = xsql::exact_int64(a.value);
          if (!v) return nullptr;
          addr = *v;
          have_addr = true;
          break;
        }
        case kMaxLen: {
          const auto v = xsql::exact_int64(a.value);
          if (!v) return nullptr;
          max_len = *v;
          break;
        }
        default: break;
      }
    }
    if (!have_addr) {
      xsql::set_vtab_error("read_cstr requires WHERE addr = <address>");
      return std::make_unique<ReadCstrGen>(ReadCstrRow{});
    }
    return std::make_unique<ReadCstrGen>(run_read_cstr(be, addr, max_len));
  };

  auto def = xsql::generator_table<ReadCstrRow>("read_cstr")
    .estimate_rows([]() -> size_t { return 1; })
    .column_text ("content",   [](const ReadCstrRow& r) { return r.content; })
    .column_int64("length",    [](const ReadCstrRow& r) { return r.length; })
    .column_text ("section",   [](const ReadCstrRow& r) { return r.section; })
    .column_text ("type",      [](const ReadCstrRow& r) { return r.type; })
    .column_int64("truncated", [](const ReadCstrRow& r) -> int64_t { return r.truncated ? 1 : 0; })
    .column_text ("error",     [](const ReadCstrRow& r) { return r.error; })
    .hidden_column_int64("addr")
    .hidden_column_int64("max_len")
    .full_scan_error(
        "read_cstr requires WHERE addr = <address> "
        "(content is an output column, not the input)")
    .constraint_filter(
        {xsql::required_eq("addr", "read_cstr requires WHERE addr = <address>"),
         xsql::optional_eq("max_len")},
        make_gen, 1.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
