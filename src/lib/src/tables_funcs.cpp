// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// funcs — function inventory via `aflj`. Each row is one analysed function;
// the JSON is re-issued per query so the view is always live.
//
// Writes (`name` rename via `afn`, `prototype` via `afs`, `calltype` via
// `afc`, DELETE via `af-`, INSERT's `af`/`afn`) are all address-scoped, so on
// the in-process (libr) backend each dispatches through Backend::cmd_noeval —
// radare2's own command handler, seeked to the target address, called
// directly without evaluating its command-chaining grammar (`;`/`@`/`|`/
// backtick) at all. This is an ADDITIONAL layer alongside this table's
// existing grammar/value validation (`valid_flag_name`, `valid_c_signature`,
// the `calling_convention_exists` check on `calltype`) — none replaces the
// others. On every other backend (r2pipe, mock) cmd_noeval reports
// unsupported and the exact same `cmd()` + spliced `@ <addr>` string this
// table always issued runs unchanged. Same shape as the `comments` table's
// pilot of this dispatch.
//
// `name`'s rename is explicitly REFUSED a C-API port, unlike the sibling
// rename/set writes on `comments`/`flags`/`locals` (measured together in a
// private standalone lab). Not a speed question — `afn`'s bulk-rename
// cost clears the same 3x bar the others did. The refusal is PARITY: reading
// `afn`'s actual handler (`__setFunctionName`, `cmd_anal.inc.c`) found it
// does substantially more than `r_anal_function_rename` alone —
//   * it renames (or creates, in the `functions` flagspace) the FLAG that
//     shares the function's address, via `r_flag_rename`/`r_flag_set`;
//   * it renames the function's `func.<name>.args`/`.arg.N`/`.ret` sdb keys
//     (`rename_fcnsig`) — the stored C-signature metadata `prototype`
//     reads back through `afcf`;
//   * it fires the `on_fcn_rename` callback.
// `r_anal_function_rename` touches ONLY the function's own name field and
// hashtable entries — none of the above. The write-path lab proved this
// live, not just from the source read: after an equal-sized bulk rename on
// two independent cores, the CMD leg's flag was renamed on 100% of rows and
// the API leg's flag was renamed on 0% — a real, silent desync between
// `funcs.name` and its own backing flag, the exact bug class already fixed
// once this session for `flags.name` (`afn` creating a duplicate flag
// instead of renaming in place). Porting this write would require
// reimplementing `__setFunctionName` in full, which is not a "call the C
// API instead" port at all — it is copying that problem in reverse. Stays
// on the command path unconditionally.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <cctype>
#include <string_view>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <cstdint>
#include <vector>

namespace r2xsql {

namespace {

using direct::FuncRow;

// Column index of `prototype` in the table below, as a colUsed bit. Unlike the
// other eight fields, the signature is not free: radare2 builds it per function
// from the type database, and it is most of what a full scan costs. Skipping it
// when the query does not read it is worth roughly an order of magnitude.
constexpr uint64_t kColUsedAll     = 1ull << 63;
constexpr uint64_t kPrototypeColBit = 1ull << 8;

void build_funcs(Backend* be, std::vector<FuncRow>& rows, bool with_prototype) {
  if (auto* api = be->direct()) {
    api->funcs_scan(with_prototype, rows);
    return;
  }
  auto arr = be->cmd_json("aflj");
  if (!arr.is_array()) return;
  rows.reserve(arr.size());
  for (auto& j : arr) {
    FuncRow r;
    r.addr     = json_utils::i64_addr(j);
    r.name     = json_utils::str(j, "name");
    r.size     = json_utils::i64(j, "size");
    r.nbbs     = json_utils::i64(j, "nbbs");
    r.edges    = json_utils::i64(j, "edges");
    r.cc       = json_utils::i64(j, "cc");
    r.type     = json_utils::str(j, "type");
    r.calltype = json_utils::str(j, "calltype");
    // One `aflj` carries every field, so on this path the signature is already
    // paid for whether or not the query wants it.
    if (with_prototype) r.prototype = json_utils::str(j, "signature");

    r.end_addr   = json_utils::i64(j, "maxaddr");
    r.ninstrs    = json_utils::i64(j, "ninstrs");
    r.stackframe = json_utils::i64(j, "stackframe");
    r.cost       = json_utils::i64(j, "cost");
    r.tracecov   = json_utils::i64(j, "tracecov");
    r.is_noreturn = json_utils::boolean(j, "noreturn");
    // `is-pure` is the odd one out twice over: the key is hyphenated, and
    // radare2 prints it through r_str_bool, so it arrives as the STRING
    // "true"/"false" rather than a JSON boolean. Reading it as a bool yields
    // false for every function.
    r.is_pure      = json_utils::str(j, "is-pure") == "true";
    r.is_recursive = json_utils::boolean(j, "recursive");
    rows.push_back(std::move(r));
  }
}

std::string compact_signature(std::string_view signature) {
  while (!signature.empty() &&
         (std::isspace(static_cast<unsigned char>(signature.back())) ||
          signature.back() == ';')) {
    signature.remove_suffix(1);
  }
  std::string compact;
  compact.reserve(signature.size());
  for (unsigned char c : signature) {
    if (!std::isspace(c)) compact.push_back(static_cast<char>(c));
  }
  return compact;
}

bool signature_readback_matches(
    Backend* be, int64_t addr, std::string_view expected) {
  if (auto* api = be->direct()) {
    FuncRow row;
    return api->function_details(addr, true, row) &&
        compact_signature(row.prototype) == compact_signature(expected);
  }
  auto info = be->cmd_json("afij @ " + json_utils::hex_addr(addr));
  const nlohmann::json* func = nullptr;
  if (info.is_array() && !info.empty() && info[0].is_object()) {
    func = &info[0];
  } else if (info.is_object()) {
    func = &info;
  }
  return func &&
         compact_signature(json_utils::str(*func, "signature")) ==
             compact_signature(expected);
}

// `calltype` write validation/readback.
//
// `afc <cc>` was checked against radare2's own handler (`cmd_anal.inc.c`'s
// case 'c' / `input[2]==' '` branch), and its own textual output is USELESS
// for detecting failure: the success path (`fcn->callconv = ...`) calls no
// `cons_printf` at all, and the rejection path (`!r_anal_cc_exist`) reports
// through `R_LOG_ERROR`, which writes to r2's log target, never into the
// buffer `r_core_cmd_str` returns. So `afc`'s own output is the empty string
// on BOTH a successful set AND a rejected, made-up convention name — the
// `table_utils::command_error_text` scan every other write in this file
// relies on cannot tell them apart here. That is why this write validates
// the name up front instead of trusting the command's silence, and why the
// post-write readback below is load-bearing rather than a second layer.
//
// Validation source: re-issue the SAME `afclj` command the `calling_conventions`
// table reads (rather than a hardcoded name list), so what this column accepts
// always tracks the live session's (arch,bits) exactly. `afclj` emits a JSON
// OBJECT keyed by convention name (see tables_calling_conventions.cpp).
bool calling_convention_exists(Backend* be, const std::string& cc) {
  if (auto* api = be->direct()) return api->calling_convention_exists(cc);
  auto obj = be->cmd_json("afclj");
  return obj.is_object() && obj.contains(cc);
}

bool calltype_readback_matches(
    Backend* be, int64_t addr, std::string_view expected) {
  if (auto* api = be->direct()) {
    FuncRow row;
    return api->function_details(addr, false, row) && row.calltype == expected;
  }
  auto info = be->cmd_json("afij @ " + json_utils::hex_addr(addr));
  const nlohmann::json* func = nullptr;
  if (info.is_array() && !info.empty() && info[0].is_object()) {
    func = &info[0];
  } else if (info.is_object()) {
    func = &info;
  }
  return func && json_utils::str(*func, "calltype") == expected;
}

// Dispatch a write command scoped to `addr`. Tries the structural no-eval
// path first (libr backend only, via Backend::cmd_noeval); falls back to the
// original command-string form (`command @ addr`) on every backend that
// reports it unsupported, so r2pipe's behavior and command text stay
// byte-for-byte unchanged. Same helper shape as the `comments` table's pilot
// of this dispatch.
std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}
}  // namespace

void register_funcs_table(Session& s) {
  auto def = xsql::cached_table<FuncRow>("funcs")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "afl~?", 1000);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<FuncRow>& rows) {
      build_funcs(be, rows, /*with_prototype=*/true);
    })
    .projection_cache_builder([be = s.backend_ptr()](std::vector<FuncRow>& rows,
                                                     uint64_t colUsed) {
      const bool with_prototype =
          (colUsed & kColUsedAll) || (colUsed & kPrototypeColBit);
      build_funcs(be, rows, with_prototype);
    })
    .column_int64("addr",  [](const FuncRow& r) { return r.addr; })
    // Writable: UPDATE funcs SET name='x' WHERE addr=... renames the function
    // via `afn` (radare2's function-rename). The dummy `fcn.<addr>` names are
    // the common thing to fix during analysis.
    .column_text_rw("name",
      [](const FuncRow& r) { return r.name; },
      [be = s.backend_ptr()](FuncRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_flag_name(v)) {
          xsql::set_vtab_error(
              "funcs: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
          return false;
        }
        std::string out = dispatch_write(be, r.addr, std::string("afn ") + v);
        if (std::string e = table_utils::command_error_text(out); !e.empty()) {
          xsql::set_vtab_error("funcs: rename failed (addr=" +
                               json_utils::hex_addr(r.addr) + "): " + e);
          return false;
        }
        r.name = v;
        return true;
      })
    .column_int64("size",  [](const FuncRow& r) { return r.size; })
    .column_int64("nbbs",  [](const FuncRow& r) { return r.nbbs; })
    .column_int64("edges", [](const FuncRow& r) { return r.edges; })
    .column_int64("cc",    [](const FuncRow& r) { return r.cc; })
    .column_text ("type",  [](const FuncRow& r) { return r.type; })
    // Writable: UPDATE funcs SET calltype='ms' WHERE addr=... sets the calling
    // convention via `afc <cc>` (radare2's set-calling-convention). READ comes
    // from the `calltype` field of `aflj` (free — no per-row command). The
    // name is validated up front against the live `afclj` convention set
    // (see `calling_convention_exists` above) — not merely a second layer
    // here, but the PRIMARY defense, because `afc`'s own output cannot
    // distinguish a successful set from a rejected name (see the comment on
    // `calling_convention_exists`/`calltype_readback_matches`). The write is
    // then readback-verified via `afij`, the same shape as `prototype` below.
    .column_text_rw("calltype",
      [](const FuncRow& r) { return r.calltype; },
      [be = s.backend_ptr()](FuncRow& r, const char* v) -> bool {
        if (!v || !*v) {
          xsql::set_vtab_error(
              "funcs: calltype must be a non-empty calling convention name "
              "(see the calling_conventions table for valid names)");
          return false;
        }
        std::string cc = v;
        if (!calling_convention_exists(be, cc)) {
          xsql::set_vtab_error(
              "funcs: unknown calling convention '" + cc +
              "' (see the calling_conventions table for the names valid on "
              "this session's arch/bits)");
          return false;
        }
        if (cc == r.calltype) return true;  // no-op replay
        std::string out = dispatch_write(be, r.addr, std::string("afc ") + cc);
        if (std::string e = table_utils::command_error_text(out); !e.empty()) {
          xsql::set_vtab_error("funcs: set calltype failed (addr=" +
                               json_utils::hex_addr(r.addr) + "): " + e);
          return false;
        }
        if (!calltype_readback_matches(be, r.addr, cc)) {
          xsql::set_vtab_error("funcs: calltype was not reflected by afij "
                               "(addr=" + json_utils::hex_addr(r.addr) + ")");
          return false;
        }
        r.calltype = cc;
        return true;
      })
    // Writable: UPDATE funcs SET prototype='int f(int a)' WHERE addr=... applies a
    // C function signature via `afs` (radare2 set-signature). READ comes from the
    // `signature` field of `aflj` (free — no per-row command). Empty/NULL is
    // rejected: r2 has no clear-signature primitive and an empty `afs` mangles the
    // function name. A trailing `;` (afs echoes one) is stripped. `afs` does not
    // accept whole-command quoting, so a strict signature grammar rejects every
    // r2 command metacharacter before the command is issued.
    .column_text_rw("prototype",
      [](const FuncRow& r) { return r.prototype; },
      [be = s.backend_ptr()](FuncRow& r, const char* v) -> bool {
        std::string sig = v ? v : "";
        while (!sig.empty() && (sig.back() == ';' || sig.back() == ' ' ||
                                sig.back() == '\t' || sig.back() == '\n' ||
                                sig.back() == '\r'))
          sig.pop_back();
        if (sig.empty()) {
          xsql::set_vtab_error(
              "funcs: prototype must be a non-empty C signature "
              "(r2 has no clear-signature primitive)");
          return false;
        }
        if (!json_utils::valid_c_signature(sig)) {
          xsql::set_vtab_error(
              "funcs: prototype must be a one-line C signature without "
              "r2 command metacharacters");
          return false;
        }
        if (compact_signature(r.prototype) == compact_signature(sig)) {
          return true;  // no-op replay (rename-only update)
        }
        std::string out = dispatch_write(be, r.addr, std::string("afs ") + sig);
        if (std::string e = table_utils::command_error_text(out); !e.empty()) {
          xsql::set_vtab_error("funcs: set prototype failed (addr=" +
                               json_utils::hex_addr(r.addr) + "): " + e);
          return false;
        }
        if (!signature_readback_matches(be, r.addr, sig)) {
          xsql::set_vtab_error("funcs: prototype was not reflected by afij "
                               "(addr=" + json_utils::hex_addr(r.addr) + ")");
          return false;
        }
        r.prototype = sig;
        return true;
      })
    // Appended AFTER `prototype` on purpose: that keeps it at column index 8,
    // which is the bit kPrototypeColBit tests.
    //
    // `end_addr` is radare2's `maxaddr` — past the highest block, which is NOT
    // `addr + size`: a function's blocks can sit below its entry address and
    // its linear size can overshoot its highest block.
    .column_int64("end_addr",   [](const FuncRow& r) { return r.end_addr; })
    .column_int64("ninstrs",    [](const FuncRow& r) { return r.ninstrs; })
    .column_int64("stackframe", [](const FuncRow& r) { return r.stackframe; })
    .column_int64("cost",       [](const FuncRow& r) { return r.cost; })
    .column_int64("tracecov",   [](const FuncRow& r) { return r.tracecov; })
    // Booleans are 0/1 integers named is_<predicate>, per the family convention.
    .column_int64("is_noreturn",  [](const FuncRow& r) -> int64_t { return r.is_noreturn ? 1 : 0; })
    .column_int64("is_pure",      [](const FuncRow& r) -> int64_t { return r.is_pure ? 1 : 0; })
    .column_int64("is_recursive", [](const FuncRow& r) -> int64_t { return r.is_recursive ? 1 : 0; })
    .deletable([be = s.backend_ptr()](FuncRow& r) -> bool {
      // Remove the function definition at this address (analysis only).
      // `af-` takes the address as a plain trailing argument, not via `@`
      // (unlike afn/afs/af above), so this can't reuse `dispatch_write`'s
      // generic "command @ addr" fallback shape unchanged; the no-eval leg is
      // the same (addr passed structurally, never spliced into `command`).
      std::string out;
      if (!be->cmd_noeval(r.addr, "af-", &out)) {
        out = be->cmd("af- " + json_utils::hex_addr(r.addr));
      }
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("funcs: DELETE failed (addr=" +
                             json_utils::hex_addr(r.addr) + "): " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns: addr(0), name(1), size(2), nbbs(3), edges(4), cc(5),
      // type(6), calltype(7), prototype(8). Defines a function at addr (`af`),
      // optionally naming it (`afn`); prototype is set separately via UPDATE (`afs`).
      if (argc < 1 || argv[0].is_null()) {
        xsql::set_vtab_error("funcs: INSERT requires addr");
        return false;
      }
      const int64_t addr = argv[0].as_int64();
      const std::string at = json_utils::hex_addr(addr);
      if (std::string e = table_utils::command_error_text(dispatch_write(be, addr, "af")); !e.empty()) {
        xsql::set_vtab_error("funcs: INSERT failed to define a function at " + at + ": " + e);
        return false;
      }
      // Optional best-effort naming; a failed afn does not undo the af above.
      if (argc > 1 && !argv[1].is_null()) {
        const char* name = argv[1].as_c_str();
        if (name && *name && json_utils::valid_flag_name(name)) {
          (void)dispatch_write(be, addr, std::string("afn ") + name);
        }
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
