// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// funcs — function inventory via `aflj`. Each row is one analysed function;
// the JSON is re-issued per query so the view is always live.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <cctype>
#include <string_view>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct FuncRow {
  int64_t     addr = 0;
  std::string name;
  int64_t     size = 0;
  int64_t     nbbs = 0;
  int64_t     edges = 0;
  int64_t     cc = 0;
  std::string type;
  std::string calltype;
  std::string prototype;
};

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
}  // namespace

void register_funcs_table(Session& s) {
  auto def = xsql::cached_table<FuncRow>("funcs")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "afl~?", 1000);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<FuncRow>& rows) {
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
        r.prototype = json_utils::str(j, "signature");
        rows.push_back(std::move(r));
      }
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
        std::string out = be->cmd(std::string("afn ") + v + " @ " + json_utils::hex_addr(r.addr));
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
    .column_text ("calltype", [](const FuncRow& r) { return r.calltype; })
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
        const std::string command =
            std::string("afs ") + sig + " @ " + json_utils::hex_addr(r.addr);
        std::string out = be->cmd(command);
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
    .deletable([be = s.backend_ptr()](FuncRow& r) -> bool {
      // Remove the function definition at this address (analysis only).
      std::string out = be->cmd("af- " + json_utils::hex_addr(r.addr));
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
      if (std::string e = table_utils::command_error_text(be->cmd("af @ " + at)); !e.empty()) {
        xsql::set_vtab_error("funcs: INSERT failed to define a function at " + at + ": " + e);
        return false;
      }
      // Optional best-effort naming; a failed afn does not undo the af above.
      if (argc > 1 && !argv[1].is_null()) {
        const char* name = argv[1].as_c_str();
        if (name && *name && json_utils::valid_flag_name(name)) {
          (void)be->cmd(std::string("afn ") + name + " @ " + at);
        }
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
