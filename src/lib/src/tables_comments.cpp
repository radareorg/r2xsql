// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// comments — `CCj` for read; `CCu <text> @ <addr>` for UPDATE; `CC- @ <addr>`
// for DELETE. Writes go through Backend so any backend (libr/r2pipe) works.
//
// Pilot table for the structural no-eval write dispatch (Backend::cmd_noeval):
// every write here is already address-scoped (`@ <addr>`), which maps
// directly onto that primitive's (addr, command) shape. On the libr backend,
// each write below dispatches straight to its command handler instead of
// through radare2's separator-evaluating command grammar; on every other
// backend (r2pipe, mock) cmd_noeval reports "unsupported" and the exact same
// `cmd()` + spliced `@ <addr>` string this table always used runs unchanged.
// The existing input handling (base64-encoding the comment text) is kept
// as-is — this is an additional, structural layer, not a replacement for it.
//
// The READ path is a separate, later change: `CCj` is already a single
// full-scan command (not an N+1-per-function shape), and reading radare2's
// meta interval tree directly instead measures 5-70x with exact field
// parity — including two quirks of `CCj`'s own emitter that this table's
// command path already exhibited before this port touched anything: `type`
// is the literal string "CCu" (not "comment"), and `text` is
// `r_str_escape`d, not raw, for any comment containing a newline/tab/quote/
// backslash/non-ASCII byte. See `direct.hpp`'s `CommentRow`/`Api::comments_scan`
// for the full citation. This is unrelated to, and does not modify, the
// cmd_noeval write path above.
//
// The WRITE path (this table's `text` UPDATE and INSERT) is ALSO now
// C-API-backed on the libr flavor, a separate, later port from both of the
// above: a private standalone lab measured a bulk workload (N=500 repeated
// sets, simulating a bulk-annotate script) at 30-40x over the CMD leg
// (`r_core_call_str_at("CCu base64:...")`, the SAME dispatch this table
// already issues), with exact field/behavior parity once the API leg
// reproduces `CCu`'s own dedup-skip quirk (see `Api::comment_set` in
// `direct.hpp`). Proven live, not just cited: a substring-of-existing-text
// UPDATE is a silent no-op on both legs; a genuine overwrite lands on both.
// On every non-libr backend (r2pipe, mock), `Backend::direct()` returns
// nullptr and the exact `cmd_noeval`/`cmd()` fallback above runs unchanged.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::CommentRow;

// The command-path full-scan producer — unchanged from before this port,
// moved into a named function (was an inline lambda) so the cache_builder
// below can branch to the C-API producer first, exactly the pattern
// `tables_flags.cpp`'s `build_flags` established.
void build_comments(Backend* be, std::vector<CommentRow>& rows) {
  auto arr = be->cmd_json("CCj");
  if (!arr.is_array()) return;
  rows.reserve(arr.size());
  for (auto& j : arr) {
    CommentRow r;
    r.addr = json_utils::i64_addr(j);
    r.type = json_utils::str(j, "type", "comment");
    r.text = json_utils::str(j, "name");
    rows.push_back(std::move(r));
  }
}

// Dispatch a write command scoped to `addr`. Tries the structural no-eval
// path first (libr backend only); falls back to the original command-string
// form (`command @ addr`) on every backend that reports it unsupported, so
// r2pipe's behavior and command text are byte-for-byte unchanged.
std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}
}  // namespace

void register_comments_table(Session& s) {
  auto def = xsql::cached_table<CommentRow>("comments")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1024; })
    .cache_builder([be = s.backend_ptr()](std::vector<CommentRow>& rows) {
      if (auto* api = be->direct()) {
        api->comments_scan(rows);
        return;
      }
      build_comments(be, rows);
    })
    .row_populator([](CommentRow& r, int argc, xsql::FunctionArg* argv) {
      if (argc > 2 && !argv[2].is_null()) r.addr = argv[2].as_int64();
      if (argc > 3 && !argv[3].is_null()) {
        const char* type = argv[3].as_c_str();
        r.type = type ? type : "";
      }
      if (argc > 4 && !argv[4].is_null()) {
        const char* text = argv[4].as_c_str();
        r.text = text ? text : "";
      }
    })
    .column_int64("addr", [](const CommentRow& r) { return r.addr; })
    .column_text ("type", [](const CommentRow& r) { return r.type; })
    .column_text_rw("text",
      [](const CommentRow& r) { return r.text; },
      [be = s.backend_ptr()](CommentRow& r, const char* v) -> bool {
        const std::string text = v ? v : "";
        if (auto* api = be->direct()) {
          if (!api->comment_set(r.addr, text)) {
            xsql::set_vtab_error("comments: UPDATE failed (addr=" +
                                 json_utils::hex_addr(r.addr) + ")");
            return false;
          }
          if (v) r.text = v;
          return true;
        }
        // Fallback (r2pipe, mock): CCu takes the comment verbatim; pass it as
        // base64 so spaces, quotes, and `@` can't corrupt the comment or
        // inject extra r2 commands. Kept even with the structural dispatch
        // below: defense-in-depth, not either/or.
        std::string cmd = "CCu base64:" + json_utils::base64_encode(text);
        if (std::string e = table_utils::command_error_text(dispatch_write(be, r.addr, cmd));
            !e.empty()) {
          xsql::set_vtab_error("comments: UPDATE failed: " + e);
          return false;
        }
        if (v) r.text = v;
        return true;
      })
    .deletable([be = s.backend_ptr()](CommentRow& r) -> bool {
      if (std::string e = table_utils::command_error_text(dispatch_write(be, r.addr, "CC-"));
          !e.empty()) {
        xsql::set_vtab_error("comments: DELETE failed: " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: addr(0), type(1), text(2).
      if (argc < 3 || argv[0].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("comments: INSERT requires addr and text");
        return false;
      }
      const int64_t addr = argv[0].as_int64();
      const char* text = argv[2].as_c_str();
      const std::string body = text ? text : "";
      if (auto* api = be->direct()) {
        if (!api->comment_set(addr, body)) {
          xsql::set_vtab_error("comments: INSERT failed (addr=" +
                               json_utils::hex_addr(addr) + ")");
          return false;
        }
        return true;
      }
      std::string cmd = "CCu base64:" + json_utils::base64_encode(body);
      if (std::string e = table_utils::command_error_text(dispatch_write(be, addr, cmd));
          !e.empty()) {
        xsql::set_vtab_error("comments: INSERT failed: " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql


