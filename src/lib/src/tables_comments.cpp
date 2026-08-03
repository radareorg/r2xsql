// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// comments — `CCj` for read; `CCu <text> @ <addr>` for UPDATE; `CC- @ <addr>`
// for DELETE. Writes go through Backend so any backend (libr/r2pipe) works.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct CommentRow {
  int64_t     addr = 0;
  std::string type;
  std::string text;
};
}  // namespace

void register_comments_table(Session& s) {
  auto def = xsql::cached_table<CommentRow>("comments")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1024; })
    .cache_builder([be = s.backend_ptr()](std::vector<CommentRow>& rows) {
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
        // CCu takes the comment verbatim; pass it as base64 so spaces, quotes,
        // and `@` can't corrupt the comment or inject extra r2 commands.
        std::string cmd = "CCu base64:" + json_utils::base64_encode(v ? v : "") +
                          " @ " + json_utils::hex_addr(r.addr);
        if (std::string e = table_utils::command_error_text(be->cmd(cmd)); !e.empty()) {
          xsql::set_vtab_error("comments: UPDATE failed: " + e);
          return false;
        }
        if (v) r.text = v;
        return true;
      })
    .deletable([be = s.backend_ptr()](CommentRow& r) -> bool {
      std::string cmd = "CC- @ " + json_utils::hex_addr(r.addr);
      if (std::string e = table_utils::command_error_text(be->cmd(cmd)); !e.empty()) {
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
      std::string cmd = "CCu base64:" + json_utils::base64_encode(text ? text : "") +
                        " @ " + json_utils::hex_addr(addr);
      if (std::string e = table_utils::command_error_text(be->cmd(cmd)); !e.empty()) {
        xsql::set_vtab_error("comments: INSERT failed: " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql


