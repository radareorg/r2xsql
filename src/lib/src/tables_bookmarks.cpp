// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// bookmarks — backed by the `bookmarks` flag space. Each row is one flag
// inside that space. Writable: UPDATE name → `fr`; DELETE → `f- @ addr`;
// INSERT (addr, name) → `f <name> @ <addr>`. Every write is scoped to the
// `bookmarks` flagspace (save/select/restore), mirroring the read path, so
// it never touches flags in other spaces.

#include <vector>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct BookmarkRow {
  int64_t     id = 0;
  int64_t     addr = 0;
  std::string name;
};

class BookmarkSpaceScope {
public:
  explicit BookmarkSpaceScope(Backend& backend) : backend_(backend) {
    (void)backend_.cmd("fs+bookmarks");
  }

  ~BookmarkSpaceScope() {
    (void)backend_.cmd("fs-");
  }

  BookmarkSpaceScope(const BookmarkSpaceScope&) = delete;
  BookmarkSpaceScope& operator=(const BookmarkSpaceScope&) = delete;

private:
  Backend& backend_;
};

bool has_bookmark(const nlohmann::json& arr, int64_t addr,
                  std::string_view name) {
  if (!arr.is_array()) return false;
  for (const auto& item : arr) {
    if (json_utils::i64_addr(item) == addr &&
        json_utils::str(item, "name") == name) {
      return true;
    }
  }
  return false;
}
}  // namespace

void register_bookmarks_table(Session& s) {
  auto def = xsql::cached_table<BookmarkRow>("bookmarks")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 128; })
    .cache_builder([be = s.backend_ptr()](std::vector<BookmarkRow>& rows) {
      BookmarkSpaceScope scope(*be);
      auto arr = be->cmd_json("fj");
      if (!arr.is_array()) return;
      int64_t id = 0;
      for (auto& j : arr) {
        BookmarkRow r;
        r.id   = ++id;
        r.addr = json_utils::i64_addr(j);
        r.name = json_utils::str(j, "name");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("id",   [](const BookmarkRow& r) { return r.id; })
    .column_int64("addr", [](const BookmarkRow& r) { return r.addr; })
    .column_text_rw("name",
      [](const BookmarkRow& r) { return r.name; },
      [be = s.backend_ptr()](BookmarkRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_flag_name(v)) {
          xsql::set_vtab_error(
              "bookmarks: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
          return false;
        }
        if (r.name == v) return true;
        BookmarkSpaceScope scope(*be);
        const std::string out = be->cmd("fr " + r.name + " " + v);
        if (std::string e = table_utils::command_error_text(out); !e.empty()) {
          xsql::set_vtab_error("bookmarks: rename failed: " + e);
          return false;
        }
        if (!has_bookmark(
                be->cmd_json("fj @ " + json_utils::hex_addr(r.addr)),
                r.addr, v)) {
          xsql::set_vtab_error("bookmarks: rename was not applied");
          return false;
        }
        r.name = v;
        return true;
      })
    .deletable([be = s.backend_ptr()](BookmarkRow& r) -> bool {
      BookmarkSpaceScope scope(*be);
      const std::string out =
          be->cmd("f- @ " + json_utils::hex_addr(r.addr));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("bookmarks: delete failed: " + e);
        return false;
      }
      if (has_bookmark(
              be->cmd_json("fj @ " + json_utils::hex_addr(r.addr)),
              r.addr, r.name)) {
        xsql::set_vtab_error("bookmarks: delete was not applied");
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: id(0), addr(1), name(2).
      if (argc < 3 || argv[1].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("bookmarks: INSERT requires addr and name");
        return false;
      }
      const int64_t addr = argv[1].as_int64();
      const char* name = argv[2].as_c_str();
      if (!name || !*name) {
        xsql::set_vtab_error("bookmarks: INSERT requires a non-empty name");
        return false;
      }
      if (!json_utils::valid_flag_name(name)) {
        xsql::set_vtab_error(
            "bookmarks: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
        return false;
      }
      BookmarkSpaceScope scope(*be);
      const std::string out =
          be->cmd(std::string("f ") + name + " @ " +
                  json_utils::hex_addr(addr));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("bookmarks: insert failed: " + e);
        return false;
      }
      if (!has_bookmark(be->cmd_json(
                            "fj @ " + json_utils::hex_addr(addr)),
                        addr, name)) {
        xsql::set_vtab_error("bookmarks: insert was not applied");
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
