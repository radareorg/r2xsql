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
//
// All three writes dispatch through Backend::cmd_noeval on the in-process
// (libr) backend — the same structural no-eval idiom piloted on `comments`
// and rolled out to `funcs`/`flags`. INSERT's `f` and DELETE's `f-` are
// address-scoped exactly like those tables' writes, so they use the same
// `dispatch_write(be, addr, command)` shape.
//
// `fr <old> <new>` (the rename) is the same odd one out `flags` already hit:
// it carries no address anywhere in its own grammar at all — radare2
// resolves both flag names purely by name lookup, independent of the current
// seek. This raised the identical question `flags`' rollout raised (and an
// earlier note here once answered wrongly, assuming a new addr-less
// primitive was required): does `fr` need one, or can it still route through
// `cmd_noeval`'s (addr, command) shape? Verified empirically here too, not
// just carried over from `flags` by analogy — a bookmark row always has a
// real address of its own (the same `r.addr` the read path already reports),
// so seeking to it costs nothing (the seek `r_core_call_str_at` performs is
// strictly temporary: seek, dispatch, seek back — see `flags`' file header
// for the source-verified reasoning) and buys the same structural no-eval
// guarantee. No new addr-less primitive was needed for `bookmarks` either.
//
// The flagspace save/select/restore (`fs+bookmarks` / `fs-`) is unrelated to
// this dispatch: it is a constant, non-user-controlled command with nothing
// to inject, so it stays a plain `Backend::cmd()` call exactly as before.

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

// Dispatch a write command scoped to `addr`. Tries the structural no-eval
// path first (libr backend only, via Backend::cmd_noeval); falls back to the
// original command-string form (`command @ addr`) on every backend that
// reports it unsupported, so r2pipe's behavior and command text stay
// byte-for-byte unchanged. Same helper shape as the `flags`/`funcs` tables'
// rollout of this dispatch.
std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}

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
        // `fr` takes no address at all (see the file header for the full
        // reasoning) — dispatch it through cmd_noeval anyway, seeked to this
        // row's own `r.addr`, which the command never consults; a plain
        // Backend::cmd_noeval-unsupported backend (r2pipe, mock) falls back to
        // the exact same bare `fr <old> <new>` string this table has always
        // issued, with no `@ <addr>` ever spliced onto it.
        std::string cmd = "fr " + r.name + " " + v;
        std::string out;
        if (!be->cmd_noeval(r.addr, cmd, &out)) {
          out = be->cmd(cmd);
        }
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
      const std::string out = dispatch_write(be, r.addr, "f-");
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
          dispatch_write(be, addr, std::string("f ") + name);
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
