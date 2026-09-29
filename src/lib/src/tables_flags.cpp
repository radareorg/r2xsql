// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// flags — `fj` for read; `fr <old> <new>` for renames; `f- @ <addr>` for deletes.
//
// `space` is radare2's real flagspace, read from radare2. It used to be guessed
// from the name prefix (everything before the first `.`), which was wrong in
// three separate ways on a stock PE: it invented a vocabulary radare2 does not
// use (`sym` where radare2 says `imports`, `str` where it says `strings`), it
// SPLIT one real space across two guessed ones (`fcn` + `sub` are both
// `functions`), and it left every dot-less flag with no space at all. Nothing
// downstream could tell, because the guess always produced a plausible string.
//
// radare2 will report the truth, but not in one command: `fj` never emits a
// flag's space (see `print_flag_json` in libr/flag/flag.c — it emits
// name/realname/size/comment/alias/addr and nothing else). So the space has to
// be established by enumerating flagspaces and listing each one.
//
// A full scan is that same enumeration: one `fj` (full dump) + one
// `fs <name>; fj; fs *` PER FLAGSPACE to attribute the real space back onto
// each flag by name. On the libr backend this reads `r_flag_foreach` directly
// instead — measured at 17-47x on a full scan across a real
// binary, this project's own scale fixtures, and a real large DLL, with exact
// field parity (including a pointer-equality quirk in radare2's own
// `realname` field), before being ported (see `direct.hpp` for why the second
// producer lives in another TU). `r_flag_foreach` needs no `fs` selection or
// session-state save/restore at all — it is not scoped by the
// currently-selected flagspace the way the `fj` COMMAND is — so the port also
// deletes the enumeration loop's own atomic-select/list/restore workaround
// entirely on the ported leg. The command path remains the only
// implementation r2pipe can have.
//
// Writes (INSERT's `f`, DELETE's `f-`, and the rename's `fr`) dispatch through
// Backend::cmd_noeval on the in-process (libr) backend — the same structural
// no-eval idiom piloted on `comments` and rolled out to `funcs`. `f`/`f-` are
// address-scoped exactly like those tables' writes, so they use the same
// `dispatch_write(be, addr, command)` shape.
//
// `fr <old> <new>` is the odd one out: unlike every other write in this
// family, it carries NO address anywhere in its own grammar at all — radare2
// resolves both flag names purely by name lookup, independent of the current
// seek. This raised a genuine question when rolling the dispatch out here:
// does `fr` need a new addr-less primitive (the same gap `bookmarks`' rename
// will hit), or can it still route through `cmd_noeval`'s (addr, command)
// shape? Verified against radare2's own source (`r_core_call_at`,
// libr/core/cmd.c) rather than assumed: the seek that dispatch performs is
// STRICTLY TEMPORARY — it seeks to `addr`, calls the command handler
// directly (bypassing `;`/`@`/`|`/backtick evaluation), then unconditionally
// seeks back to whatever address was current before the call. So the address
// passed to `cmd_noeval` is not an input INTO `fr`'s own operation, only a
// place to seek-and-restore around it; since `fr` never consults the current
// seek, passing this flag's own `r.addr` costs nothing and buys the same
// structural no-eval guarantee every other write here gets. This works
// because a `flags` row always has a real, valid address of its own to use
// for that harmless seek — it is NOT a general answer to "how do you
// `cmd_noeval` a command with no address at all". A write with no natural
// address anywhere near it (which `bookmarks`' rename may or may not turn out
// to be) would still need a genuine addr-less primitive; that remains
// unbuilt and is not needed here.
//
// The rename is ALSO now C-API-backed on the libr flavor, a separate, later
// port from the cmd_noeval rollout above: a benchmark
// measured a bulk workload (N up to 500 repeated renames, simulating a
// bulk-rename script) at 48-62x over the CMD leg (the SAME
// `r_core_call_str_at("fr ...")` dispatch this table already issues), with
// exact parity — `fr`'s own handler (`cmd_flag.inc.c`) was read and found to
// be nothing more than the same `r_flag_get` (by name) + `r_flag_rename` the
// API leg calls directly, unlike `funcs.name`'s `afn` (see that table's
// comment for why THAT rename was refused). The C-API leg needs no address
// at all — see `Api::flag_rename` in `direct.hpp`. On every non-libr backend
// (r2pipe, mock), `Backend::direct()` returns nullptr and the exact `fr`
// dispatch above runs unchanged.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <r_util.h>
#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2xsql {

namespace {
using direct::FlagRow;

// Dispatch a write command scoped to `addr`. Tries the structural no-eval
// path first (libr backend only, via Backend::cmd_noeval); falls back to the
// original command-string form (`command @ addr`) on every backend that
// reports it unsupported, so r2pipe's behavior and command text stay
// byte-for-byte unchanged. Same helper shape as the `comments`/`funcs`
// tables' pilot of this dispatch.
std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}

void build_flags(Backend* be, std::vector<FlagRow>& rows) {
  auto arr = be->cmd_json("fj");
  if (!arr.is_array()) return;
  rows.reserve(arr.size());
  // Index by name: flag names are unique within a radare2 session (`f <name>`
  // replaces), and a name is what the per-space listing gives back.
  std::unordered_map<std::string, size_t> by_name;
  for (auto& j : arr) {
    FlagRow r;
    r.addr     = json_utils::i64_addr(j);
    r.size     = json_utils::i64(j, "size");
    r.name     = json_utils::str(j, "name");
    r.realname = json_utils::str(j, "realname");
    if (!r.name.empty()) by_name.emplace(r.name, rows.size());
    rows.push_back(std::move(r));
  }

  auto spaces = be->cmd_json("fsj");
  if (!spaces.is_array()) return;
  for (const auto& sp : spaces) {
    const std::string name = json_utils::str(sp, "name");
    // A space name is spliced into a command, so it gets the same charset gate
    // as every other name this project sends to radare2.
    if (name.empty() || !r_name_check(name.c_str())) continue;
    if (json_utils::i64(sp, "count") == 0) continue;   // nothing to attribute

    // One command, not three: selecting a flagspace is session state, so the
    // select / list / restore has to be atomic with respect to anything else
    // using this backend. `fs *` restores the default (all spaces visible),
    // which is what every other reader here expects to find.
    auto in_space = be->cmd_json("fs " + name + "; fj; fs *");
    if (!in_space.is_array()) continue;
    for (const auto& j : in_space) {
      auto it = by_name.find(json_utils::str(j, "name"));
      if (it != by_name.end()) rows[it->second].space = name;
    }
  }
}
}  // namespace

void register_flags_table(Session& s) {
  auto def = xsql::cached_table<FlagRow>("flags")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, direct::Collection::Flags, "fj~?", 4096);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<FlagRow>& rows) {
      if (auto* api = be->direct()) {
        api->flags_scan(rows);
        return;
      }
      build_flags(be, rows);
    })
    .column_int64("addr",     [](const FlagRow& r) { return r.addr; })
    .column_int64("size",     [](const FlagRow& r) { return r.size; })
    .column_text_rw("name",
      [](const FlagRow& r) { return r.name; },
      [be = s.backend_ptr()](FlagRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!r_name_check(v)) {
          xsql::set_vtab_error(
              "flags: name must start with a letter, '_' or ':' and use only [A-Za-z0-9._:]");
          return false;
        }
        if (r.name == v) return true;
        // `fr <old> <new>` is radare2's generic in-place flag rename
        // (r_flag_rename -> update_flag_item_name): it updates the existing
        // item's name key and never creates a new item, regardless of which
        // flagspace the flag lives in.
        //
        // This used to try `afn <new> @ <addr>` first, on the theory that it
        // was a harmless "function symbol" fast path that no-ops for a
        // non-function flag. Live-verified against radare2
        // (`__setFunctionName` in the analysis command dispatcher) that this
        // was wrong: `afn` only renames the flag in place when the flag it
        // looks up by the function's OWN analysis name is already in the
        // `functions` flagspace. Otherwise it CREATES a brand-new flag under
        // the new name (parked in whichever space its own prefix-matching
        // picks) and leaves the original flag completely untouched. The
        // follow-up `fr <old> <new>` then also fails — the new name is
        // already taken by the just-created duplicate — but that failure was
        // never surfaced, so the net observable effect of a rename through
        // this table was a second, extra flag at the same address plus the
        // original flag surviving under its old name unchanged. Reproduced
        // live: a `symbols`-space flag renamed through this path left the old
        // flag in place in `symbols` and added a duplicate in `functions`.
        //
        // Fix: issue plain `fr` only — it is the correct, generic, in-place
        // rename for any flag regardless of space, and its result is checked
        // like the other single-command flag writes below. A function's own
        // analysis-tracked name (used by decompiler/xref output) is kept in
        // sync separately via the `funcs` table's `name` column, which issues
        // `afn` directly and is unaffected by this change.
        //
        // The C-API leg needs no address at all (see the file header) — try
        // it first on the libr backend.
        if (auto* api = be->direct()) {
          if (!api->flag_rename(r.name, v)) {
            xsql::set_vtab_error("flags: rename failed (addr=" +
                                 json_utils::hex_addr(r.addr) +
                                 "): flag not found or new name rejected");
            return false;
          }
          r.name = v;
          return true;
        }
        // Fallback (r2pipe, mock): `fr` takes no address at all (see the file
        // header for the full reasoning) — dispatch it through cmd_noeval
        // anyway, seeked to this row's own `r.addr`, which the command never
        // consults; a plain Backend::cmd_noeval-unsupported backend (r2pipe,
        // mock) falls back to the exact same bare `fr <old> <new>` string
        // this table has always issued, with no `@ <addr>` ever spliced onto
        // it.
        std::string cmd = std::string("fr ") + r.name + " " + v;
        std::string out;
        if (!be->cmd_noeval(r.addr, cmd, &out)) {
          out = be->cmd(cmd);
        }
        if (std::string e = table_utils::command_error_text(out); !e.empty()) {
          xsql::set_vtab_error("flags: rename failed (addr=" +
                               json_utils::hex_addr(r.addr) + "): " + e);
          return false;
        }
        // Refused fr commands may report only to stderr; verify the write.
        const auto flags = be->cmd_json("fj");
        if (!flags.is_array() || std::any_of(flags.begin(), flags.end(),
            [&r](const auto& flag) { return json_utils::str(flag, "name") == r.name; })) {
          xsql::set_vtab_error("flags: rename was not reflected by fj (name=" + r.name + ")");
          return false;
        }
        r.name = v;
        return true;
      })
    .column_text ("realname", [](const FlagRow& r) { return r.realname; })
    .column_text ("space",    [](const FlagRow& r) { return r.space; })
    .deletable([be = s.backend_ptr()](FlagRow& r) -> bool {
      std::string out = dispatch_write(be, r.addr, "f-");
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("flags: DELETE failed (addr=" +
                             json_utils::hex_addr(r.addr) + "): " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns: addr(0), size(1), name(2), realname(3), space(4).
      if (argc < 3 || argv[0].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("flags: INSERT requires addr and name");
        return false;
      }
      int64_t addr = 0;
      if (!table_utils::exact_write_int64(argv[0], "flags: addr", addr)) return false;
      const char* name = argv[2].as_c_str();
      if (!name || !*name) {
        xsql::set_vtab_error("flags: INSERT requires a non-empty name");
        return false;
      }
      if (!r_name_check(name)) {
        xsql::set_vtab_error(
            "flags: name must start with a letter, '_' or ':' and use only [A-Za-z0-9._:]");
        return false;
      }
      std::string out = dispatch_write(be, addr, std::string("f ") + name);
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error(std::string("flags: INSERT failed (name=") + name + "): " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql


