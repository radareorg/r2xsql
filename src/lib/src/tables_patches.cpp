// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// patches — a writable surface over radare2's write-cache (`io.cache`) byte
// overlay: stage a raw hex patch, optionally commit it to the underlying
// file, or undo it while it is still pending. Command-path only (`wx`/`wci`/
// `wcu`/`wcj`) -- no C-API port -- with identical observable behavior on both
// backends; INSERT's `wx` additionally dispatches through the structural
// no-eval path (Backend::cmd_noeval) on the in-process (libr) backend only,
// falling back to the exact same command text on every other backend (see
// the no-eval rollout note further down this header).
//
// `asm_text` (INSERT-only, write-only): the assembled-text alternative this
// file's own original design note flagged as a future extension ("Raw hex
// only in this first version -- never wa/wz -- ... assembled-text or string
// patches are a future extension"). Closes the `patch_asm(addr, asm)` gap
// WITHOUT a new write primitive: `asm_text` is assembled to hex via
// `table_utils::assemble_hex` (the SAME `pa`-based helper `tables_assemble.cpp`'s
// `assemble` table uses, charset-gated by `json_utils::valid_asm_source_text`
// first) and the result is handed to the EXISTING `wx <hex> @ addr` path
// below, unchanged -- `wa`/`wz` are still never used, exactly as this file
// always intended. Exactly one of `patched_bytes`/`asm_text` must be given;
// `asm_text` itself is never stored or read back (PatchRow has no field for
// it -- a SELECT always reads this column as an empty string, including for
// the row an `asm_text` INSERT just created, since `wcj`'s cache entries only
// ever carry bytes, never the mnemonic that produced them).
//
// Column mapping corrects a confirmed radare2 field-naming defect: `wcj`
// reports each cache entry's bytes under `"after"`/`"before"` keys that are
// swapped relative to their actual contents (`"after"` holds the ORIGINAL
// bytes, `"before"` holds the NEW ones -- verified against the write-cache
// undo path, which restores a patch from the field named `"after"`). This
// table's own columns are named for what they mean and mapped explicitly:
//   original_bytes <= wcj "after"
//   patched_bytes  <= wcj "before"
// Never copy wcj's field names verbatim into a query result -- that would
// carry the swap into a caller who trusts the label.
//
// HARD CONSTRAINT, load-bearing: radare2's write cache has no selective or
// ranged commit. Its ranged form (`wc+ <from> <to>`) has a confirmed
// upstream parser defect that silently collapses any two-argument range to
// a 1-byte commit, which then corrupts the cache entry and can crash the
// process later -- this is not a style preference, it is unsafe. The ONLY
// commit primitive this file may ever issue is `wci` (commit every pending
// patch in the session). UPDATE patches SET committed=1 therefore commits
// ALL currently-pending patches, not just the matched row -- there is no
// way to commit "just this one." If a caller wants to keep some patches
// uncommitted while committing others, they must DELETE the ones they don't
// want committed first, then commit. Never add a ranged wc+/wc- call here
// to make this "more precise" -- that reintroduces exactly the corrupting
// path this design avoids.
//
// DELETE constraint, also load-bearing and NOT part of the original design
// note: radare2's undo primitive (`wcu`) is a LIFO stack pop -- it always
// undoes whichever cache entry was staged MOST RECENTLY, with no address
// targeting at all (verified against `r_io_cache_undo`'s source: it pops
// the last element of the cache layer's item vector, unconditionally). So
// `DELETE FROM patches WHERE addr=X` is only safe when the matched row is
// itself the most-recently-staged entry in the whole session -- otherwise
// `wcu` would silently undo a DIFFERENT (newer) patch than the one named in
// the WHERE clause. This table detects that case (see PatchRow::is_stack_top)
// and refuses the DELETE with a clear error instead of guessing.
//
// Staging requires `io.cache=true`; this file sets it before every `wx` so
// INSERT behaves the same whether or not a caller already enabled it.
//
// `patches` is the sixth and last write-capable table examined for the
// structural no-eval dispatch (Backend::cmd_noeval) piloted on `comments` and
// rolled out to `funcs`/`flags`/`bookmarks`/`types`. Its three writes split
// two different ways, not one:
//
//   - INSERT's `wx <hex> @ <addr>` IS address-scoped, the same shape every
//     prior table's address-scoped write already used -- it dispatches
//     through the same `dispatch_write(be, addr, command)` helper. Its own
//     free-text argument (`patched_bytes`) is already constrained, before
//     this dispatch ever runs, to `json_utils::valid_hex_bytes`'s charset
//     ([0-9a-fA-F], even length) -- a set that structurally cannot contain
//     `;`/`@`/`|`/backtick, so the hex validator alone already makes chaining
//     through THIS argument impossible. cmd_noeval adds no NEW closed hole
//     for this one input; it is wired in anyway for defense-in-depth and
//     consistency with the other five tables' address-scoped writes, not
//     because a real gap was found here.
//   - UPDATE's `wci` and DELETE's `wcu` are NEITHER address-scoped NOR
//     user-parameterized at all: both are issued as fixed, literal strings
//     with zero interpolation (see the two `be->cmd(...)` call sites below --
//     neither ever concatenates anything into the command text). Unlike
//     `td`/`t-` (also addr-less, but whose user-supplied declaration/name IS
//     a real injection surface, which is why `types` needed
//     `table_utils::dispatch_type_write`'s fixed anchor), there is no
//     attacker-controlled text anywhere in `wci`'s or `wcu`'s construction to
//     protect -- inventing a fixed-anchor cmd_noeval call for a hardcoded
//     literal would add a code path with no security benefit, so both stay
//     on the plain `Backend::cmd()` path, unchanged. This is a deliberate,
//     audited "nothing to harden" finding, not an oversight: with it, all six
//     write-capable tables in this project have been examined for this idiom.

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {

// Dispatch a write command scoped to `addr`. Tries the structural no-eval
// path first (libr backend only, via Backend::cmd_noeval); falls back to the
// original command-string form (`command @ addr`) on every backend that
// reports it unsupported, so r2pipe's behavior and command text stay
// byte-for-byte unchanged. Same helper shape as the `comments`/`funcs`/
// `flags`/`bookmarks` tables' rollout of this dispatch. Only INSERT's `wx`
// uses this -- `wci`/`wcu` are fixed literals with no address and nothing to
// dispatch differently (see the file header).
std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}

using direct::PatchRow;

// Read the current write-cache layer (`wcj`) into row form, swap-correcting
// the before/after field names. Single source of truth for SELECT and for
// every mutation's readback verification below.
std::vector<PatchRow> load_layer(Backend* be) {
  std::vector<PatchRow> rows;
  if (auto* api = be->direct()) {
    api->patches_scan(rows);
    return rows;
  }
  auto j = be->cmd_json("wcj");
  if (!j.is_object()) return rows;
  auto it = j.find("layer");
  if (it == j.end() || !it->is_array()) return rows;
  rows.reserve(it->size());
  for (auto& e : *it) {
    PatchRow r;
    // `addr` is a ut64 in radare2 and an int64 here, because SQLite has no
    // unsigned 64-bit type -- so an address >= 2^63 necessarily renders
    // NEGATIVE. That is not hypothetical: radare2's write cache has been
    // observed carrying a sentinel entry at 0xfffffffffffffffe (UT64_MAX-1,
    // size 1), which surfaces as addr = -2 and sorts first under ORDER BY addr.
    // Surfaced faithfully rather than filtered: it is genuinely in r2's cache,
    // and silently dropping rows would be worse than showing an odd one. Every
    // address column in r2xsql shares this projection; real addresses never
    // reach 2^63, so only r2-side sentinels can trip it.
    r.addr = json_utils::i64(e, "addr");
    r.size = json_utils::i64(e, "size");
    r.original_bytes = json_utils::str(e, "after");   // swap-corrected
    r.patched_bytes  = json_utils::str(e, "before");  // swap-corrected
    r.committed = json_utils::boolean(e, "written") ? 1 : 0;
    rows.push_back(std::move(r));
  }
  if (!rows.empty()) rows.back().is_stack_top = true;
  return rows;
}

}  // namespace

void register_patches_table(Session& s) {
  auto def = xsql::cached_table<PatchRow>("patches")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 16; })
    .cache_builder([be = s.backend_ptr()](std::vector<PatchRow>& rows) {
      rows = load_layer(be);
    })
    .column_int64("addr",            [](const PatchRow& r) { return r.addr; })
    .column_int64("size",            [](const PatchRow& r) { return r.size; })
    .column_text ("original_bytes",  [](const PatchRow& r) { return r.original_bytes; })
    .column_text ("patched_bytes",   [](const PatchRow& r) { return r.patched_bytes; })
    // committed: writable, but only SET committed=1 is a defined operation
    // (see the HARD CONSTRAINT note above -- it commits EVERY pending patch,
    // not just this row). SET committed=0 has no verified radare2 primitive
    // and is rejected rather than guessed at.
    .column_int_rw("committed",
      [](const PatchRow& r) { return r.committed; },
      [be = s.backend_ptr()](PatchRow& r, int v) -> bool {
        if (v != 1) {
          xsql::set_vtab_error(
              "patches: UPDATE only supports SET committed = 1 -- there is no "
              "verified 'uncommit' primitive once a patch is written through "
              "(DELETE the patch before committing if you don't want it applied)");
          return false;
        }
        if (r.committed) return true;  // already committed: idempotent no-op

        // The one and only safe commit primitive. NEVER a ranged wc+/wc- --
        // see the HARD CONSTRAINT note at the top of this file.
        if (std::string e = table_utils::command_error_text(be->cmd("wci")); !e.empty()) {
          xsql::set_vtab_error("patches: UPDATE (commit) failed: " + e);
          return false;
        }

        // `wci` prints nothing on success OR failure -- verify via readback
        // that every pending patch actually flipped to written=true, the
        // same silent-failure discipline the types table's td+tk guard uses.
        for (auto& e : load_layer(be)) {
          if (!e.committed) {
            xsql::set_vtab_error(
                "patches: UPDATE (commit) did not take effect for addr " +
                json_utils::hex_addr(e.addr) +
                " -- the session may need write access (-w) to commit to "
                "the underlying file");
            return false;
          }
        }
        r.committed = 1;
        return true;
      })
    // asm_text: INSERT-only convenience, never stored/read back (see file
    // header) -- always empty on SELECT, including immediately after an
    // asm_text-driven INSERT. Declared LAST so its column index (5) sits
    // after committed's (4), matching the insertable() callback's own
    // "columns in declared order" comment below.
    .column_text ("asm_text",        [](const PatchRow&) { return std::string(); })
    // DELETE FROM patches WHERE addr=X undoes an UNCOMMITTED patch via `wcu`.
    // Refused for a committed row (undo semantics there are unverified, see
    // FINDINGS) and refused when the row isn't the most-recently-staged
    // entry (wcu is a LIFO stack pop with no address targeting -- see the
    // DELETE constraint note at the top of this file).
    .deletable([be = s.backend_ptr()](PatchRow& r) -> bool {
      if (r.committed) {
        xsql::set_vtab_error(
            "patches: DELETE refused -- this patch is already committed; "
            "undo semantics for a committed write-cache entry are unverified "
            "and not supported by this table");
        return false;
      }
      if (!r.is_stack_top) {
        xsql::set_vtab_error(
            "patches: DELETE refused -- radare2's undo (wcu) always undoes "
            "the MOST RECENTLY STAGED patch, never the one matched by addr "
            "(there is no address-targeted undo in radare2's write cache); a "
            "newer pending patch is staged after this one, so undoing now "
            "would silently revert the WRONG patch. Delete the newer pending "
            "patch(es) first, then this one.");
        return false;
      }
      const size_t before_count = load_layer(be).size();
      if (std::string e = table_utils::command_error_text(be->cmd("wcu")); !e.empty()) {
        xsql::set_vtab_error("patches: DELETE failed: " + e);
        return false;
      }
      // `wcu` prints nothing on success OR failure either -- verify via
      // readback that the cache layer actually shrank.
      if (load_layer(be).size() >= before_count) {
        xsql::set_vtab_error(
            "patches: DELETE failed -- wcu did not remove the pending patch "
            "(cache layer size unchanged; io.cache may be disabled)");
        return false;
      }
      return true;
    })
    // INSERT INTO patches(addr, patched_bytes) VALUES(0x140001d70, '90909090')
    // stages a new, uncommitted raw-hex patch. INSERT INTO patches(addr,
    // asm_text) VALUES(0x140001d70, 'nop') assembles the mnemonic first (via
    // table_utils::assemble_hex, the SAME helper `assemble`'s table uses) and
    // stages the result the identical way -- exactly one of the two must be
    // given (see the file header). Never `wa`/`wz` either way.
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: addr(0), size(1), original_bytes(2),
      // patched_bytes(3), committed(4), asm_text(5).
      if (argc < 4 || argv[0].is_null()) {
        xsql::set_vtab_error(
            "patches: INSERT requires addr and exactly one of "
            "patched_bytes/asm_text");
        return false;
      }
      if (argc > 1 && !argv[1].is_null()) {
        xsql::set_vtab_error(
            "patches: size is derived from patched_bytes/asm_text on INSERT, do not set it");
        return false;
      }
      if (argc > 2 && !argv[2].is_null()) {
        xsql::set_vtab_error("patches: original_bytes is read back from radare2 on INSERT, do not set it");
        return false;
      }
      if (argc > 4 && !argv[4].is_null()) {
        xsql::set_vtab_error(
            "patches: committed cannot be set on INSERT -- a new patch always "
            "starts uncommitted; use UPDATE ... SET committed = 1 to commit");
        return false;
      }

      int64_t addr = 0;
      if (!table_utils::exact_write_int64(argv[0], "patches: addr", addr)) return false;
      const bool have_hex = argc > 3 && !argv[3].is_null();
      const bool have_asm = argc > 5 && !argv[5].is_null();
      if (have_hex == have_asm) {
        xsql::set_vtab_error(
            "patches: INSERT requires EXACTLY ONE of patched_bytes (raw hex) "
            "or asm_text (an assembly mnemonic to encode) -- not both, not "
            "neither");
        return false;
      }

      std::string hex;
      if (have_hex) {
        const char* hex_c = argv[3].as_c_str();
        hex = json_utils::compact_hex(hex_c ? hex_c : "");
        // Same hex validator byte_search's exact-match decoder uses (see
        // json_utils::valid_hex_bytes / hex_decode) -- one shared definition
        // of "valid hex" across every table that accepts a raw byte string.
        if (!json_utils::valid_hex_bytes(hex)) {
          xsql::set_vtab_error(
              "patches: patched_bytes must be a non-empty, even-length hex "
              "string (e.g. '90909090')");
          return false;
        }
      } else {
        const char* asm_c = argv[5].as_c_str();
        const std::string asm_text = asm_c ? asm_c : "";
        // Same charset allowlist `assemble`/`search_asm` use (see
        // tables_assemble.cpp) -- makes splicing asm_text into `pa` safe
        // without quoting, on every backend.
        if (!json_utils::valid_asm_source_text(asm_text)) {
          xsql::set_vtab_error(
              "patches: asm_text accepts only disassembly-safe characters "
              "(letters, digits, space, and ,.+-*/[]():%#_$)");
          return false;
        }
        // Assembled AT the patch's own target address -- pc-relative
        // encodings (short branches, rip-relative loads) must be computed
        // relative to where the patch actually lands, not wherever the
        // session happens to be seeked at INSERT time.
        if (!table_utils::assemble_hex(be, addr, asm_text, &hex)) {
          xsql::set_vtab_error(
              "patches: INSERT failed -- radare2 could not assemble '" +
              asm_text +
              "' (bad mnemonic/operands, or unsupported on this arch)");
          return false;
        }
      }
      std::vector<uint8_t> bytes;
      if (!json_utils::hex_decode(hex, bytes)) {
        xsql::set_vtab_error("patches: resulting patched_bytes is not valid hex");
        return false;
      }

      // `wx` only stages into the revertible overlay when io.cache is on;
      // set it explicitly so INSERT behaves the same regardless of prior
      // session state (harmless to repeat -- an idempotent config write).
      be->cmd("e io.cache=true");

      // Address-scoped, same shape as every prior table's address-scoped
      // write -- see the file header for why cmd_noeval is wired in here
      // even though the hex validator above already makes this argument
      // injection-proof on its own.
      if (std::string e = table_utils::command_error_text(
              dispatch_write(be, addr, "wx " + hex));
          !e.empty()) {
        xsql::set_vtab_error(
            "patches: INSERT failed (addr=" + json_utils::hex_addr(addr) + "): " + e);
        return false;
      }

      // Readback verification (same discipline as the types table's td+tk
      // guard): a write-cache parser failure can
      // otherwise look like a silent no-op success. Confirm the entry we
      // just staged is really there, at the address and size we asked for.
      auto rows = load_layer(be);
      if (rows.empty() || rows.back().addr != addr ||
          rows.back().size != static_cast<int64_t>(bytes.size()) ||
          rows.back().committed != 0) {
        xsql::set_vtab_error(
            "patches: INSERT failed (addr=" + json_utils::hex_addr(addr) +
            "): the write-cache entry was not present after wx");
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
