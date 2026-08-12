// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// types — radare2 type system catalog.
//
// Backed by:
//   tk*   list of `NAME=KIND` pairs (atomic|struct|union|enum|typedef|func)
//   tj    array of atomic-type records with size + pf format
//   tsj N struct definition (name, format, fields[])
//   tuj N union definition  (same shape as tsj)
//   tej N enum  definition  (name, values{key:int, ...})
//
// One row per type. Columns:
//   ordinal   INT64 — 0-based position of this row in the type set, in the
//                     SAME name-sorted order the row walk below already
//                     produces (a free running counter over the existing
//                     scan -- no extra command, no extra cost). NOT a
//                     persistent per-type identity: this table has
//                     .no_shared_cache() (the type database is mutable), so
//                     the row set -- and therefore every ordinal from the
//                     matched row onward -- is recomputed from scratch on
//                     every query. Two queries in the same session agree on
//                     a given name's ordinal ONLY while the type set is
//                     unchanged; an intervening INSERT/DELETE (or
//                     r2xsql_type_define) shifts the alphabetical position
//                     of every name that sorts after the change. Never
//                     derived from any address. Both backends share this
//                     exact producer (no direct::/C-API path exists for
//                     `types` -- see the "Resolved -- won't build" record),
//                     so pipe and full assign identical ordinals for
//                     identical type sets structurally, not by coincidence.
//   name      TEXT  — fully qualified type name
//   kind      TEXT  — atomic | struct | union | enum | typedef | func | type
//   size      INT64 — byte size (-1 for unsized/opaque/pointer-like)
//   format    TEXT  — pf-style format string (atomics/structs/unions); empty otherwise
//
// Both writes here (`td` for INSERT, `t-` for DELETE) dispatch through
// Backend::cmd_noeval on the in-process (libr) backend -- the fifth
// (`comments`/`funcs`/`flags`/`bookmarks` came first) and structurally
// DIFFERENT rollout of that no-eval idiom: every prior table's write had a
// real row address to seek to; `td`/`t-` have none at all -- a struct/union/
// enum definition is not tied to any address, and `t-` deletes purely by
// name. Verified against radare2's own source (cmd_type.inc.c), not assumed:
// both handlers read only `core->anal`, never `core->addr`/the current seek,
// so `Backend::cmd_noeval`'s mandatory seek target is genuinely unobservable
// to either one -- see `table_utils::kTypeSystemAnchorAddr` /
// `dispatch_type_write` (table_utils.hpp) for the fixed-anchor helper this
// uses instead of a per-row address, and the full citation. `t-`'s name
// argument is already charset-validated (`valid_flag_name`) with no free-text
// surface to speak of; the genuine adversarial surface for this table's
// write family is `r2xsql_type_define`'s one-line C declaration (session.cpp),
// which allows `;`/`{`/`}` (needed for C syntax) and dispatches through the
// same `dispatch_type_write` helper.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2xsql {

namespace {

struct TypeRow {
  int64_t     ordinal = 0;
  std::string name;
  std::string kind;
  int64_t     size = 0;
  std::string format;
};

}  // namespace

void register_types_table(Session& s) {
  auto def = xsql::cached_table<TypeRow>("types")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 256; })
    .cache_builder([be = s.backend_ptr()](std::vector<TypeRow>& rows) {
      auto kinds = json_utils::parse_tk_dump(be->cmd("tk*"));
      if (kinds.empty()) return;

      // Enrich atomics with size + pf format from `tj`.
      std::unordered_map<std::string, std::pair<int64_t, std::string>> atomic_info;
      auto tj = be->cmd_json("tj");
      if (tj.is_object()) {
        const auto& arr = tj.contains("types") ? tj["types"] : nlohmann::json::array();
        for (const auto& j : arr) {
          atomic_info[json_utils::str(j, "type")] =
              {json_utils::i64(j, "size", -1), json_utils::str(j, "format")};
        }
      }

      rows.reserve(kinds.size());
      for (auto& [name, kind] : kinds) {
        TypeRow r;
        r.name = name;
        r.kind = kind;
        r.size = -1;
        if (kind == "atomic" || kind == "type") {
          auto it = atomic_info.find(name);
          if (it != atomic_info.end()) {
            r.size   = it->second.first;
            r.format = it->second.second;
          }
        } else if (kind == "struct" || kind == "union") {
          auto cmd = (kind == "struct" ? std::string("tsj ") : std::string("tuj ")) + name;
          auto j = be->cmd_json(cmd);
          if (j.is_object()) {
            r.format = json_utils::str(j, "format");
            int64_t total = 0;
            int64_t max_field = 0;
            if (j.contains("fields") && j["fields"].is_array()) {
              for (const auto& f : j["fields"]) {
                int64_t sz = json_utils::i64(f, "size");
                int64_t ar = json_utils::i64(f, "array_size", 1);
                if (ar <= 0) ar = 1;
                int64_t fsize = sz * ar;
                if (kind == "struct") total += fsize;
                else if (fsize > max_field) max_field = fsize;
              }
            }
            r.size = (kind == "struct") ? total : max_field;
          }
        }
        rows.push_back(std::move(r));
      }
      std::sort(rows.begin(), rows.end(),
                [](const TypeRow& a, const TypeRow& b) { return a.name < b.name; });
      // Free running counter over the row walk above, taken AFTER the sort so
      // ordinal reflects the same name-sorted order every column reads --
      // matches the default cache-position rowid this table already reports
      // (no .rowid() override exists for `types`), so ordinal and rowid agree.
      for (size_t i = 0; i < rows.size(); ++i) {
        rows[i].ordinal = static_cast<int64_t>(i);
      }
    })
    .column_int64("ordinal", [](const TypeRow& r) { return r.ordinal; })
    .column_text ("name",   [](const TypeRow& r) { return r.name; })
    .column_text ("kind",   [](const TypeRow& r) { return r.kind; })
    .column_int64("size",   [](const TypeRow& r) { return r.size; })
    .column_text ("format", [](const TypeRow& r) { return r.format; })
    // DELETE FROM types WHERE name='X' removes the type (`t- X`). A full
    // typed declaration (members, an underlying primitive, a signature, …)
    // doesn't fit the row columns, so that stays on the
    // r2xsql_type_define('<C decl>') scalar function. INSERT covers only
    // the one case that genuinely fits name+kind alone: an EMPTY
    // struct/union/enum shell, synthesized as the equivalent one-line C
    // declaration and routed through the same `td` command
    // r2xsql_type_define already uses — not a second code path, just a
    // narrower entry to the same one. atomic/typedef/func are refused: an
    // atomic type needs a real primitive, a typedef needs a target type,
    // and a func needs a signature, none of which a bare name+kind can
    // supply without inventing one.
    .deletable([be = s.backend_ptr()](TypeRow& r) -> bool {
      if (r.name.empty() || !json_utils::valid_flag_name(r.name)) {
        xsql::set_vtab_error("types: refusing to delete an unsafe/empty type name");
        return false;
      }
      // `t-` has no address in its own grammar at all (see the file header);
      // dispatch_type_write seeks Backend::cmd_noeval to the fixed
      // kTypeSystemAnchorAddr instead of a per-row address, falling back to
      // this exact same "t- <name>" string, byte-for-byte, on every backend
      // that reports the primitive unsupported (r2pipe, mock).
      const std::string cmd = "t- " + r.name;
      if (std::string e = table_utils::command_error_text(
              table_utils::dispatch_type_write(be, cmd));
          !e.empty()) {
        xsql::set_vtab_error("types: DELETE failed (name=" + r.name + "): " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: ordinal(0, read-only, ignored here),
      // name(1), kind(2), size(3), format(4).
      if (argc < 3 || argv[1].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("types: INSERT requires name and kind");
        return false;
      }
      const char* name_c = argv[1].as_c_str();
      const char* kind_c = argv[2].as_c_str();
      const std::string name = name_c ? name_c : "";
      const std::string kind = kind_c ? kind_c : "";
      if (name.empty() || !json_utils::valid_flag_name(name)) {
        xsql::set_vtab_error("types: refusing to create an unsafe/empty type name");
        return false;
      }
      if (kind != "struct" && kind != "union" && kind != "enum") {
        xsql::set_vtab_error(
            "types: INSERT only creates an empty struct/union/enum shell "
            "(kind must be one of those three) -- for a real type with "
            "members, an underlying primitive, or a signature, use "
            "r2xsql_type_define('<C decl>') instead");
        return false;
      }
      const std::string decl = kind + " " + name + " {};";
      // `td` is not address-scoped either (see the file header); the no-eval
      // leg takes the declaration completely unquoted (r_cmd_call never
      // re-scans it for ';'/'{'/'}' the way r_core_cmd0 does, so there is
      // nothing for a quote wrapper to protect there -- and a quote wrapper
      // would be taken as literal argument text, breaking the declaration).
      // The fallback leg keeps the pre-existing r2_quote wrapping verbatim,
      // since only r_core_cmd0's evaluating path needs it.
      const std::string out = table_utils::dispatch_type_write(
          be, "td " + decl, json_utils::r2_quote("td " + decl));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("types: INSERT failed (name=" + name + "): " + e);
        return false;
      }
      // A td parser failure may log only to stderr and otherwise look like
      // a successful no-output command -- read the name back, same guard
      // r2xsql_type_define already relies on for the same reason.
      if (table_utils::trim_ascii(be->cmd("tk " + name)).empty()) {
        xsql::set_vtab_error("types: INSERT failed (name=" + name +
                             "): type was not present after td");
        return false;
      }
      return true;
    })
    .build();
  (void)s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
