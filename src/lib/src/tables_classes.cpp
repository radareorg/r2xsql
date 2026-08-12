// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// classes / class_methods — C++ class/vtable/RTTI recovery, backed by
// radare2's anal-side class database (`RAnalClass`, sdb-backed): `acl`
// (text)/`aclj` (JSON). This is a DIFFERENT, unrelated concept from
// `ic`/`icj` (`RBinClass`) -- that command reads bin-format class tables
// (Java/.class, Objective-C, .NET) populated at load time by the matching
// bin plugin, and is structurally empty for every native PE/ELF binary
// regardless of content. `ic`/`icj` is never used here. There is also no
// `acj` command -- the top-level `ac` dispatcher has no `j` case at that
// level; the JSON list verb is `aclj`, reached through `ac` + `l` + `j`.
//
// The anal-side class database is populated either by hand (`ac`/`acm`/`acv`)
// or automatically by `avrr` (search for C++ vtables, then parse MSVC/Itanium
// RTTI at each one). radare2's own `aaa` already runs `avrr` internally once,
// at file-open/analysis time, before this table (or any table) is ever
// queried.
//
// THE HARD CONSTRAINT: `avrr` is confirmed NOT idempotent. A second explicit
// `avrr` call duplicates every already-recovered class under a `_1`-suffixed
// name (`r_anal_class_create`'s clash-avoidance renames rather than
// erroring/merging/no-op'ing) -- measured directly: 7 classes became 14 on a
// second call, every original name duplicated. Consequence: this file must
// NEVER issue `avrr` (or `av`) itself, under any code path, including on
// table (re)registration or a fresh cache build. It only ever reads the
// class database that `aaa` already populated, via `aclj`. If `aaa` has not
// run yet in the session, `aclj` reports whatever is already recovered (very
// possibly nothing) -- an honest empty result, never a trigger to recover
// anything ourselves.
//
// Both tables re-read `aclj` on every query (no cache shared across queries,
// same convention as `types`/`types_members`) -- `aclj` is a pure read of
// already-recovered state, so re-reading it costs one extra command per
// query but can never re-trigger the expensive, non-idempotent recovery
// itself (that only happens inside `avrr`, which this file never calls).
//
// Design decisions made explicitly for this first version (not left open):
//
//   - Multiple inheritance: `classes.base_name` is a single nullable TEXT
//     column holding only the FIRST direct base from `aclj`'s `bases[]`
//     array. A class with more than one direct base (multiple inheritance)
//     loses every base past the first from this column -- not silently
//     corrupted (the first base is real and correct), but genuinely a
//     narrower view than the raw data. A future breaking-schema revision
//     could add a junction table (one row per class/base pair) if that
//     turns out to matter; not built now.
//   - CRT-noise filtering: NONE. Every class `aclj` reports is visible here,
//     including CRT-internal recoveries from a statically-linked runtime
//     (`type_info`, `std::exception`, `std::bad_alloc`, ...). This table
//     does not invent a curation boundary radare2 itself does not draw. A
//     caller who wants only their own program's classes filters client-side
//     (e.g. `WHERE name NOT LIKE 'std::%' AND name <> 'type_info'`).
//   - ABI coverage: verified against MSVC RTTI only (exact method counts and
//     base relationships, confirmed against a known compiled hierarchy).
//     The Itanium ABI (GCC/Clang, Linux/macOS) path exists in radare2
//     (`avrr` branches on `context.abi`) but its accuracy through this
//     surface is UNVERIFIED -- do not assume or claim cross-platform
//     correctness from this table alone.
//
// No pushdown: the recovered class set is small (tens to low hundreds of
// classes on a realistic binary) and is not re-computed per query shape --
// see the caching note above.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {

struct ClassRow {
  std::string                name;
  std::optional<std::string> base_name;    // first direct base only; see file header
  std::optional<int64_t>     vtable_addr;
};

struct ClassMethodRow {
  std::string             class_name;
  std::string              name;
  int64_t                  addr = 0;
  std::optional<int64_t>   vtable_offset;  // NULL for a non-virtual method
};

}  // namespace

void register_classes_table(Session& s) {
  auto def = xsql::cached_table<ClassRow>("classes")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 64; })
    .cache_builder([be = s.backend_ptr()](std::vector<ClassRow>& rows) {
      auto arr = be->cmd_json("aclj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& c : arr) {
        if (!c.is_object()) continue;
        ClassRow r;
        r.name = json_utils::str(c, "name");

        auto bases_it = c.find("bases");
        if (bases_it != c.end() && bases_it->is_array() && !bases_it->empty() &&
            (*bases_it)[0].is_object()) {
          std::string base_name = json_utils::str((*bases_it)[0], "name");
          if (!base_name.empty()) r.base_name = std::move(base_name);
        }

        auto vt_it = c.find("vtables");
        if (vt_it != c.end() && vt_it->is_array() && !vt_it->empty() &&
            (*vt_it)[0].is_object()) {
          r.vtable_addr = json_utils::i64_addr((*vt_it)[0]);
        }

        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const ClassRow& r) { return r.name; })
    .column_text_nullable("base_name",
        [](const ClassRow& r) { return r.base_name; })
    .column("vtable_addr", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const ClassRow& r) {
          if (r.vtable_addr) ctx.result_int64(*r.vtable_addr);
          else ctx.result_null();
        })
    .build();
  s.db().register_and_create_cached_table(def);
}

void register_class_methods_table(Session& s) {
  auto def = xsql::cached_table<ClassMethodRow>("class_methods")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 256; })
    .cache_builder([be = s.backend_ptr()](std::vector<ClassMethodRow>& rows) {
      auto arr = be->cmd_json("aclj");
      if (!arr.is_array()) return;
      for (auto& c : arr) {
        if (!c.is_object()) continue;
        const std::string class_name = json_utils::str(c, "name");

        auto methods_it = c.find("methods");
        if (methods_it == c.end() || !methods_it->is_array()) continue;
        for (auto& m : *methods_it) {
          if (!m.is_object()) continue;
          ClassMethodRow r;
          r.class_name = class_name;
          r.name       = json_utils::str(m, "name");
          r.addr       = json_utils::i64_addr(m);
          // radare2 omits the "vtable_offset" key entirely for a non-virtual
          // method the recovery still attributed to the class (class.c only
          // emits it when meth->vtable_offset >= 0) -- absence, not a -1
          // sentinel, is how NULL is signaled here.
          auto vo_it = m.find("vtable_offset");
          if (vo_it != m.end() && vo_it->is_number_integer()) {
            r.vtable_offset = vo_it->get<int64_t>();
          }
          rows.push_back(std::move(r));
        }
      }
    })
    .column_text ("class_name", [](const ClassMethodRow& r) { return r.class_name; })
    .column_text ("name",       [](const ClassMethodRow& r) { return r.name; })
    .column_int64("addr",       [](const ClassMethodRow& r) { return r.addr; })
    .column("vtable_offset", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const ClassMethodRow& r) {
          if (r.vtable_offset) ctx.result_int64(*r.vtable_offset);
          else ctx.result_null();
        })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
