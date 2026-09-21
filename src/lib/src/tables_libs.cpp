// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// libs -- the binary's linked/imported library list, backed by `ilj`
// (`bin_libs`, libr/core/cbin.c). Confirmed live: `bin_libs` is a thin
// wrapper over `r_bin_get_libs(core->bin)` -- for a PE this is each DLL an
// import comes from (`kernel32.dll`, `user32.dll`, ...), the same data a
// native ELF's `DT_NEEDED` entries would populate through the same API on
// that format. The JSON mode (`IS_MODE_JSON`) is a plain `pj_s` per entry --
// a bare array of STRINGS, not objects (verified by reading the handler:
// there is no per-entry object, ordinal, or path field anywhere in this
// command's emission, on any mode). Confirmed on a real ~2700-import DLL
// fixture that this returns radare2's own dependency set (its `r_util`/
// `r_reg`/... sibling DLLs plus the Windows CRT/system DLLs it links), not
// just the small 4-entry set the stripped test PE happens to show.
//
// One column, matching the actual JSON shape rather than inventing fields
// the command never provides (an ordinal, a load-order index, a resolved
// path) -- the same "column inventory only, no invented curation" call made
// for this cluster.
//
// No C-API producer: `ilj` is already ONE full-scan command over a small
// list (`r_bin_get_libs`) with no N-per-function/N-per-address shape to
// collapse -- the same reasoning `relocs` documents for skipping a port.
// Ships command-path-only on both backends, matching `syscalls`/
// `calling_conventions`/`classes`/`relocs`/`registers`.
//
// No pushdown: the library list is tiny (single digits to low dozens) --
// smaller than any other reference table in this project.
//
// Deliberately NOT de-duplicated beyond whatever `r_bin_get_libs` itself
// returns: if a format's loader ever emitted the same library name twice,
// this table reproduces that verbatim rather than silently collapsing it,
// the same "uncurated, matches the underlying truth" precedent `names`/
// `classes` already document.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"

namespace r2xsql {

namespace {

struct LibRow {
  std::string name;
};

}  // namespace

void register_libs_table(Session& s) {
  auto def = xsql::cached_table<LibRow>("libs")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 16; })
    .cache_builder([be = s.backend_ptr()](std::vector<LibRow>& rows) {
      auto arr = be->cmd_json("ilj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        if (!j.is_string()) continue;
        LibRow r;
        r.name = j.get<std::string>();
        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const LibRow& r) { return r.name; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
