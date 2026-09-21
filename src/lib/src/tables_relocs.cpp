// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// relocs -- the binary's relocation table, backed by `irj` (`bin_relocs`,
// libr/core/cbin.c, IS_MODE_JSON branch). Confirmed live on two real PE
// fixtures (a stripped static PE and a real ~2000-reloc DLL) that this
// command exists and returns real relocation entries -- it is NOT vacuous
// the way `icj` (classes) turned out to be. `irj` walks
// `r_bin_get_relocs(core->bin)` and prints one object per `RBinReloc`.
//
// Field shape read directly from the emitter (`bin_relocs`'s
// `IS_MODE_JSON` branch), not assumed:
//
//   - `name`/`demname` are each conditionally emitted only when
//     `R_STR_ISNOTEMPTY`: `name` is the associated import's or symbol's
//     name (import checked first), `demname` is that name demangled. On
//     every fixture available (radare2's own Windows PE build artifacts),
//     every single reloc has a real import name and `demname` never differs
//     (C linkage only, nothing to demangle) -- recorded as a scope limit on
//     the *available fixtures*, not assumed universal; a reloc targeting an
//     unnamed relative fixup (no import, no symbol) would read NULL for
//     both, and this table must handle that path even though it was never
//     observed live.
//   - `type` is `bin_reloc_type_name`: `(reloc->additive ? "ADD_" :
//     "SET_")` + a bit-width suffix (1/2/4/8/16/24/32/48/64), or the
//     literal string `"UNKNOWN"` for a width outside that fixed set. NOT a
//     raw relocation-type enum -- always this rendered SET_*/ADD_*/UNKNOWN
//     string.
//   - `ntype` is the raw, FORMAT-SPECIFIC relocation type code
//     (`reloc->ntype`) straight from the object format's own relocation
//     directory (e.g. PE's `IMAGE_REL_BASED_*`, ELF's `R_<arch>_*`) --
//     its vocabulary is per-file-format and per-architecture, not a
//     portable r2xsql enum. Kept as a raw pass-through int for callers who
//     already know their target format's numbering, the same "give the raw
//     number, don't invent a translation table" call `syscalls.num` makes.
//   - `sym_va`: present ONLY when the reloc resolved through a genuine
//     symbol (`reloc->symbol`, as opposed to an import) -- surfaced here as
//     `sym_vaddr`, NULL otherwise. Unexercised on every available fixture
//     (both are pure-import PE relocation tables) -- recorded as a scope
//     limit, not assumed populated.
//   - `is_ifunc`: always emitted (`pj_kb`, unconditional), `false` on every
//     available fixture (GNU IFUNC resolvers are an ELF-only mechanism;
//     both fixtures are PE) -- recorded as a scope limit, not assumed to
//     ever read `true` here.
//   - `reloc->addend` is READABLE on the C struct (used internally by the
//     NORMAL/plain-text render mode, e.g. `bin_reloc_size`) but is NEVER
//     emitted as a JSON key by `irj` -- confirmed by reading the
//     `IS_MODE_JSON` branch field-by-field. Deliberately NOT a column here,
//     the same call already made for `switch_tables.table_addr`: a command-
//     path-only table cannot expose a field its own command never prints,
//     and this table has no C-API producer (see below) to fill it from the
//     struct directly -- adding it would silently read NULL on every
//     backend forever, which is worse than omitting the column.
//
// No C-API producer: `irj` is already ONE full-scan command (confirmed
// while reading `bin_relocs` -- it is a single `r_crbtree_foreach` over
// `r_bin_get_relocs`'s tree, not an N-per-function/N-per-address loop), the
// same "already one command" shape `strings`/`sections`/`imports`/`entries`
// were found to have in `binary-meta-lab`. Per that lab's own conclusion,
// a JSON-round-trip port is only worth building when it removes an O(N)
// command-dispatch shape, not merely a parse step -- so this ships
// command-path-only on both backends, matching `syscalls`/
// `calling_conventions`/`classes` (all new-capability tables built this
// project session with no existing r2xsql history to port from).
//
// No pushdown: relocation tables are typically hundreds to low thousands of
// rows (95 on the stripped PE fixture, ~2000 on the real DLL) -- small
// enough for a full scan, the same size class `strings`/`imports` already
// accept without one.

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

struct RelocRow {
  int64_t                     addr  = 0;   // vaddr
  int64_t                     paddr = 0;
  std::string                 type;        // SET_*/ADD_*/UNKNOWN
  int64_t                     ntype = 0;   // raw, format-specific code
  std::optional<std::string>  name;
  std::optional<std::string>  demname;
  std::optional<int64_t>      sym_vaddr;
  bool                        is_ifunc = false;
};

}  // namespace

void register_relocs_table(Session& s) {
  auto def = xsql::cached_table<RelocRow>("relocs")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 512; })
    .cache_builder([be = s.backend_ptr()](std::vector<RelocRow>& rows) {
      auto arr = be->cmd_json("irj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        if (!j.is_object()) continue;
        RelocRow r;
        r.addr  = json_utils::i64(j, "vaddr");
        r.paddr = json_utils::i64(j, "paddr");
        r.type  = json_utils::str(j, "type");
        r.ntype = json_utils::i64(j, "ntype");
        if (auto it = j.find("name"); it != j.end() && it->is_string()) {
          r.name = it->get<std::string>();
        }
        if (auto it = j.find("demname"); it != j.end() && it->is_string()) {
          r.demname = it->get<std::string>();
        }
        if (auto it = j.find("sym_va"); it != j.end() && it->is_number_integer()) {
          r.sym_vaddr = it->get<int64_t>();
        }
        r.is_ifunc = json_utils::boolean(j, "is_ifunc");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",  [](const RelocRow& r) { return r.addr; })
    .column_int64("paddr", [](const RelocRow& r) { return r.paddr; })
    .column_text ("type",  [](const RelocRow& r) { return r.type; })
    .column_int64("ntype", [](const RelocRow& r) { return r.ntype; })
    .column_text_nullable("name",    [](const RelocRow& r) { return r.name; })
    .column_text_nullable("demname", [](const RelocRow& r) { return r.demname; })
    .column("sym_vaddr", xsql::ColumnType::Integer,
        [](xsql::FunctionContext& ctx, const RelocRow& r) {
          if (r.sym_vaddr) ctx.result_int64(*r.sym_vaddr);
          else ctx.result_null();
        })
    .column_int64("is_ifunc", [](const RelocRow& r) { return r.is_ifunc ? 1 : 0; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
