// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// registers -- a static per-(arch,bits) register PROFILE reference table,
// backed by `arpj` (cmd_debug.inc.c, case 'j' under the shared "dr"/"ar"
// prefix routing -- the comment there literally reads `// "drpj" .. dup from
// "arpj"`). This is NOT `arj`'s live register VALUES: `arj` was checked
// first and confirmed to exist, but it prints the CURRENT machine-state
// register contents (`{"rax":0,"rbx":0,...}`), which read back as all-zero
// on every fixture because r2xsql is a static-analysis tool -- it never runs
// the target, so there is no live CPU state to report. Building a table on
// top of `arj` would therefore always read as zero/garbage, not a useful
// surface. `arpj` is the correct source instead: the register PROFILE (which
// registers exist, their name/size/bit-offset/kind), a portable per-arch
// fact with zero dependency on execution, the same "static reference, not
// live occurrence" shape `syscalls`/`calling_conventions` already ship.
//
// Verified directly against `cmd_debug.inc.c`'s case 'j' handler, not
// assumed:
//
//   pj_k(pj, "reg_info"); for (i = 0; i < R_REG_TYPE_LAST; i++)
//     r_list_foreach(core->dbg->reg->regset[i].regs, iter, ri) { ... }
//
// `regset[i].regs` is the list of registers WHOSE type already IS `i` --
// there is no "walk every type and re-list matching registers" step, so the
// per-type re-query pattern (`r_reg_get_list(reg, t)` called once per type,
// needing a "skip ri->type != t" dedupe) does NOT apply here.
// Confirmed empirically too: every `name` in a real `arpj` dump is unique
// across the whole `reg_info` array (zero duplicates on a real x86-64 PE
// fixture). **The dedupe idiom the roadmap flagged as "a real correctness
// detail to reimplement" turned out not to apply to this command source --
// it was only ever needed for a per-type re-query C-API walk, not for
// `arpj`'s single already-partitioned emission.** Documented here rather
// than silently dropped, since the roadmap explicitly called it out as an
// open risk.
//
// `role` is sourced from the SAME `arpj` payload's `alias_info` array --
// `{"role":N,"role_str":"PC","reg":"rip"}` entries mapping a register ROLE
// (program counter, stack pointer, frame pointer, argument slots A0-A7,
// return R0, syscall-number SN, ...) onto the underlying register NAME.
// A single physical register can carry more than one role on a real target
// (verified: x86-64's `rax` is tagged both "R0" (first return-location role)
// and "SN" (syscall-number role) at once) -- `role` joins every matching
// role_str with a comma, the same multi-value idiom `calling_conventions`
// already uses for `rets`/`args`, rather than picking one arbitrarily or
// adding a junction table for a handful of rows. A register with no alias
// role (nearly every sub-register width, e.g. `eax`/`ax`/`al`) reports NULL.
//
// No pushdown: the whole table is small (~130-140 rows on a real x86-64
// target) and cheap (the profile is compiled into the arch/anal plugin as a
// literal C string set at core-open time -- confirmed by reading the
// handler above, which walks `core->dbg->reg`'s already-built regsets, not
// any external file -- so, unlike `syscalls`/`calling_conventions`, this
// table has NO data-dir dependency to work around).
//
// `arch`/`bits` echo the session config (`asm.arch`/`asm.bits`) onto every
// row, the same informational idiom `syscalls` uses for `arch`/`os` --
// this table is inherently single-target per session, so these columns
// exist for readability/joins, not to disambiguate a cross-arch union.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {

struct RegisterRow {
  std::string                name;
  std::string                type;   // type_str: gpr | fpu | flg | seg | drx | vec128 | ...
  int64_t                    size   = 0;   // bits
  int64_t                    offset = 0;   // bit offset within radare2's internal
                                            // per-type register arena -- NOT a memory address
  std::optional<std::string> role;         // comma-joined alias role_str values, or NULL
  std::string                arch;
  std::string                bits;
};

}  // namespace

void register_registers_table(Session& s) {
  auto def = xsql::cached_table<RegisterRow>("registers")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 160; })
    .cache_builder([be = s.backend_ptr()](std::vector<RegisterRow>& rows) {
      const std::string arch = table_utils::trim_ascii(be->cmd("e asm.arch"));
      const std::string bits = table_utils::trim_ascii(be->cmd("e asm.bits"));

      auto obj = be->cmd_json("arpj");
      if (!obj.is_object()) return;

      // reg name -> comma-joined role_str list, built from alias_info first
      // so reg_info's single pass below can look each name up in O(1).
      std::unordered_map<std::string, std::string> roles_by_reg;
      if (auto ai = obj.find("alias_info"); ai != obj.end() && ai->is_array()) {
        for (auto& a : *ai) {
          if (!a.is_object()) continue;
          std::string reg = json_utils::str(a, "reg");
          std::string role_str = json_utils::str(a, "role_str");
          if (reg.empty() || role_str.empty()) continue;
          std::string& joined = roles_by_reg[reg];
          if (!joined.empty()) joined += ',';
          joined += role_str;
        }
      }

      auto ri = obj.find("reg_info");
      if (ri == obj.end() || !ri->is_array()) return;
      rows.reserve(ri->size());
      for (auto& j : *ri) {
        if (!j.is_object()) continue;
        RegisterRow r;
        r.name   = json_utils::str(j, "name");
        r.type   = json_utils::str(j, "type_str");
        r.size   = json_utils::i64(j, "size");
        r.offset = json_utils::i64(j, "offset");
        r.arch   = arch;
        r.bits   = bits;
        if (auto it = roles_by_reg.find(r.name); it != roles_by_reg.end()) {
          r.role = it->second;
        }
        rows.push_back(std::move(r));
      }
    })
    .column_text ("name",   [](const RegisterRow& r) { return r.name; })
    .column_text ("type",   [](const RegisterRow& r) { return r.type; })
    .column_int64("size",   [](const RegisterRow& r) { return r.size; })
    .column_int64("offset", [](const RegisterRow& r) { return r.offset; })
    .column_text_nullable("role", [](const RegisterRow& r) { return r.role; })
    .column_text ("arch",   [](const RegisterRow& r) { return r.arch; })
    .column_text ("bits",   [](const RegisterRow& r) { return r.bits; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
