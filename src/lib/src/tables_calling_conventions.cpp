// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// calling_conventions — a static per-(arch,bits) calling-convention
// reference table, backed by `afclj` (cmd_type.inc.c's cmd_afcl, dispatched
// through cmd_tcc), which iterates `core->anal->sdb_cc`. That is the exact
// same SDB `funcs.calltype`/`funcs.stackframe` are already driven by: this
// table and those two columns describe the same underlying radare2 state
// from two angles (the full convention definition vs. which one a specific
// function was assigned). Both were affected by the project's data-dir
// cliff -- an in-process consumer not run from the analysis engine's own
// install location silently loaded a synthetic single-entry fallback
// convention (name "reg", built straight from the register profile) instead
// of the real per-arch table, with no log signal to detect it -- and that
// gap has since been closed for this SDB by an explicit cache-busting reload
// keyed off the build's own configured prefix. If a future regression ever
// reopens it, this table degrades the same way `funcs.calltype` used to:
// exactly one row named "reg", not zero rows.
//
// The whole convention set is small (typically single digits on a real
// target) and is process-global static data for the session's (arch,bits) --
// nothing in this table's own surface, or anywhere else in r2xsql, adds,
// removes, or edits a calling-convention definition, so it is safe (and
// cheap) to use the default shared cache rather than re-issuing `afclj`
// every query (contrast `classes`/`types`, which opt out because their
// backing state genuinely can change mid-session).
//
// Field shape, read directly from `core_anal_cc_json` (cmd_type.inc.c) and
// `r_anal_cc_argloc`/`r_anal_cc_ret` (libr/anal/cc.c), not assumed:
//
//   - `args`: one entry per explicitly named argument-position register
//     (`cc.<name>.arg0`, `arg1`, ...), in position order.
//   - `ret` / `rets`: `ret` is `r_anal_cc_ret(anal, cc, 0)` -- the FIRST
//     return-value location. `rets` is the full list (`ret0`, `ret1`, ...).
//     These are NOT always redundant: most conventions define only `ret0`,
//     but a genuine multi-return-register convention (e.g. `dlang` on x86,
//     which returns a second value in `rdx`/`edx` per `cc.dlang.ret1` in
//     radare2's own SDB source) has `rets` carry more entries than the
//     single `ret` column -- don't drop `rets` as "just `ret` restated".
//   - `argn`: NOT an argument value, and not a count despite the name.
//     `r_anal_cc_argloc(anal, cc, max_arg, 0, -1)` queries the SDB key
//     `cc.<name>.argn` -- the location for every argument PAST the last
//     explicitly named position (`args[N-1]`), i.e. "where do the overflow
//     arguments go". `r_anal_cc_argloc` runs that raw SDB value through
//     `dyncc_from_static_loc`, which is why the worked example reads
//     `"argn":"^"` rather than the SDB source's literal `stack`: `stack` ->
//     `^` (ascending stack), `stack_rev` -> `^-` (descending/reversed stack
//     push order), and a plain register name (rare; some non-x86 ABIs reuse
//     a register for overflow args) passes through unchanged. Empty/NULL
//     means the convention defines no args past its named positions (every
//     argument has its own explicit slot).
//   - `signature`: deliberately NOT surfaced as a column here. It is
//     `core_anal_cc_json`'s one rendered-text field (`r_anal_cc_get`'s
//     pretty-printed "ret name (arg0, arg1, ..., argn);" form) -- the same
//     rendered-vs-structured split `funcs.prototype` documents against
//     `funcs`'s other columns: display text radare2's own renderer already
//     produced, redundant with the structured `args`/`ret`/`rets`/`argn`
//     fields already on offer here, not something to re-parse for the same
//     values.
//
// No pushdown: the whole table is small and cheap (one `afclj` call,
// already-loaded SDB), so a full scan is a real, bounded answer.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"

namespace r2xsql {

namespace {

struct CallingConventionRow {
  std::string                name;
  std::vector<std::string>   args;
  std::optional<std::string> ret;
  std::vector<std::string>   rets;
  std::optional<std::string> argn;
};

std::string join_comma(const std::vector<std::string>& parts) {
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) out += ',';
    out += parts[i];
  }
  return out;
}

}  // namespace

void register_calling_conventions_table(Session& s) {
  auto def = xsql::cached_table<CallingConventionRow>("calling_conventions")
    .estimate_rows([]() -> size_t { return 16; })
    .cache_builder([be = s.backend_ptr()](std::vector<CallingConventionRow>& rows) {
      // `afclj` emits a JSON OBJECT keyed by convention name (cmd_afcl wraps
      // the whole thing in pj_o()/pj_ko(pj, cc)), unlike most r2xsql sources,
      // which are arrays.
      auto obj = be->cmd_json("afclj");
      if (!obj.is_object()) return;
      rows.reserve(obj.size());
      for (auto& [name, cc] : obj.items()) {
        if (!cc.is_object()) continue;
        CallingConventionRow r;
        r.name = name;

        if (auto it = cc.find("ret"); it != cc.end() && it->is_string()) {
          r.ret = it->get<std::string>();
        }
        if (auto it = cc.find("rets"); it != cc.end() && it->is_array()) {
          for (auto& e : *it) {
            if (e.is_string()) r.rets.push_back(e.get<std::string>());
          }
        }
        if (auto it = cc.find("args"); it != cc.end() && it->is_array()) {
          for (auto& e : *it) {
            if (e.is_string()) r.args.push_back(e.get<std::string>());
          }
        }
        if (auto it = cc.find("argn"); it != cc.end() && it->is_string()) {
          r.argn = it->get<std::string>();
        }

        rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const CallingConventionRow& r) { return r.name; })
    .column_text("args", [](const CallingConventionRow& r) { return join_comma(r.args); })
    .column_text_nullable("ret", [](const CallingConventionRow& r) { return r.ret; })
    .column_text("rets", [](const CallingConventionRow& r) { return join_comma(r.rets); })
    .column_text_nullable("argn", [](const CallingConventionRow& r) { return r.argn; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
