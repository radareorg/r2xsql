// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// demangle -- one-row-per-query demangler over radare2's `iD`/`iDj` (verified
// against the CURRENT radare2 source, `libr/core/cmd_info.inc.c`'s
// `cmd_info_demangle` + `libr/bin/demangle.c`'s `r_bin_demangle`/
// `r_bin_demangle_type`, not assumed from a citation). This closes a REAL
// gap: `funcs.name` and `imports.name` already demangle automatically (via
// `r_core_anal_fcn_name`/`r_bin_demangle` respectively, gated on the
// `bin.demangle` config) for symbols radare2 already knows about from the
// loaded binary, but there was no SQL surface to demangle an ARBITRARY
// string that isn't necessarily any table's row.
//
// The `mangled` hidden input is NOT charset-restricted the way
// `assemble`/`search_asm`'s `asm` input is (see tables_assemble.cpp):
// real-world manglings routinely use characters a disassembly-text
// allowlist would reject -- MSVC uses `?`/`@`/`$` throughout
// (`?foo@@YAHXZ`), Rust and Itanium C++ use `$`-escaped substitutions
// heavily. So this table uses the SAME structural no-eval dispatch
// (Backend::cmd_noeval) `types`' `td` already pilots
// for an addr-less command with a genuinely unrestrictable free-text
// argument -- verified live (not assumed) that the injection risk is real:
// `iDj cxx foo; ?e INJECTED` through a plain `Backend::cmd()` splice DOES
// execute the injected `?e` as a second command (radare2's own `;`
// chaining), while `cmd_noeval` reaches `iD`'s single argument parser with
// the whole string, `;` included, treated as opaque data.
//
// `iD`/`iDj` carries no address in its own grammar at all (same shape as
// `td`/`t-`), so this dispatches seeked to a fixed anchor (0, same constant
// choice as `table_utils::kTypeSystemAnchorAddr` -- kept as a small local
// copy rather than reusing that name directly, since this table has nothing
// to do with the type system; the anchor value is arbitrary and unobserved
// by `iD`'s handler either way, verified against `cmd_info_demangle`, which
// reads only its own `lang`/`text` arguments, never `core->addr`).
//
// `lang` is passed through UNVALIDATED against radare2's own known-language
// list: verified live that `r_bin_demangle_type()` returning
// `R_BIN_LANG_NONE` for an unrecognized string does NOT abort the call --
// `cmd_info_demangle` still invokes `r_bin_demangle(bf, lang, text, ...)`,
// which runs its OWN auto-detection from the mangled text's prefix
// (`_Z`/`__Z`/`?`/...) regardless of what `lang` said. So a caller-supplied
// `lang` is always advisory, never validated client-side to match; this
// table simply forwards it and lets radare2 do what it already does.
//
// `iDj`'s own JSON always echoes `lang` back VERBATIM (the input string,
// not radare2's actually-auto-detected type) -- confirmed live with
// `iDj bogus _ZN3Foo3barEv`, which still demangled successfully via
// auto-detection while echoing `"lang":"bogus"`. This table does not
// surface that echo at all (mangled/lang are pure hidden inputs, never
// duplicated as output columns, matching byte_search's own
// pattern-is-hidden-only convention) precisely to avoid presenting that
// potentially-misleading echo as if it were the resolved demangler.
//
// No JSON mode exists for the empty-`text` or unparseable-argument cases
// either -- `iDj` still emits a well-formed `{"lang":...,"mangled":...,
// "error":"..."}` object in every failure mode exercised (empty text,
// non-mangled text, unrecognized lang), so `error` is always populated
// exactly when `demangled` is not, with no separate "malformed command"
// case to handle.
//
// Command-path-only, no C-API producer: a single demangle call has no N+1
// or full-scan cost shape to collapse (same "one full-scan-equivalent
// command, no per-row cost" reasoning `bininfo`/`rop_gadgets` already
// documented for themselves), so both backends share the identical
// command-based implementation and cannot disagree.

#include <cstdint>
#include <memory>
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

// Arbitrary, unobserved by `iD`'s handler (see file header) -- kept as a
// small local constant rather than reusing table_utils::kTypeSystemAnchorAddr
// so this table reads as self-contained, not borrowed from the type system.
constexpr int64_t kDemangleAnchorAddr = 0;

struct DemangleRow {
  std::string demangled;  // empty iff demangling failed (never a legitimate
                           // empty symbol name)
  std::string error;      // empty iff demangled is non-empty
};

enum Col { kDemangled = 0, kError = 1, kMangled = 2, kLang = 3 };

// Seeked-to-a-fixed-anchor no-eval dispatch for `iDj`, mirroring
// table_utils::dispatch_type_write's shape exactly (try cmd_noeval first,
// fall back to the r2_quote-wrapped plain command on every backend that
// reports it unsupported) -- a local copy, not a shared call, since this
// table's anchor and command shape are its own (see file header).
std::string dispatch_demangle(Backend* be, const std::string& noeval_command,
                               const std::string& fallback_command) {
  std::string out;
  if (be->cmd_noeval(kDemangleAnchorAddr, noeval_command, &out)) return out;
  return be->cmd(fallback_command);
}

DemangleRow run_demangle(Backend* be, const std::string& mangled,
                          const std::string& lang) {
  DemangleRow row;
  if (mangled.empty()) {
    row.error = "demangle: mangled must not be empty";
    return row;
  }
  // Two-arg form when lang is given ("iDj <lang> <mangled>"), single-arg
  // form otherwise ("iDj <mangled>", radare2 defaults lang from its own
  // bin.lang config) -- matches iD's own grammar (see file header); this
  // table never synthesizes a placeholder lang token to keep the shapes
  // separate, since args="" lang would misparse a mangled name containing
  // its own leading space.
  const std::string plain =
      lang.empty() ? ("iDj " + mangled) : ("iDj " + lang + " " + mangled);
  const std::string out = dispatch_demangle(be, plain, json_utils::r2_quote(plain));

  nlohmann::json j = nlohmann::json::parse(out, nullptr, false);
  if (j.is_discarded() || !j.is_object()) {
    row.error = "demangle: radare2 returned no result (iDj produced no "
                "parseable output)";
    return row;
  }
  if (j.contains("error") && j["error"].is_string()) {
    row.error = j["error"].get<std::string>();
    return row;
  }
  row.demangled = json_utils::str(j, "demangled");
  if (row.demangled.empty()) {
    row.error = "demangle: radare2 produced neither a demangled name nor an "
                "error (unexpected iDj shape)";
  }
  return row;
}

class DemangleGen : public xsql::Generator<DemangleRow> {
  DemangleRow row_;
  bool served_ = false;
 public:
  explicit DemangleGen(DemangleRow row) : row_(std::move(row)) {}
  bool next() override {
    if (served_) return false;
    served_ = true;
    return true;
  }
  const DemangleRow& current() const override { return row_; }
  int64_t rowid() const override { return 0; }
};

}  // namespace

void register_demangle_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<DemangleRow>> {
    std::string mangled, lang;
    for (const auto& a : args) {
      if (a.op != xsql::ConstraintOp::Eq) continue;
      switch (a.column_index) {
        case kMangled: { const char* v = a.value.as_c_str(); if (v) mangled = v; break; }
        case kLang:    { const char* v = a.value.as_c_str(); if (v) lang = v; break; }
        default: break;
      }
    }
    if (mangled.empty()) {
      xsql::set_vtab_error("demangle requires WHERE mangled = '<mangled name>'");
      return std::make_unique<DemangleGen>(DemangleRow{});
    }
    return std::make_unique<DemangleGen>(run_demangle(be, mangled, lang));
  };

  auto def = xsql::generator_table<DemangleRow>("demangle")
    .estimate_rows([]() -> size_t { return 1; })
    .column_text("demangled", [](const DemangleRow& r) { return r.demangled; })
    .column_text("error",     [](const DemangleRow& r) { return r.error; })
    .hidden_column_text("mangled")
    .hidden_column_text("lang")
    .full_scan_error(
        "demangle requires WHERE mangled = '<mangled name>' "
        "(demangled is an output column, not the input)")
    .constraint_filter(
        {xsql::required_eq("mangled",
             "demangle requires WHERE mangled = '<mangled name>'"),
         xsql::optional_eq("lang")},
        make_gen, 1.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
