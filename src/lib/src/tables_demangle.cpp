// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// demangle -- one row for an arbitrary mangled name. Demangling always uses
// r_bin_demangle through the in-process direct::Api.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"

namespace r2xsql {

namespace {

struct DemangleRow {
  std::string demangled;  // empty iff demangling failed (never a legitimate
                           // empty symbol name)
  std::string error;      // empty iff demangled is non-empty
};

enum Col { kDemangled = 0, kError = 1, kMangled = 2, kLang = 3 };

DemangleRow run_demangle(Backend* be, const std::string& mangled,
                          const std::string& lang) {
  DemangleRow row;
  if (mangled.empty()) {
    row.error = "demangle: mangled must not be empty";
    return row;
  }
  auto* api = be->direct();
  if (!api) {
    row.error = "demangle requires the in-process libr backend";
    return row;
  }
  row.demangled = api->demangle(mangled, lang, row.error);
  if (!row.demangled.empty()) row.error.clear();
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
