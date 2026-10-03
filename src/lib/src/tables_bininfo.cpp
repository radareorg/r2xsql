// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "tables.hpp"
#include "table_sources.hpp"

namespace r2xsql {

namespace {

struct BininfoRow {
  std::optional<std::string> file;
  std::string                format;      // iIj "bintype" (RBinInfo::rclass)
  std::string                arch;
  std::optional<std::string> cpu;
  int64_t                    bits = 0;
  std::optional<std::string> os;
  std::optional<std::string> machine;
  std::string                endian;
  std::optional<std::string> lang;
  std::string                bin_class;   // iIj "class" (RBinInfo::bclass)
  std::optional<std::string> subsystem;
  std::string                compiler;
  int64_t                    baddr = 0;
  std::optional<int64_t>     has_va;
  std::optional<int64_t>     has_nx;
  int64_t                    has_canary = 0;
  std::optional<int64_t>     has_pi;
  std::optional<std::string> default_cc;
};

using Info = std::map<std::string, std::string>;

std::optional<std::string> opt_str(const Info& info, const char* key) {
  auto it = info.find(key);
  if (it != info.end() && !it->second.empty()) return it->second;
  return std::nullopt;
}

std::optional<int64_t> opt_bool01(const Info& info, const char* key) {
  auto it = info.find(key);
  if (it == info.end()) return std::nullopt;
  return it->second == "true" ? 1 : 0;
}
}  // namespace

void register_bininfo_table(Session& s) {
  auto def = xsql::cached_table<BininfoRow>("bininfo")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1; })
    .cache_builder([be = s.backend_ptr()](std::vector<BininfoRow>& rows) {
      Info info;
      for (const auto& row : table_sources::binary_info(be)) info[row.key] = row.value;
      if (info.empty()) return;

      BininfoRow r;
      r.format     = info["bintype"];
      r.arch       = info["arch"];
      r.cpu        = opt_str(info, "cpu");
      r.bits       = info.count("bits") ? static_cast<int64_t>(std::stoull(info["bits"])) : 0;
      r.os         = opt_str(info, "os");
      r.machine    = opt_str(info, "machine");
      r.endian     = info["endian"];
      r.lang       = opt_str(info, "lang");
      r.bin_class  = info["class"];
      r.subsystem  = opt_str(info, "subsys");
      r.compiler   = info["compiler"];
      r.baddr      = info.count("baddr") ? static_cast<int64_t>(std::stoull(info["baddr"])) : 0;
      r.has_va     = opt_bool01(info, "va");
      r.has_nx     = opt_bool01(info, "nx");
      r.has_canary = info["canary"] == "true" ? 1 : 0;
      r.has_pi     = opt_bool01(info, "pic");
      r.default_cc = opt_str(info, "cc");

      // No file is SQL NULL, not '' -- the same "unknown reads NULL" contract
      // the havecode-gated columns keep.
      if (auto path = table_sources::file_path(be); !path.empty()) r.file = std::move(path);

      rows.push_back(std::move(r));
    })
    .column_text_nullable("file",      [](const BininfoRow& r) { return r.file; })
    .column_text("format",             [](const BininfoRow& r) { return r.format; })
    .column_text("arch",               [](const BininfoRow& r) { return r.arch; })
    .column_text_nullable("cpu",       [](const BininfoRow& r) { return r.cpu; })
    .column_int64("bits",              [](const BininfoRow& r) { return r.bits; })
    .column_text_nullable("os",        [](const BininfoRow& r) { return r.os; })
    .column_text_nullable("machine",   [](const BininfoRow& r) { return r.machine; })
    .column_text("endian",             [](const BininfoRow& r) { return r.endian; })
    .column_text_nullable("lang",      [](const BininfoRow& r) { return r.lang; })
    .column_text("class",              [](const BininfoRow& r) { return r.bin_class; })
    .column_text_nullable("subsystem", [](const BininfoRow& r) { return r.subsystem; })
    .column_text("compiler",           [](const BininfoRow& r) { return r.compiler; })
    .column_int64("baddr",             [](const BininfoRow& r) { return r.baddr; })
    .column_int_nullable("has_va", [](const BininfoRow& r) -> std::optional<int> {
        if (!r.has_va) return std::nullopt;
        return static_cast<int>(*r.has_va);
      })
    .column_int_nullable("has_nx", [](const BininfoRow& r) -> std::optional<int> {
        if (!r.has_nx) return std::nullopt;
        return static_cast<int>(*r.has_nx);
      })
    .column_int64("has_canary",        [](const BininfoRow& r) { return r.has_canary; })
    .column_int_nullable("has_pi", [](const BininfoRow& r) -> std::optional<int> {
        if (!r.has_pi) return std::nullopt;
        return static_cast<int>(*r.has_pi);
      })
    .column_text_nullable("default_cc", [](const BininfoRow& r) { return r.default_cc; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
