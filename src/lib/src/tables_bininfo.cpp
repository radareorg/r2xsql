// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// bininfo -- one-row, typed binary-metadata summary (architecture/format/OS
// facts plus mitigation flags), sourced from `iIj` (`bin_info`,
// libr/core/cbin.c) -- the SAME command the `binary` key/value table already
// issues generically. This is an EXTENSION of that existing data, not a new
// radare2 capability: `binary`'s generic per-key loop already carries these
// same facts as TEXT rows (`key='nx'`/`'canary'`/`'pic'`/`'va'`, among
// others). This table reshapes the identical `iIj` JSON into a typed,
// single-row, wide surface for the "first question an analyst asks" query
// shape (`SELECT has_nx, has_canary, has_pi FROM bininfo`), which the
// key/value shape cannot answer in one row.
//
// Verified against the CURRENT radare2 source rather than trusted from a
// citation's C-struct field names. `RBinInfo` (libr/include/r_bin.h) does
// carry `has_va`/`has_pi`/`has_canary`/`has_nx` as its own field spellings,
// but `bin_info()` (libr/core/cbin.c), the handler behind `iIj`, renames
// three of them on the wire: struct `has_nx` -> JSON key "nx", struct
// `has_pi` -> JSON key "pic", struct `has_va` -> JSON key "va"; only
// `has_canary` keeps its struct spelling as JSON "canary". This table's own
// column names follow the struct's boolean-predicate spelling
// (`has_nx`/`has_pi`/`has_canary`/`has_va`) since that reads better as a SQL
// predicate column (the same "has_/is_" convention `funcs.is_pure`/
// `xrefs.is_code` already use elsewhere in this project) -- the JSON-key
// rename is purely a source-mapping detail, invisible to SQL callers.
//
// One might expect an `rclass` column distinct from `format`. Verified that
// does NOT hold up on the command path:
// `bin_info()` emits exactly ONE JSON key for `RBinInfo::rclass` ("bintype",
// the value this table calls `format`) and a SEPARATE key for
// `RBinInfo::bclass` ("class"), but NEVER a key for `RBinInfo::type` (the
// field the `format` column reads, straight off the C struct). Since
// this table is command-path-only (see below -- no C-API producer, so both
// backends share the identical JSON), it cannot manufacture a THIRD, distinct
// value command-path JSON never emits without the two backends structurally
// disagreeing on it -- so `rclass`/`type` is deliberately dropped rather than
// duplicating `format` under a second name or a name libr alone could answer.
//
// `os`/`machine`/`lang`/`subsystem`/`default_cc`/`has_nx`/`has_pi`/`has_va`
// are emitted by `bin_info()` only when the file looks executable or has
// entries (its own internal `havecode` gate) -- on a non-executable input
// (e.g. a filesystem image) these read SQL NULL rather than a guessed
// default. `has_canary` is NOT behind that gate (`bin_info()` emits it
// unconditionally whenever there is a loaded bin), so it is always a real
// 0/1, never NULL.
//
// `file` is read the same way `binary`'s own `file` row already is (a second
// `ij` call -> `core.file`) -- matching that table's existing two-command
// shape rather than inventing a third source.
//
// Unlike `binary` (which always emits identity/version rows even with
// nothing loaded), this table emits NO row at all when `iIj` reports no bin
// (empty JSON object) -- an honest empty table, the same "no data yet ==
// empty, not a row of blanks" contract `relocs`/`registers`/`libs` already
// use.
//
// No C-API producer: like `syscalls`/`calling_conventions`/`classes`/
// `registers`/`relocs`/`libs`, this is already ONE full-scan-equivalent
// command pair (`iIj` + `ij`) with no N-per-row shape to collapse -- ships
// command-path-only on both backends, so pipe and libr structurally cannot
// disagree.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

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

std::optional<std::string> opt_str(const nlohmann::json& obj, const char* key) {
  if (obj.contains(key) && obj[key].is_string()) {
    auto v = obj[key].get<std::string>();
    if (!v.empty()) return v;
  }
  return std::nullopt;
}

std::optional<int64_t> opt_bool01(const nlohmann::json& obj, const char* key) {
  if (obj.contains(key) && obj[key].is_boolean())
    return obj[key].get<bool>() ? 1 : 0;
  return std::nullopt;
}

}  // namespace

void register_bininfo_table(Session& s) {
  auto def = xsql::cached_table<BininfoRow>("bininfo")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 1; })
    .cache_builder([be = s.backend_ptr()](std::vector<BininfoRow>& rows) {
      auto info = be->cmd_json("iIj");
      if (!info.is_object() || info.empty()) return;  // no bin loaded

      BininfoRow r;
      r.format     = json_utils::str(info, "bintype");
      r.arch       = json_utils::str(info, "arch");
      r.cpu        = opt_str(info, "cpu");
      r.bits       = json_utils::i64(info, "bits");
      r.os         = opt_str(info, "os");
      r.machine    = opt_str(info, "machine");
      r.endian     = json_utils::str(info, "endian");
      r.lang       = opt_str(info, "lang");
      r.bin_class  = json_utils::str(info, "class");
      r.subsystem  = opt_str(info, "subsys");
      r.compiler   = json_utils::str(info, "compiler");
      r.baddr      = json_utils::i64(info, "baddr");
      r.has_va     = opt_bool01(info, "va");
      r.has_nx     = opt_bool01(info, "nx");
      r.has_canary = json_utils::boolean(info, "canary") ? 1 : 0;
      r.has_pi     = opt_bool01(info, "pic");
      r.default_cc = opt_str(info, "cc");

      // file (ij -> core.file), the same second call `binary` already makes.
      auto j = be->cmd_json("ij");
      if (j.is_object() && j.contains("core") && j["core"].is_object()) {
        auto& core = j["core"];
        if (core.contains("file") && core["file"].is_string())
          r.file = core["file"].get<std::string>();
      }

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
