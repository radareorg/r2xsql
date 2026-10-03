// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// locals — per-function local variables and arguments via `afvj @ <func_addr>`.
// One row per variable, keyed on (func_addr, name). Two columns are writable:
//   * name  → rename via `afvn <new> <old> @ <func_addr>`
//   * type  → retype via `afvt <name> <type> @ <func_addr>`
// r2 reflects a rename/retype immediately on the next read, so there is nothing
// to batch: the table is a plain no_shared_cache table (no commit hook — r2xsql
// declined the libxsql commit hook for exactly this reason).
//
//
//

#include <cctype>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <r_util.h>
#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::LocalRow;

// Render the storage reference: a reg var's "ref" is a plain register string
// ("rcx"); a stack/spv var's "ref" is an object {base, offset} → "rsp+0x20"
// or "rsp-0x20".
std::string storage_ref_of(const nlohmann::json& v) {
  auto it = v.find("ref");
  if (it == v.end() || it->is_null()) return {};
  if (it->is_string()) return it->get<std::string>();
  if (it->is_object()) {
    const std::string base = json_utils::str(*it, "base");
    const int64_t off = json_utils::i64(*it, "offset");
    if (base.empty()) return {};
    char buf[48];
    if (off < 0) {
      const uint64_t magnitude = uint64_t{0} - static_cast<uint64_t>(off);
      std::snprintf(buf, sizeof(buf), "%s-0x%llx", base.c_str(),
                    static_cast<unsigned long long>(magnitude));
    } else {
      std::snprintf(buf, sizeof(buf), "%s+0x%llx", base.c_str(),
                    static_cast<unsigned long long>(off));
    }
    return std::string(buf);
  }
  return {};
}

// Flatten one afvj group ("reg" / "sp" / "bp") into LocalRows tagged with the
// owning function address and a coarse storage class.
void append_group(std::vector<LocalRow>& out, const nlohmann::json& obj,
                  const char* group_key, const char* storage, int64_t fa) {
  auto it = obj.find(group_key);
  if (it == obj.end() || !it->is_array()) return;
  for (const auto& v : *it) {
    LocalRow r;
    r.func_addr   = fa;
    r.name        = json_utils::str(v, "name");
    if (r.name.empty()) continue;
    r.kind        = json_utils::str(v, "kind");
    r.storage     = storage;
    r.storage_ref = storage_ref_of(v);
    r.type        = json_utils::str(v, "type");
    out.push_back(std::move(r));
  }
}

// All variables of a single function via one scoped `afvj @ <fa>`.
void append_locals_for_func(std::vector<LocalRow>& out, Backend* be, int64_t fa) {
  auto j = be->cmd_json("afvj @ " + json_utils::hex_addr(fa));
  if (!j.is_object()) return;
  append_group(out, j, "reg", "reg",   fa);   // register args/locals
  append_group(out, j, "sp",  "stack", fa);   // sp-relative stack vars
  append_group(out, j, "bp",  "spv",   fa);   // bp-relative stack vars
}

bool same_storage(const LocalRow& a, const LocalRow& b) {
  return a.func_addr == b.func_addr && a.kind == b.kind &&
         a.storage == b.storage && a.storage_ref == b.storage_ref;
}

std::string compact_type(std::string_view type) {
  std::string out;
  out.reserve(type.size());
  for (unsigned char c : type) {
    if (!std::isspace(c)) out.push_back(static_cast<char>(c));
  }
  return out;
}


bool local_readback_matches(Backend* be, const LocalRow& before,
                            const std::string& expected_name,
                            const std::string* expected_type = nullptr) {
  std::vector<LocalRow> current;
  append_locals_for_func(current, be, before.func_addr);
  for (const auto& row : current) {
    if (!same_storage(row, before) || row.name != expected_name) continue;
    if (!expected_type || compact_type(row.type) == compact_type(*expected_type)) {
      return true;
    }
  }
  return false;
}
}  // namespace

void register_locals_table(Session& s) {
  auto def = xsql::cached_table<LocalRow>("locals")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 4096; })
    .cache_builder([be = s.backend_ptr()](std::vector<LocalRow>& rows) {
      if (auto* api = be->direct()) {
        api->locals_scan(rows);
        return;
      }
      auto funcs = be->cmd_json("aflj");
      if (!funcs.is_array()) return;
      for (const auto& f : funcs) {
        append_locals_for_func(rows, be, json_utils::i64_addr(f));
      }
    })
    .column_int64("func_addr", [](const LocalRow& r) { return r.func_addr; })
    // Writable: UPDATE locals SET name='x' WHERE func_addr=F AND name='old'
    // renames the variable via `afvn <new> <old> @ <func_addr>`. r2 reflects
    // the rename immediately, so the next read returns the new name.
    .column_text_rw("name",
      [](const LocalRow& r) { return r.name; },
      [be = s.backend_ptr()](LocalRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!r_name_check(v)) {
          xsql::set_vtab_error(
              "locals: name must start with a letter, '_' or ':' and use only [A-Za-z0-9._:]");
          return false;
        }
        if (!r_name_check(r.name.c_str())) {
          xsql::set_vtab_error(
              "locals: existing name contains r2 command metacharacters");
          return false;
        }
        if (r.name == v) return true;
        const std::string old_name = r.name;
        if (auto* api = be->direct()) {
          if (!api->var_rename(r.func_addr, r.name, v)) {
            xsql::set_vtab_error("locals: rename failed (func_addr=" +
                                 json_utils::hex_addr(r.func_addr) + ", name=" +
                                 r.name + "): variable not found or name rejected");
            return false;
          }
        } else {
          std::string out = be->cmd_noeval(r.func_addr,
                                           std::string("afvn ") + v + " " + r.name);
          if (std::string e = table_utils::command_error_text(out); !e.empty()) {
            xsql::set_vtab_error("locals: rename failed (func_addr=" +
                                 json_utils::hex_addr(r.func_addr) + ", name=" +
                                 r.name + "): " + e);
            return false;
          }
        }
        if (!local_readback_matches(be, r, v)) {
          xsql::set_vtab_error("locals: rename was not reflected by afvj "
                               "(func_addr=" + json_utils::hex_addr(r.func_addr) +
                               ", old_name=" + old_name + ")");
          return false;
        }
        r.name = v;
        return true;
      })
    .column_text("kind",        [](const LocalRow& r) { return r.kind; })
    .column_text("storage",     [](const LocalRow& r) { return r.storage; })
    .column_text("storage_ref", [](const LocalRow& r) { return r.storage_ref; })
    // Writable: UPDATE locals SET type='int' WHERE ... retypes the variable via
    // `afvt <name> <type> @ <func_addr>`. r2 accepts a bare (unquoted) type,
    // including a spaced `char *`; wrapping it in quotes would store the quotes
    // literally, so we validate and pass it verbatim.
    .column_text_rw("type",
      [](const LocalRow& r) { return r.type; },
      [be = s.backend_ptr()](LocalRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_type_text(v)) {
          xsql::set_vtab_error(
              "locals: type contains an r2 metacharacter (@ ; | ` \" $ etc.)");
          return false;
        }
        if (!r_name_check(r.name.c_str())) {
          xsql::set_vtab_error(
              "locals: existing name contains r2 command metacharacters");
          return false;
        }
        const std::string expected_type = v;
        if (compact_type(r.type) == compact_type(expected_type)) return true;
        if (auto* api = be->direct()) {
          if (!api->var_set_type(r.func_addr, r.name, v)) {
            xsql::set_vtab_error("locals: retype failed (func_addr=" +
                                 json_utils::hex_addr(r.func_addr) + ", name=" +
                                 r.name + "): variable not found");
            return false;
          }
        } else {
          std::string out = be->cmd_noeval(r.func_addr,
                                           std::string("afvt ") + r.name + " " + v);
          if (std::string e = table_utils::command_error_text(out); !e.empty()) {
            xsql::set_vtab_error("locals: retype failed (func_addr=" +
                                 json_utils::hex_addr(r.func_addr) + ", name=" +
                                 r.name + "): " + e);
            return false;
          }
        }
        if (!local_readback_matches(be, r, r.name, &expected_type)) {
          xsql::set_vtab_error("locals: retype was not reflected by afvj "
                               "(func_addr=" + json_utils::hex_addr(r.func_addr) +
                               ", name=" + r.name + ")");
          return false;
        }
        r.type = v;
        return true;
      })
    .column_int64("size", [](const LocalRow& r) { return r.size; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
