// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// io_maps — radare2 IO maps (`omj`). This is r2's *writable* memory map: the
// read-only `segments`/`sections` tables come from the binary headers, whereas
// IO maps are the live address space you can add to, rebase, and remove.
//   read   : `omj`
//   insert : `om $d <vaddr> <size> <paddr> <perm> [name]`
//   delete : `om-<map_id>`
// Adding/removing an IO map round-trips through `omj` immediately.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include <r_util.h>
#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::IoMapRow;

// Build `om $d <vaddr> <size> <paddr> <perm> [name]` from an IO-map row spec.
std::string make_om_command(int64_t start, int64_t end, int64_t paddr,
                            const std::string& perm, const std::string& name) {
  const int64_t size = end - start;
  std::string cmd = "om $d " + json_utils::hex_addr(start) + " " +
                    json_utils::hex_addr(size) + " " + json_utils::hex_addr(paddr);
  if (!perm.empty()) cmd += " " + perm;
  if (!name.empty()) cmd += (perm.empty() ? " rwx " : " ") + name;
  return cmd;
}
}  // namespace

void register_io_maps_table(Session& s) {
  auto def = xsql::cached_table<IoMapRow>("io_maps")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, direct::Collection::Maps, "om~?", 64);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<IoMapRow>& rows) {
      if (auto* api = be->direct()) {
        api->io_maps_scan(rows);
        return;
      }
      auto arr = be->cmd_json("omj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        IoMapRow r;
        r.start_addr = json_utils::i64(j, "from");
        r.end_addr   = json_utils::i64(j, "to") + 1;  // r2 "to" is inclusive
        r.paddr         = json_utils::i64(j, "delta");
        r.map_id        = json_utils::i64(j, "map");
        r.fd            = json_utils::i64(j, "fd");
        r.perm          = json_utils::str(j, "perm");
        r.name          = json_utils::str(j, "name");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("start_addr", [](const IoMapRow& r) { return r.start_addr; })
    .column_int64("end_addr",   [](const IoMapRow& r) { return r.end_addr; })
    .column_text ("perm",          [](const IoMapRow& r) { return r.perm; })
    .column_text ("name",          [](const IoMapRow& r) { return r.name; })
    .column_int64("paddr",         [](const IoMapRow& r) { return r.paddr; })
    .column_int64("map_id",        [](const IoMapRow& r) { return r.map_id; })
    .column_int64("fd",            [](const IoMapRow& r) { return r.fd; })
    .deletable([be = s.backend_ptr()](IoMapRow& r) -> bool {
      std::string out = be->cmd("om-" + std::to_string(r.map_id));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("io_maps: DELETE failed (map_id=" +
                             std::to_string(r.map_id) + "): " + e);
        return false;
      }
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns: start_addr(0), end_addr(1), perm(2), name(3), paddr(4),
      //          map_id(5, output), fd(6, output).
      if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
        xsql::set_vtab_error("io_maps: INSERT requires start_addr and end_addr");
        return false;
      }
      int64_t start = 0, end = 0;
      if (!table_utils::exact_write_int64(argv[0], "io_maps: start_addr", start) ||
          !table_utils::exact_write_int64(argv[1], "io_maps: end_addr", end)) {
        return false;
      }
      if (end <= start) {
        xsql::set_vtab_error("io_maps: end_addr must be > start_addr");
        return false;
      }
      std::string perm = (argc > 2 && !argv[2].is_null()) ? argv[2].as_c_str() : "rwx";
      if (!json_utils::valid_perm(perm)) {
        xsql::set_vtab_error("io_maps: perm must be [rwx-] only (e.g. rwx, r-x)");
        return false;
      }
      std::string name;
      if (argc > 3 && !argv[3].is_null()) {
        name = argv[3].as_c_str();
        if (!name.empty() && !r_name_check(name.c_str())) {
          xsql::set_vtab_error("io_maps: name must start with a letter, '_' or ':' and use only [A-Za-z0-9._:]");
          return false;
        }
      }
      int64_t paddr = 0;
      if (argc > 4 && !argv[4].is_null() &&
          !table_utils::exact_write_int64(argv[4], "io_maps: paddr", paddr)) {
        return false;
      }
      std::string out = be->cmd(make_om_command(start, end, paddr, perm, name));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("io_maps: INSERT failed (check a file is open and "
                             "$d resolves to a valid fd): " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
