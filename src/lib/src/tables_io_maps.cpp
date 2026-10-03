// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// io_maps — read and mutate the live address space through RIO.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::IoMapRow;

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
      auto* api = be->direct();
      if (!api || !api->io_map_delete(r.map_id)) {
        xsql::set_vtab_error("io_maps: DELETE failed (map_id=" +
                             std::to_string(r.map_id) + ")");
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
      }
      int64_t paddr = 0;
      if (argc > 4 && !argv[4].is_null() &&
          !table_utils::exact_write_int64(argv[4], "io_maps: paddr", paddr)) {
        return false;
      }
      auto* api = be->direct();
      const uint64_t size = static_cast<uint64_t>(end) - static_cast<uint64_t>(start);
      if (!api || !api->io_map_create(start, size, paddr, perm, name)) {
        xsql::set_vtab_error("io_maps: INSERT failed (check a file is open)");
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
