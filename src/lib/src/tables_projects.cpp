// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// projects — radare2 project list (`Plj`). SELECT lists saved projects;
// DELETE FROM projects WHERE name='X' removes it on disk (`P- X`).
// Save and open projects with native `Ps <name>` and `P <name>` commands.

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
using direct::ProjectRow;
}  // namespace

void register_projects_table(Session& s) {
  auto def = xsql::cached_table<ProjectRow>("projects")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 32; })
    .cache_builder([be = s.backend_ptr()](std::vector<ProjectRow>& rows) {
      if (auto* api = be->direct()) {
        api->projects_scan(rows);
        return;
      }
      auto arr = be->cmd_json("Plj");
      if (!arr.is_array()) return;
      for (auto& j : arr) {
        ProjectRow r;
        if (j.is_string())      r.name = j.get<std::string>();
        else if (j.is_object()) r.name = json_utils::str(j, "name");
        if (!r.name.empty()) rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const ProjectRow& r) { return r.name; })
    .deletable([be = s.backend_ptr()](ProjectRow& r) -> bool {
      if (r.name.empty() || !r_name_check(r.name.c_str())) {
        xsql::set_vtab_error("projects: refusing to delete an unsafe/empty project name");
        return false;
      }
      // With scr.interactive on, P- asks "Confirm project deletion? (Y/n)" on
      // the console and the statement blocks on it (over =h, so does the
      // request). The DELETE is the confirmation, so answer it here.
      const std::string prior = table_utils::trim_ascii(be->cmd("e scr.interactive"));
      be->cmd("e scr.interactive=false");
      const std::string out = be->cmd("'P- " + r.name);
      be->cmd("e scr.interactive=" + (prior.empty() ? std::string("false") : prior));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        xsql::set_vtab_error("projects: DELETE failed (name=" + r.name + "): " + e);
        return false;
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
