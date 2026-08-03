// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>

#include <xsql/functions.hpp>

#include <regex>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

Session::Session(std::unique_ptr<Backend> backend) : backend_(std::move(backend)) {
  db_.open(":memory:");
  register_all_tables_();
  register_functions_();
  detect_decompiler_();
}

Session::~Session() = default;

xsql::Result Session::query(std::string_view sql) {
  std::lock_guard<std::mutex> lock(query_mu_);
  std::string s(sql);

  // Intercept `PRAGMA r2xsql.*` before handing SQL to SQLite: these are runtime
  // controls (query timeout, hints, the timeout stack), not table queries.
  xsql::Result pragma;
  if (handle_runtime_pragma_(s.c_str(), pragma)) {
    return pragma;
  }

  // Drive the per-query timeout from the runtime settings (mirrors idasql/bnsql:
  // libxsql installs a progress handler and surfaces timed_out on the Result).
  xsql::QueryOptions options;
  options.timeout_ms = runtime_settings_.query_timeout_ms();
  return db_.query(s, options);
}

namespace {

xsql::Result make_pragma_result(const std::string& name, const std::string& value) {
  xsql::Result r;
  r.columns = {"name", "value"};
  xsql::Row row;
  row.values = {name, value};
  r.rows.push_back(std::move(row));
  return r;
}

xsql::Result make_pragma_error(const std::string& error) {
  xsql::Result r;
  r.error = error;
  return r;
}

std::string declared_type_name(const std::string& declaration) {
  static const std::regex tagged(
      R"(^\s*(?:struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*))",
      std::regex::ECMAScript);
  std::smatch match;
  if (std::regex_search(declaration, match, tagged)) return match[1].str();

  static const std::regex pointer_declarator(
      R"(\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))",
      std::regex::ECMAScript);
  if (std::regex_search(declaration, match, pointer_declarator)) {
    return match[1].str();
  }

  static const std::regex typedef_prefix(
      R"(^\s*typedef(?:\s|$))", std::regex::ECMAScript);
  if (std::regex_search(declaration, typedef_prefix)) {
    static const std::regex trailing_name(
        R"(([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)*;?\s*$)",
        std::regex::ECMAScript);
    if (std::regex_search(declaration, match, trailing_name)) {
      return match[1].str();
    }
    return "";
  }

  static const std::regex function_name(
      R"(([A-Za-z_][A-Za-z0-9_]*)\s*\()", std::regex::ECMAScript);
  return std::regex_search(declaration, match, function_name)
             ? match[1].str()
             : "";
}

}  // namespace

bool Session::handle_runtime_pragma_(const char* sql, xsql::Result& out) {
  const auto request = xsql::runtime::parse_runtime_pragma(sql, "r2xsql");
  if (!request.matched) return false;

  // Clean break: only the two imperative timeout verbs remain PRAGMAs. Value
  // settings are read via SELECT and changed via UPDATE runtime_settings.
  if (request.key == "timeout_push" || request.key == "timeout_pop") {
    const auto common = xsql::runtime::handle_common_runtime_pragma(
        request, "r2xsql", runtime_settings_.common_settings());
    out = common.success ? make_pragma_result(common.name, common.value)
                         : make_pragma_error(common.error);
    return true;
  }

  out = make_pragma_error(xsql::runtime::unknown_runtime_pragma_error("r2xsql"));
  return true;
}

std::string Session::raw_cmd(std::string command) {
  std::lock_guard<std::mutex> lock(query_mu_);
  return backend_->cmd(command);
}

void Session::register_all_tables_() {
  register_binary_table(*this);
  register_funcs_table(*this);
  register_locals_table(*this);
  register_blocks_table(*this);
  register_bytes_table(*this);
  register_cfg_edges_table(*this);
  register_switch_tables_table(*this);
  register_function_frames_table(*this);
  register_data_items_table(*this);
  register_byte_search_table(*this);
  register_dominators_table(*this);
  register_post_dominators_table(*this);
  register_loops_table(*this);
  register_instructions_table(*this);
  register_operands_table(*this);
  register_esil_tables(*this);  // esil_ops / esil_operands + ir_ops family (after instructions)
  register_xrefs_table(*this);
  register_strings_table(*this);
  register_imports_table(*this);
  register_exports_table(*this);
  register_sections_table(*this);
  register_segments_table(*this);
  register_io_maps_table(*this);
  register_flags_table(*this);
  register_comments_table(*this);
  register_bookmarks_table(*this);
  register_grep_table(*this);
  register_types_table(*this);
  register_types_members_table(*this);
  register_projects_table(*this);
  register_runtime_settings_table(*this);
  register_true_believers_table(*this);
}

void Session::register_functions_() {
  // regexp(pattern, text) -> 1 if `text` matches the ECMAScript regex
  // `pattern`, else 0. SQLite rewrites `text REGEXP pattern` to this call
  // (pattern first), enabling the documented `WHERE name REGEXP '...'` form.
  // SQLite has no built-in REGEXP, so it must be registered here.
  db_.register_function("regexp", 2, xsql::ScalarFn(
    [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
        ctx.result_int(0);
        return;
      }
      try {
        std::regex re(argv[0].as_text(), std::regex::ECMAScript);
        ctx.result_int(std::regex_search(argv[1].as_text(), re) ? 1 : 0);
      } catch (const std::exception&) {
        ctx.result_int(0);  // invalid pattern -> no match (never throws into SQLite)
      }
    }));

  // Project persistence as a SQL surface — save/open a project mid-session
  // without exiting. These run inside the query lock (db_.query holds
  // query_mu_), so they call the backend directly rather than Session::raw_cmd
  // (which would re-acquire the same lock and deadlock).
  Backend* be = backend_.get();
  db_.register_function("r2xsql_project_save", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: project name required"); return; }
      std::string name = argv[0].as_text();
      if (!json_utils::valid_flag_name(name)) { ctx.result_text("error: invalid project name"); return; }
      if (std::string e = table_utils::command_error_text(be->cmd("Ps " + name));
          !e.empty()) {
        ctx.result_text("error: project save failed: " + e);
        return;
      }
      ctx.result_text("saved: " + name);
    }));
  db_.register_function("r2xsql_project_open", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: project name required"); return; }
      std::string name = argv[0].as_text();
      if (!json_utils::valid_flag_name(name)) { ctx.result_text("error: invalid project name"); return; }
      if (std::string e = table_utils::command_error_text(be->cmd("P " + name));
          !e.empty()) {
        ctx.result_text("error: project open failed: " + e);
        return;
      }
      ctx.result_text("opened: " + name);
    }));
  // Define a type from a one-line C declaration (`td "<decl>"`), the
  // create-counterpart to DELETE FROM types (a struct decl doesn't fit the
  // types table's columns).
  db_.register_function("r2xsql_type_define", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: C declaration required"); return; }
      std::string decl = argv[0].as_text();
      if (!json_utils::valid_c_declaration(decl)) {
        ctx.result_text(
            "error: declaration must be one line and contain only safe C declarator syntax");
        return;
      }
      const std::string type_name = declared_type_name(decl);
      if (type_name.empty()) {
        ctx.result_text(
            "error: declaration must define a named struct, union, enum, "
            "typedef, or function prototype");
        return;
      }
      // radare2's `td` requires the WHOLE command r2-quoted so the `;`/`{}` in
      // the C declaration aren't treated as command separators/grouping.
      const std::string out = be->cmd(json_utils::r2_quote("td " + decl));
      if (std::string e = table_utils::command_error_text(out); !e.empty()) {
        ctx.result_text("error: type definition failed: " + e);
        return;
      }
      // Read the declared name back because parser failures may be logged only
      // to stderr and otherwise look like a successful no-output command.
      if (table_utils::trim_ascii(be->cmd("tk " + type_name)).empty()) {
        ctx.result_text("error: type definition was not present after td");
        return;
      }
      ctx.result_text("ok");
    }));
}

void Session::detect_decompiler_() {
  // Probe pdg?, pdd?, pdc? — the first one that produces non-empty help
  // text wins. Commands that aren't registered return empty in r2.
  struct Probe { const char* probe; const char* cmd; DecompilerKind kind; };
  static const Probe probes[] = {
    {"pdg?", "pdg", DecompilerKind::Ghidra},
    {"pdd?", "pdd", DecompilerKind::Dec},
    {"pdc?", "pdc", DecompilerKind::Pdc},
  };
  for (auto& p : probes) {
    auto out = backend_->cmd(p.probe);
    if (!out.empty() && out.find("Usage:") != std::string::npos) {
      decompiler_kind_ = p.kind;
      decompiler_cmd_  = p.cmd;
      register_decompiler_table_if_available(*this);
      return;
    }
  }
}

}  // namespace r2xsql
