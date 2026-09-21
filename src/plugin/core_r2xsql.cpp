// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// core_r2xsql.cpp — radare2 RCorePlugin entrypoint for r2xsql.
//
// Once loaded into radare2 (e.g. `L core_r2xsql.dll` / `core_r2xsql.so`),
// this plugin registers a `sql` command:
//
//   sql                  print help
//   sql <SQL>            execute one statement
//   sql?                 print top-level help
//   sql.?                list sql.* subcommands
//   sql.tables           list available tables
//   sql.views            list available views
//
// The plugin wraps the host RCore* with libr2xsql's LibrBackend (no
// ownership) and shares a single Session across calls so SQLite caches
// stay warm across queries.

#include <r2xsql/r2xsql.hpp>
#include <xsql/query_script.hpp>

#include <r_core.h>
#include <r_lib.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

// r2xsql::make_libr_backend_from_core (declared in <r2xsql/backend.hpp>, included
// via <r2xsql/r2xsql.hpp> above) wraps the host RCore* without taking ownership.

namespace {

struct PluginState {
  std::unique_ptr<r2xsql::Session> session;
  RCore* bound_core = nullptr;
  std::mutex mu;
};

PluginState g_state;

void ensure_session(RCore* core) {
  std::lock_guard<std::mutex> lock(g_state.mu);
  if (g_state.session && g_state.bound_core == core) return;
  auto backend = r2xsql::make_libr_backend_from_core(core);
  g_state.session = std::make_unique<r2xsql::Session>(std::move(backend));
  g_state.bound_core = core;
}

static RCoreHelpMessage help_msg_sql = {
    "Usage:", "sql <SQL>", "Query radare2 data with SQL",
    "sql", " <SQL>", "execute a statement and print a radare2 table",
    "sql,", "<tablequery> <SQL>", "format or filter the result with a table query",
    "sql,?", "", "show table-query help",
    "sql?", "", "show this help",
    "sql.?", "", "show sql.* subcommands",
    "sqlj", " <SQL>", "execute statements and print a JSON result envelope",
    nullptr};

static RCoreHelpMessage help_msg_sql_dot = {
    "Usage:", "sql.<command>", "Run an r2xsql plugin subcommand",
    "sql.?", "", "show this help",
    "Catalogs:", "", "",
    "sql.tables", "", "list available SQL tables",
    "sql.views", "", "list available SQL views",
    nullptr};

static RCoreHelpMessage help_msg_sql_tables = {
    "Usage:", "sql.tables", "List available SQL tables",
    "Tables:", "", "",
    "", "binary, blocks, bookmarks, byte_search, bytes, cfg_edges", "",
    "", "comments, data_items, dominators, entries, esil_operands, esil_ops", "",
    "", "flags, funcs, function_frames, grep, imports, instruction_operands", "",
    "", "instructions, io_maps, locals, loops, post_dominators, projects", "",
    "", "pseudocode*, runtime_settings, sections, segments, strings", "",
    "", "switch_tables, types, types_members, xrefs", "",
    "* pseudocode requires a decompiler plugin such as pdg, pdd, or pdc", "", "",
    nullptr};

static RCoreHelpMessage help_msg_sql_views = {
    "Usage:", "sql.views", "List available SQL views",
    "Views:", "", "",
    "", "ir_maturities, ir_operands, ir_ops, ir_v_arith, ir_v_branches", "",
    "", "ir_v_calls, ir_v_mem_reads, ir_v_mem_writes", "",
    nullptr};

void print_help(RCore* core, RCoreHelpMessage help = help_msg_sql) {
#if R2_ABIVERSION >= 125
  r_cons_cmd_help(core->cons, help);
#else
  r_core_cmd_help(core, help);
#endif
}

std::string render_table(RCore* core, const xsql::Result& res,
                         const char* query) {
  if (!res.ok()) return "ERROR: " + res.error + "\n";
  std::unique_ptr<RTable, decltype(&r_table_free)> table(
      r_core_table_new(core, "sql"), r_table_free);
  if (!table) return "ERROR: cannot create table\n";
  for (const auto& name : res.columns) {
    r_table_add_column(table.get(), r_table_type("string"), name.c_str(), 0);
  }
  for (const auto& row : res.rows) {
    RList* items = r_list_newf(free);
    if (!items) return "ERROR: cannot create row\n";
    for (const auto& value : row.values) {
      char* cell = strdup(value.c_str());
      if (!cell || !r_list_append(items, cell)) {
        free(cell);
        r_list_free(items);
        return "ERROR: cannot create cell\n";
      }
    }
    r_table_add_row_list(table.get(), items);
  }
  if (!r_table_query(table.get(), query)) return "ERROR: invalid table query\n";
  std::unique_ptr<char, decltype(&free)> out(r_table_tostring(table.get()), free);
  return out ? out.get() : "";
}

bool dispatch(RCore* core, const char* input) {
  if (!input) return false;

  std::string table_query;
  if (*input == ',') {
    const char* begin = ++input;
    while (*input && *input != ' ' && *input != '\t') ++input;
    table_query.assign(begin, input);
    if (table_query == "?" || table_query.ends_with(":help")) {
      r_cons_println(core->cons, r_table_help());
      return true;
    }
  }

  // Strip leading whitespace.
  input = r_str_trim_head_ro(input);

  // Top-level help: `sql` or `sql?`.
  if (*input == '\0' || std::strcmp(input, "?") == 0) {
    print_help(core);
    return true;
  }

  // The dotted namespace is reserved for plugin subcommands, never SQL.
  if (std::strcmp(input, ".") == 0 || std::strcmp(input, ".?") == 0) {
    print_help(core, help_msg_sql_dot);
    return true;
  }

  if (std::strcmp(input, ".tables") == 0 ||
      std::strcmp(input, ".tables?") == 0) {
    print_help(core, help_msg_sql_tables);
    return true;
  }

  if (std::strcmp(input, ".views") == 0 ||
      std::strcmp(input, ".views?") == 0) {
    print_help(core, help_msg_sql_views);
    return true;
  }

  if (*input == '.') {
    r_cons_printf(core->cons, "Unknown sql subcommand: sql%s\n", input);
    r_cons_println(core->cons, "See `sql.?` for available subcommands.");
    return true;
  }

  ensure_session(core);

  std::string out;
  {
    // Serialize against concurrent callers (e.g. from other plugins or tools)
    // which also touch g_state.session / SQLite under this same mutex.
    std::lock_guard<std::mutex> lock(g_state.mu);
    try {
      auto res = g_state.session->query(input);
      out = render_table(core, res, table_query.c_str());
    } catch (const std::exception& e) {
      out = std::string("EXCEPTION: ") + e.what() + "\n";
    } catch (...) {
      out = "EXCEPTION: unknown\n";
    }
  }
  r_cons_print(core->cons, out.c_str());
  return true;
}

bool dispatch_json(RCore* core, const char* input) {
  input = r_str_trim_head_ro(input);
  if (!*input || std::strcmp(input, "?") == 0) {
    print_help(core);
    return true;
  }
  std::string out;
  try {
    ensure_session(core);
    std::lock_guard<std::mutex> lock(g_state.mu);
    auto exec = [](const std::string& sql, xsql::ScriptStatementResult& result) {
      auto res = g_state.session->query(sql);
      result.success = res.ok();
      result.error = res.error;
      result.warnings = std::move(res.warnings);
      result.timed_out = res.timed_out;
      result.partial = res.partial;
      result.columns = std::move(res.columns);
      for (auto& row : res.rows) {
        result.rows.push_back(std::move(row.values));
        result.cell_null.push_back(std::move(row.nulls));
      }
    };
    out = xsql::script_result_to_json(xsql::run_script(input, {}, exec));
  } catch (const std::exception& e) {
    out = xsql::json{{"success", false}, {"error", e.what()}}.dump();
  } catch (...) {
    out = xsql::json{{"success", false}, {"error", "unknown exception"}}.dump();
  }
  r_cons_println(core->cons, out.c_str());
  return true;
}

bool plugin_call(RCorePluginSession* ctx, const char* input) {
  if (!ctx || !input) return false;
  if (std::strncmp(input, "sqlj", 4) == 0) {
    const char* sql = input + 4;
    if (*sql && *sql != ' ' && *sql != '\t' && *sql != '?') return false;
    return dispatch_json(ctx->core, sql);
  }
  // r2 calls every registered plugin's call() for every command; only
  // claim the ones that start with our prefix.
  if (std::strncmp(input, "sql", 3) != 0) return false;
  const char* rest = input + 3;
  // Accept SQL, help, subcommands, and table-query suffixes.
  if (*rest != '\0' && *rest != ' ' && *rest != '?' && *rest != '.' && *rest != ',') {
    return false;
  }
  return dispatch(ctx->core, rest);
}

bool plugin_init(RCorePluginSession* /*ctx*/) {
  return true;
}

bool plugin_fini(RCorePluginSession* /*ctx*/) {
  std::lock_guard<std::mutex> lock(g_state.mu);
  g_state.session.reset();
  g_state.bound_core = nullptr;
  return true;
}

}  // namespace

extern "C" {

static RCorePlugin r_core_plugin_r2xsql = {
    /*.meta =*/ {
        /*.name =*/ const_cast<char*>("r2xsql"),
        /*.desc =*/ const_cast<char*>("SQL interface for radare2 (libr2xsql)"),
        /*.author =*/ const_cast<char*>("0xeb"),
        /*.version =*/ const_cast<char*>("0.0.1"),
        /*.license =*/ const_cast<char*>("LicenseRef-Human-Origin-Source-1.0"),
        /*.contact =*/ const_cast<char*>("r2xsql@invalid.example"),
        /*.copyright =*/ const_cast<char*>("Copyright (c) 2024-2026 Elias Bachaalany"),
        /*.status =*/ R_PLUGIN_STATUS_BASIC,
    },
    /*.init =*/ plugin_init,
    /*.fini =*/ plugin_fini,
    /*.call =*/ plugin_call,
};

#ifdef _WIN32
#define R2XSQL_PLUGIN_EXPORT __declspec(dllexport)
#else
#define R2XSQL_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

R2XSQL_PLUGIN_EXPORT RLibStruct radare_plugin = {
    /*.type =*/ R_LIB_TYPE_CORE,
    /*.data =*/ &r_core_plugin_r2xsql,
    /*.version =*/ R2_VERSION,
    /*.free =*/ nullptr,
    /*.pkgname =*/ const_cast<char*>("r2xsql"),
    /*.abiversion =*/ R2_ABIVERSION,
};

}  // extern "C"
