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
//   sql.http [port]      start/stop/status the HTTP REST server
//
// The plugin wraps the host RCore* with libr2xsql's LibrBackend (no
// ownership) and shares a single Session across calls so SQLite caches
// stay warm. The HTTP server runs against that same shared Session.

#include <r2xsql/r2xsql.hpp>
#include <r2xsql/backend_mock.hpp>

#include <r_core.h>
#include <r_lib.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

#include <functional>

#include <xsql/json.hpp>
#include <xsql/query_script.hpp>
#if defined(XSQL_HAS_THINCLIENT)
#include <xsql/thinclient/http_query_server.hpp>
#endif

// r2xsql::make_libr_backend_from_core (declared in <r2xsql/backend.hpp>, included
// via <r2xsql/r2xsql.hpp> above) wraps the host RCore* without taking ownership.

namespace {

struct PluginState {
  std::unique_ptr<r2xsql::Session> session;
  RCore* bound_core = nullptr;
  std::mutex mu;
#if defined(XSQL_HAS_THINCLIENT)
  std::unique_ptr<xsql::thinclient::http_query_server> http;
  int http_port = 0;
  std::string http_bind;
#endif
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
    "sql", " <SQL>", "execute a single SQL statement",
    "sql?", "", "show this help",
    "sql.?", "", "show sql.* subcommands",
    nullptr};

static RCoreHelpMessage help_msg_sql_dot = {
    "Usage:", "sql.<command>", "Run an r2xsql plugin subcommand",
    "sql.?", "", "show this help",
    "Catalogs:", "", "",
    "sql.tables", "", "list available SQL tables",
    "sql.views", "", "list available SQL views",
    "HTTP REST server:", "", "",
#if defined(XSQL_HAS_THINCLIENT)
    "sql.http", " [port]", "start HTTP server (default: random 8100-8999)",
    "sql.http-", "", "stop HTTP server",
    "sql.http?", "", "show HTTP server status",
#else
    "sql.http", "", "HTTP support is not available in this build",
#endif
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

#if defined(XSQL_HAS_THINCLIENT)
// Run a SQL query/script against the session and serialize the canonical
// run_script envelope used by --http (matching the rest of the xsql
// family). run_script gives multi-statement support and lets the thinclient's
// ?format=text|csv|tsv re-render the result via json_to_script_result.
std::string plugin_query_envelope(r2xsql::Session& s, const std::string& body) {
  auto exec = [&s](const std::string& sql, xsql::ScriptStatementResult& out) {
    auto r = s.query(sql);
    out.success = r.ok();
    out.error = r.error;
    out.columns = r.columns;
    out.rows.reserve(r.rows.size());
    for (const auto& row : r.rows) out.rows.push_back(row.values);
  };
  return xsql::script_result_to_json(xsql::run_script(body, {}, std::ref(exec)));
}

// Run a request body against the shared session: ".r2cmd <command>" forwards
// a raw r2 command (returns {"success","output"}); anything else is SQL.
// Locks g_state.mu so concurrent transports serialize against r2's command
// thread. Must be called with g_state.session already initialized.
std::string plugin_raw_or_sql(const std::string& body) {
  static constexpr std::string_view kRaw = ".r2cmd ";
  std::lock_guard<std::mutex> lock(g_state.mu);
  if (!g_state.session) {
    return xsql::json{{"success", false},
                      {"error", "session not initialized"}}.dump();
  }
  try {
    size_t i = body.find_first_not_of(" \t\r\n");
    if (i != std::string::npos && body.compare(i, kRaw.size(), kRaw) == 0) {
      std::string out = g_state.session->raw_cmd(body.substr(i + kRaw.size()));
      return xsql::json{{"success", true}, {"output", out}}.dump();
    }
    return plugin_query_envelope(*g_state.session, body);
  } catch (const std::exception& e) {
    return xsql::json{{"success", false}, {"error", e.what()}}.dump();
  } catch (...) {
    return xsql::json{{"success", false}, {"error", "unknown exception"}}.dump();
  }
}

void handle_http_command(RCore* core, const char* tail) {
  // tail points after "http": empty, " <port>", "-", or "?"
  while (*tail == ' ' || *tail == '\t') ++tail;

  if (*tail == '?') {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (g_state.http && g_state.http->is_running()) {
      char buf[160];
      std::snprintf(buf, sizeof(buf),
                    "r2xsql: HTTP server running at http://%s:%d",
                    g_state.http_bind.c_str(), g_state.http_port);
      r_cons_println(core->cons, buf);
    } else {
      r_cons_println(core->cons, "r2xsql: HTTP server not running.");
    }
    return;
  }

  if (*tail == '-') {
    std::unique_ptr<xsql::thinclient::http_query_server> server;
    {
      std::lock_guard<std::mutex> lock(g_state.mu);
      server = std::move(g_state.http);
      g_state.http_port = 0;
      g_state.http_bind.clear();
    }
    if (server) {
      server->stop();
      r_cons_println(core->cons, "r2xsql: HTTP server stopped.");
    } else {
      r_cons_println(core->cons, "r2xsql: HTTP server was not running.");
    }
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (g_state.http && g_state.http->is_running()) {
      r_cons_println(core->cons,
                     "r2xsql: HTTP server already running. Use `sql.http-` to stop it.");
      return;
    }
  }

  int port = 0;
  if (*tail) {
    char* endp = nullptr;
    long v = std::strtol(tail, &endp, 10);
    if (endp != tail && v >= 0 && v <= 65535) port = static_cast<int>(v);
  }

  ensure_session(core);

  xsql::thinclient::http_query_server_config cfg;
  cfg.tool_name = "r2xsql";
  cfg.port = port;
  cfg.bind_address = "127.0.0.1";
  cfg.use_queue = false;  // worker thread calls query_fn; it locks g_state.mu
  cfg.query_fn = [](const std::string& body) -> std::string {
    return plugin_raw_or_sql(body);
  };
  cfg.status_fn = []() {
    return xsql::json{{"mode", "in-r2"}, {"tool", "r2xsql"}};
  };

  auto server = std::make_unique<xsql::thinclient::http_query_server>(cfg);
  int bound_port = server->start();
  if (bound_port < 0) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "r2xsql: failed to start HTTP server on port %d.", port);
    r_cons_println(core->cons, buf);
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    g_state.http = std::move(server);
    g_state.http_port = bound_port;
    g_state.http_bind = "127.0.0.1";
  }

  char buf[160];
  std::snprintf(buf, sizeof(buf), "r2xsql: HTTP server: http://127.0.0.1:%d",
                bound_port);
  r_cons_println(core->cons, buf);
}
#endif

std::string render_table(const xsql::Result& res) {
  std::ostringstream oss;

  if (!res.ok()) {
    oss << "ERROR: " << res.error << "\n";
    return oss.str();
  }

  // Header
  for (size_t c = 0; c < res.columns.size(); ++c) {
    if (c) oss << "\t";
    oss << res.columns[c];
  }
  oss << "\n";

  for (const auto& row : res.rows) {
    for (size_t c = 0; c < row.size(); ++c) {
      if (c) oss << "\t";
      oss << row[c];
    }
    oss << "\n";
  }
  oss << "(" << res.rows.size() << " rows)\n";
  return oss.str();
}

bool dispatch(RCore* core, const char* input) {
  if (!input) return false;

  // Strip leading whitespace.
  while (*input == ' ' || *input == '\t') ++input;

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

  // Plugin-only subcommands prefixed inside the `sql.` namespace.
  // `sql.http [port]` / `sql.http-` / `sql.http?`
  if (std::strncmp(input, ".http", 5) == 0) {
    const char* rest = input + 5;
    if (*rest == '\0' || *rest == ' ' || *rest == '\t' ||
        *rest == '-' || *rest == '?') {
#if defined(XSQL_HAS_THINCLIENT)
      handle_http_command(core, rest);
#else
      r_cons_println(core->cons,
                     "r2xsql: HTTP support is not available in this build.");
#endif
      return true;
    }
  }

  if (*input == '.') {
    r_cons_printf(core->cons, "Unknown sql subcommand: sql%s\n", input);
    r_cons_println(core->cons, "See `sql.?` for available subcommands.");
    return true;
  }

  ensure_session(core);

  std::string out;
  {
    // Serialize against the HTTP server callbacks, which run on their own
    // threads and also touch g_state.session / SQLite under this same mutex.
    std::lock_guard<std::mutex> lock(g_state.mu);
    try {
      auto res = g_state.session->query(input);
      out = render_table(res);
    } catch (const std::exception& e) {
      out = std::string("EXCEPTION: ") + e.what() + "\n";
    } catch (...) {
      out = "EXCEPTION: unknown\n";
    }
  }
  r_cons_print(core->cons, out.c_str());
  return true;
}

bool plugin_call(RCorePluginSession* ctx, const char* input) {
  if (!ctx || !input) return false;
  // r2 calls every registered plugin's call() for every command; only
  // claim the ones that start with our prefix.
  if (std::strncmp(input, "sql", 3) != 0) return false;
  const char* rest = input + 3;
  // Accept "sql", "sql ", "sql?", "sql.", "sql.<anything>"
  if (*rest != '\0' && *rest != ' ' && *rest != '?' && *rest != '.') {
    return false;
  }
  return dispatch(ctx->core, rest);
}

bool plugin_init(RCorePluginSession* /*ctx*/) {
  return true;
}

bool plugin_fini(RCorePluginSession* /*ctx*/) {
#if defined(XSQL_HAS_THINCLIENT)
  {
    std::unique_ptr<xsql::thinclient::http_query_server> http_server;
    {
      std::lock_guard<std::mutex> lock(g_state.mu);
      http_server = std::move(g_state.http);
      g_state.http_port = 0;
      g_state.http_bind.clear();
    }
    if (http_server) http_server->stop();
  }
#endif
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
