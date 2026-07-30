// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// core_r2sql.cpp — radare2 RCorePlugin entrypoint for r2sql.
//
// Once loaded into radare2 (e.g. `L core_r2sql.dll` / `core_r2sql.so`),
// this plugin registers a `sql` command:
//
//   sql                  print help
//   sql <SQL>            execute one statement
//   sql.<SQL>            execute (legacy/discoverable shortcut)
//   sql.?                help
//   sql.http [port]      start/stop/status the HTTP REST server
//   sql.mcp  [port]      start/stop/status the MCP server (when R2SQL_HAS_MCP)
//
// The plugin wraps the host RCore* with libr2sql's LibrBackend (no
// ownership) and shares a single Session across calls so SQLite caches
// stay warm. The HTTP and MCP servers run against that same shared Session.

#include <r2sql/r2sql.hpp>
#include <r2sql/backend_mock.hpp>

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
#include <xsql/thinclient/http_query_server.hpp>

#if R2SQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

// r2sql::make_libr_backend_from_core (declared in <r2sql/backend.hpp>, included
// via <r2sql/r2sql.hpp> above) wraps the host RCore* without taking ownership.

namespace {

struct PluginState {
  std::unique_ptr<r2sql::Session> session;
  RCore* bound_core = nullptr;
  std::mutex mu;
  std::unique_ptr<xsql::thinclient::http_query_server> http;
  int http_port = 0;
  std::string http_bind;
#if R2SQL_HAS_MCP
  std::unique_ptr<r2sql::McpServer> mcp;
  int mcp_port = 0;
  std::string mcp_bind;
#endif
};

PluginState g_state;

void ensure_session(RCore* core) {
  std::lock_guard<std::mutex> lock(g_state.mu);
  if (g_state.session && g_state.bound_core == core) return;
  auto backend = r2sql::make_libr_backend_from_core(core);
  g_state.session = std::make_unique<r2sql::Session>(std::move(backend));
  g_state.bound_core = core;
}

void print_help(RCore* core) {
  r_cons_println(
      core->cons,
      "Usage: sql <SQL>          execute a single SQL statement\n"
      "       sql.<SQL>          shorthand form (same as `sql <SQL>`)\n"
      "       sql.?              this help\n"
      "       sql                this help\n"
      "\n"
      "HTTP REST server:\n"
      "       sql.http [port]    start HTTP server (default: random 8100-8999)\n"
      "       sql.http-          stop HTTP server\n"
      "       sql.http?          print HTTP server status\n"
#if R2SQL_HAS_MCP
      "\n"
      "MCP server (SSE/JSON-RPC, fastmcpp):\n"
      "       sql.mcp [port]     start MCP server (default: random 9000-9999)\n"
      "       sql.mcp-           stop MCP server\n"
      "       sql.mcp?           print MCP server status\n"
#endif
      "\n"
      "Tables: binary, funcs, locals, blocks, bytes, cfg_edges, switch_tables,\n"
      "        function_frames, dominators, post_dominators, loops, data_items,\n"
      "        byte_search, instructions, instruction_operands, esil_ops,\n"
      "        esil_operands, xrefs, strings, imports, entries, sections,\n"
      "        segments, io_maps, flags, comments, bookmarks, grep, pseudocode*,\n"
      "        types, types_members, projects, runtime_settings\n"
      "Views:  ir_ops, ir_operands, ir_maturities, ir_v_calls, ir_v_mem_writes,\n"
      "        ir_v_mem_reads, ir_v_branches, ir_v_arith\n"
      "(* pseudocode only if a decompiler plugin like pdg/pdd/pdc is loaded)");
}

// Run a SQL query/script against the session and serialize the canonical
// run_script envelope used by --http and --mcp (matching the rest of the xsql
// family). run_script gives multi-statement support and lets the thinclient's
// ?format=text|csv|tsv re-render the result via json_to_script_result.
std::string plugin_query_envelope(r2sql::Session& s, const std::string& body) {
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
                    "r2sql: HTTP server running at http://%s:%d",
                    g_state.http_bind.c_str(), g_state.http_port);
      r_cons_println(core->cons, buf);
    } else {
      r_cons_println(core->cons, "r2sql: HTTP server not running.");
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
      r_cons_println(core->cons, "r2sql: HTTP server stopped.");
    } else {
      r_cons_println(core->cons, "r2sql: HTTP server was not running.");
    }
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (g_state.http && g_state.http->is_running()) {
      r_cons_println(core->cons,
                     "r2sql: HTTP server already running. Use `sql.http-` to stop it.");
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
  cfg.tool_name = "r2sql";
  cfg.port = port;
  cfg.bind_address = "127.0.0.1";
  cfg.use_queue = false;  // worker thread calls query_fn; it locks g_state.mu
  cfg.query_fn = [](const std::string& body) -> std::string {
    return plugin_raw_or_sql(body);
  };
  cfg.status_fn = []() {
    return xsql::json{{"mode", "in-r2"}, {"tool", "r2sql"}};
  };

  auto server = std::make_unique<xsql::thinclient::http_query_server>(cfg);
  int bound_port = server->start();
  if (bound_port < 0) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "r2sql: failed to start HTTP server on port %d.", port);
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
  std::snprintf(buf, sizeof(buf), "r2sql: HTTP server: http://127.0.0.1:%d",
                bound_port);
  r_cons_println(core->cons, buf);
}

#if R2SQL_HAS_MCP

void handle_mcp_command(RCore* core, const char* tail) {
  // tail points after "mcp": empty, " <port>", "-", or "?"
  while (*tail == ' ' || *tail == '\t') ++tail;

  if (*tail == '?') {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (g_state.mcp && g_state.mcp->is_running()) {
      std::string s = r2sql::format_mcp_status(g_state.mcp_port,
                                               /*running=*/true,
                                               g_state.mcp_bind);
      r_cons_print(core->cons, s.c_str());
    } else {
      r_cons_println(core->cons, "r2sql: MCP server not running.");
    }
    return;
  }

  if (*tail == '-') {
    std::unique_ptr<r2sql::McpServer> server;
    {
      std::lock_guard<std::mutex> lock(g_state.mu);
      server = std::move(g_state.mcp);
      g_state.mcp_port = 0;
      g_state.mcp_bind.clear();
    }
    if (server) {
      server->stop();
      r_cons_println(core->cons, "r2sql: MCP server stopped.");
    } else {
      r_cons_println(core->cons, "r2sql: MCP server was not running.");
    }
    return;
  }

  // Start (with optional port). Refuse if already running.
  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (g_state.mcp && g_state.mcp->is_running()) {
      r_cons_println(core->cons,
                     "r2sql: MCP server already running. Use `sql.mcp-` to stop it.");
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

  auto server = std::make_unique<r2sql::McpServer>();
  // use_queue=false: SSE worker thread calls our query callback directly.
  // The callback acquires g_state.mu, so MCP queries serialize against
  // any concurrent `sql.<query>` from r2's command thread.
  r2sql::QueryCallback cb = [core](const std::string& sql) -> std::string {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.session) {
      return xsql::json{{"success", false},
                        {"error", "session not initialized"}}.dump();
    }
    try {
      return plugin_query_envelope(*g_state.session, sql);
    } catch (const std::exception& e) {
      return xsql::json{{"success", false}, {"error", e.what()}}.dump();
    } catch (...) {
      return xsql::json{{"success", false},
                        {"error", "unknown exception"}}.dump();
    }
  };

  int bound_port = server->start(port, cb, "127.0.0.1", /*use_queue=*/false);
  if (bound_port <= 0) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "r2sql: failed to start MCP server on port %d.", port);
    r_cons_println(core->cons, buf);
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    g_state.mcp = std::move(server);
    g_state.mcp_port = bound_port;
    g_state.mcp_bind = "127.0.0.1";
  }

  std::string info = r2sql::format_mcp_info(bound_port, "127.0.0.1");
  r_cons_print(core->cons, info.c_str());
}

#endif  // R2SQL_HAS_MCP

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

  // Help: `sql` alone, `sql.`, `sql?`, `sql.?`.
  if (*input == '\0' || std::strcmp(input, "?") == 0 ||
      std::strcmp(input, ".?") == 0 || std::strcmp(input, ".") == 0) {
    print_help(core);
    return true;
  }

  // Strip a single leading `.` (the `sql.<SQL>` form).
  if (*input == '.') ++input;
  while (*input == ' ' || *input == '\t') ++input;

  if (*input == '\0') {
    print_help(core);
    return true;
  }

  // Plugin-only subcommands prefixed inside the `sql.` namespace.
  // `sql.http [port]` / `sql.http-` / `sql.http?`
  if (std::strncmp(input, "http", 4) == 0) {
    const char* rest = input + 4;
    if (*rest == '\0' || *rest == ' ' || *rest == '\t' ||
        *rest == '-' || *rest == '?') {
      handle_http_command(core, rest);
      return true;
    }
  }

#if R2SQL_HAS_MCP
  // `sql.mcp [port]` / `sql.mcp-` / `sql.mcp?`
  if (std::strncmp(input, "mcp", 3) == 0) {
    const char* rest = input + 3;
    if (*rest == '\0' || *rest == ' ' || *rest == '\t' ||
        *rest == '-' || *rest == '?') {
      handle_mcp_command(core, rest);
      return true;
    }
  }
#endif

  ensure_session(core);

  std::string out;
  {
    // Serialize against the HTTP/MCP server callbacks, which run on their own
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
#if R2SQL_HAS_MCP
  std::unique_ptr<r2sql::McpServer> server;
  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    server = std::move(g_state.mcp);
    g_state.mcp_port = 0;
    g_state.mcp_bind.clear();
  }
  if (server) server->stop();
#endif
  std::lock_guard<std::mutex> lock(g_state.mu);
  g_state.session.reset();
  g_state.bound_core = nullptr;
  return true;
}

}  // namespace

extern "C" {

static RCorePlugin r_core_plugin_r2sql = {
    /*.meta =*/ {
        /*.name =*/ const_cast<char*>("r2sql"),
        /*.desc =*/ const_cast<char*>("SQL interface for radare2 (libr2sql)"),
        /*.author =*/ const_cast<char*>("0xeb"),
        /*.version =*/ const_cast<char*>("0.0.2"),
        /*.license =*/ const_cast<char*>("LicenseRef-Human-Origin-Source-1.0"),
        /*.contact =*/ const_cast<char*>("r2sql@invalid.example"),
        /*.copyright =*/ const_cast<char*>("Copyright (c) 2024-2026 Elias Bachaalany"),
        /*.status =*/ R_PLUGIN_STATUS_BASIC,
    },
    /*.init =*/ plugin_init,
    /*.fini =*/ plugin_fini,
    /*.call =*/ plugin_call,
};

#ifdef _WIN32
#define R2SQL_PLUGIN_EXPORT __declspec(dllexport)
#else
#define R2SQL_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

R2SQL_PLUGIN_EXPORT RLibStruct radare_plugin = {
    /*.type =*/ R_LIB_TYPE_CORE,
    /*.data =*/ &r_core_plugin_r2sql,
    /*.version =*/ R2_VERSION,
    /*.free =*/ nullptr,
    /*.pkgname =*/ const_cast<char*>("r2sql"),
    /*.abiversion =*/ R2_ABIVERSION,
};

}  // extern "C"
