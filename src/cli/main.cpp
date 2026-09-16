// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// r2xsql CLI — flag surface:
//   -s <file>       open binary or r2 project
//   -q "<sql>"      run a single SQL statement (multiple via ;)
//   -f <file.sql>   run a SQL script file
//   -i              REPL
//   -w, --write     open in write mode (persist on exit via `Ps`)
//   --r2pipe        force the r2pipe backend (default: libr if available)
//   --r2-exe <path> path to radare2 executable for r2pipe (default: PATH)
//   --no-analyze    skip the implicit `aaa` at startup
//   --http [port]   start HTTP REST server (default port: 0 = random 8100-8999)
//   --bind <addr>   bind address for the HTTP server (default: 127.0.0.1)
//   --token <tok>   require Bearer token on HTTP endpoints
//   --version       print version and exit
//   -h, --help      print this help and exit

#include <r2xsql/r2xsql.hpp>
#include <r2xsql/backend_mock.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/query_script.hpp>
#include <xsql/thinclient/http_query_server.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

struct Args {
  std::string sql;
  std::string script_file;
  std::string source;
  std::string r2_exe;
  std::string project;
  std::vector<std::string> extra_r2_args;
  bool repl     = false;
  bool write    = false;
  bool analyze  = true;
  bool use_pipe = false;  // false => prefer libr
  bool show_help = false;
  bool show_version = false;

  // HTTP server
  bool http = false;
  int  http_port = 0;
  std::string http_bind = "127.0.0.1";
  std::string http_token;
};

void print_help() {
  std::printf(
#if R2XSQL_HAVE_LIBR
    "r2xsql-full %s — SQL interface for radare2 (embedded radare2 / libr)\n"
#else
    "r2xsql %s — SQL interface for radare2 (pipe-only)\n"
#endif
    R2XSQL_COPYRIGHT_STRING "\n\n"
    "Usage: r2xsql [options]\n"
    "  -s <file>          open the given binary or r2 project\n"
    "  -q \"<sql>\"         run a single SQL statement (\".<cmd>\" runs a raw r2 command)\n"
    "  -f <file.sql>      run a SQL script file\n"
    "  -i                 interactive REPL\n"
    "  -w, --write        open in write mode (persist with `Ps` on exit)\n"
    "      --no-analyze   skip the implicit `aaa` at startup\n"
    "      --project NAME r2 project name (reuses cached analysis; saves on exit if -w)\n"
    "      --r2pipe       use the r2pipe backend (spawn radare2)\n"
    "      --r2-exe PATH  path to radare2 executable for r2pipe\n"
    "      --http [port]  start HTTP REST server (default: random 8100-8999)\n"
    "      --bind <addr>  bind address for --http (default: 127.0.0.1)\n"
    "      --token <tok>  require Bearer token on HTTP endpoints\n"
    "      --version      print version and exit\n"
    "  -h, --help         print this help and exit\n",
    r2xsql::version());
}

int parse_args(int argc, char** argv, Args& a) {
  for (int i = 1; i < argc; ++i) {
    std::string_view k = argv[i];
    auto need = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "r2xsql: %s requires a value\n", name);
        return nullptr;
      }
      return argv[++i];
    };
    if (k == "-h" || k == "--help") { a.show_help = true; continue; }
    if (k == "--version")           { a.show_version = true; continue; }
    if (k == "-w" || k == "--write"){ a.write = true; continue; }
    if (k == "--no-analyze")        { a.analyze = false; continue; }
    if (k == "--r2pipe")            { a.use_pipe = true; continue; }
    if (k == "-i")                  { a.repl = true; continue; }
    if (k == "-s") { auto v = need("-s"); if (!v) return 2; a.source = v; continue; }
    if (k == "-q") { auto v = need("-q"); if (!v) return 2; a.sql = v; continue; }
    if (k == "-f") { auto v = need("-f"); if (!v) return 2; a.script_file = v; continue; }
    if (k == "--r2-exe") { auto v = need("--r2-exe"); if (!v) return 2; a.r2_exe = v; continue; }
    if (k == "--project") { auto v = need("--project"); if (!v) return 2; a.project = v; continue; }
    if (k == "--http") {
      a.http = true;
      // Optional port argument: --http [port]
      if (i + 1 < argc) {
        std::string_view next = argv[i + 1];
        if (!next.empty() && next[0] != '-') {
          try { a.http_port = std::stoi(std::string(next)); ++i; }
          catch (...) { /* leave port = 0 */ }
        }
      }
      continue;
    }
    if (k == "--bind")  { auto v = need("--bind");  if (!v) return 2; a.http_bind  = v; continue; }
    if (k == "--token") { auto v = need("--token"); if (!v) return 2; a.http_token = v; continue; }
    std::fprintf(stderr, "r2xsql: unknown argument: %.*s\n",
                 (int)k.size(), k.data());
    return 2;
  }
  return 0;
}

std::unique_ptr<r2xsql::Backend> open_backend(const Args& a) {
  r2xsql::BackendError err;
#if R2XSQL_HAVE_LIBR
  if (!a.use_pipe) {
    r2xsql::LibrOpenOptions o;
    o.path = a.source;
    o.project = a.project;
    o.analyze = a.analyze;
    o.write = a.write;
    auto be = r2xsql::open_libr(o, &err);
    if (be) return be;
    std::fprintf(stderr, "r2xsql: libr open failed (%s); falling back to r2pipe\n",
                 err.message.c_str());
  }
#endif
  r2xsql::R2PipeOpenOptions o;
  o.path = a.source;
  o.project = a.project;
  o.r2_executable = a.r2_exe;
  o.analyze = a.analyze;
  o.write = a.write;
  auto be = r2xsql::open_r2pipe(o, &err);
  if (!be) {
    std::fprintf(stderr, "r2xsql: r2pipe open failed: %s\n", err.message.c_str());
  }
  return be;
}

void print_result(const xsql::Result& r) {
  if (!r.ok()) {
    std::fprintf(stderr, "error: %s\n", r.error.c_str());
    return;
  }
  if (r.columns.empty()) return;
  for (size_t i = 0; i < r.columns.size(); ++i) {
    if (i) std::printf("\t");
    std::printf("%s", r.columns[i].c_str());
  }
  std::printf("\n");
  for (const auto& row : r) {
    for (size_t i = 0; i < row.size(); ++i) {
      if (i) std::printf("\t");
      std::printf("%s", row[i].c_str());
    }
    std::printf("\n");
  }
}

// A line whose first non-blank char is '.' is a raw r2 command passthrough
// (the leading '.' is stripped before forwarding). Returns false for plain
// SQL. The REPL reserves .quit/.exit/exit for itself before calling this.
bool is_raw_cmd(const std::string& line, std::string& out) {
  size_t i = line.find_first_not_of(" \t");
  if (i == std::string::npos || line[i] != '.') return false;
  out = line.substr(i + 1);
  return true;
}

int run_raw(r2xsql::Session& s, const std::string& cmd) {
  std::string out = s.raw_cmd(cmd);
  if (!out.empty()) {
    std::fputs(out.c_str(), stdout);
    if (out.back() != '\n') std::fputc('\n', stdout);
  }
  return 0;
}

// Print one statement's tabular result (tab-separated header + rows), the same
// rendering print_result() uses for a single xsql::Result — kept as a separate
// helper here because a multi-statement script produces one result per
// statement (xsql::ScriptStatementResult), not a single xsql::Result.
void print_statement_result(const xsql::ScriptStatementResult& r) {
  if (r.columns.empty()) return;
  for (size_t i = 0; i < r.columns.size(); ++i) {
    if (i) std::printf("\t");
    std::printf("%s", r.columns[i].c_str());
  }
  std::printf("\n");
  for (const auto& row : r.rows) {
    for (size_t i = 0; i < row.size(); ++i) {
      if (i) std::printf("\t");
      std::printf("%s", row[i].c_str());
    }
    std::printf("\n");
  }
}

// Run every ';'-terminated statement in `sql`, not just the first. A single
// Session::query() call executes exactly one prepared statement and silently
// drops the rest of a multi-statement blob, so this goes through
// xsql::run_script — the same multi-statement orchestrator the HTTP path uses
// via query_to_envelope() below — with an executor that adapts
// r2xsql::Session::query() to the ScriptStatementResult it expects.
// A leading raw r2 command (".<cmd>") is still special-cased first: it is not
// SQL and is never split into statements.
int run_sql(r2xsql::Session& s, const std::string& sql) {
  std::string raw;
  if (is_raw_cmd(sql, raw)) return run_raw(s, raw);

  auto exec = [&s](const std::string& stmt, xsql::ScriptStatementResult& out) {
    auto r = s.query(stmt);
    out.success = r.ok();
    out.error = r.error;
    out.columns = r.columns;
    out.rows.reserve(r.rows.size());
    for (const auto& row : r.rows) out.rows.push_back(row.values);
  };
  xsql::ScriptResult sr = xsql::run_script(sql, {}, std::ref(exec));

  if (!sr.parse_error.empty()) {
    std::fprintf(stderr, "error: %s\n", sr.parse_error.c_str());
    return 1;
  }

  // Multiple statements: print each one's result set distinctly (matching the
  // HTTP path's per-statement envelope), separated by a `-- statement i/N`
  // marker. A single statement renders exactly as before (no marker), so
  // existing single-statement callers see byte-identical output.
  const bool multi = sr.results.size() > 1;
  for (const auto& stmt : sr.results) {
    if (multi) {
      std::printf("-- statement %zu/%zu\n",
                  stmt.statement_index + 1, sr.statement_count);
    }
    if (!stmt.success) {
      std::fprintf(stderr, "error: %s\n", stmt.error.c_str());
      continue;
    }
    print_statement_result(stmt);
  }
  return sr.success ? 0 : 1;
}

int run_script(r2xsql::Session& s, const std::string& path) {
  std::ifstream f(path);
  if (!f) {
    std::fprintf(stderr, "r2xsql: cannot open script %s\n", path.c_str());
    return 1;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  return run_sql(s, ss.str());
}

int run_repl(r2xsql::Session& s) {
  std::printf("r2xsql %s — interactive REPL. Type .quit to exit.\n"
              R2XSQL_COPYRIGHT_STRING "\n"
              "Lines starting with '.' run a raw r2 command (e.g. .pdf @ entry0).\n",
              r2xsql::version());
  std::string line;
  for (;;) {
    std::printf("sql> ");
    std::fflush(stdout);
    if (!std::getline(std::cin, line)) break;
    if (line.empty()) continue;
    if (line == ".quit" || line == ".exit" || line == "exit") break;
    std::string raw;
    if (is_raw_cmd(line, raw)) { run_raw(s, raw); continue; }
    print_result(s.query(line));
  }
  return 0;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

static std::atomic<bool> g_shutdown_flag{false};

extern "C" void on_signal(int /*sig*/) { g_shutdown_flag.store(true); }

// Run a SQL query/script and serialize the canonical run_script envelope
// (`{success, statement_count, results:[{columns,rows,...}]}`), matching the
// rest of the xsql family (idasql/bnsql/ghidrasql). Going through run_script
// gives multi-statement support and lets the thinclient's ?format=text|csv|tsv
// re-render the result (it parses this envelope back via json_to_script_result).
static std::string query_to_envelope(r2xsql::Session& s, const std::string& body) {
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

static std::string build_help_text() {
  std::ostringstream out;
  out << "r2xsql HTTP REST API\n"
      << "===================\n\n"
      << "SQL interface for radare2 sessions via HTTP.\n\n"
      << "Endpoints:\n"
      << "  GET  /         - Welcome message\n"
      << "  GET  /help     - This documentation\n"
      << "  POST /query    - Execute SQL (body = raw SQL, response = JSON)\n"
      << "                   or a raw r2 command: body \".r2cmd <command>\"\n"
      << "  GET  /status   - Server health check\n"
      << "  POST /shutdown - Stop server\n\n"
      << "Discover Schema:\n"
      << "  SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;\n"
      << "  PRAGMA table_info(funcs);\n\n"
      << "Starter Query:\n"
      << "  SELECT * FROM binary;\n\n"
      << "Response Format:\n"
      << "  Success: {\"success\": true, \"columns\": [...], \"rows\": [[...]], \"row_count\": N}\n"
      << "  Error:   {\"success\": false, \"error\": \"message\"}\n"
      << "  .r2cmd:  {\"success\": true, \"output\": \"<raw r2 output>\"}\n";
  return out.str();
}

int run_http(r2xsql::Session& s, const Args& a) {
  xsql::thinclient::http_query_server_config cfg;
  cfg.tool_name = "r2xsql";
  cfg.help_text = build_help_text();
  cfg.port = a.http_port;
  cfg.bind_address = a.http_bind;
  cfg.auth_token = a.http_token;
  cfg.use_queue = false;
  cfg.query_fn = [&s](const std::string& body) -> std::string {
    // Raw r2 passthrough sugar: a body of ".r2cmd <command>" forwards the
    // command to the backend and returns {"success", "output"} instead of
    // the tabular SQL envelope.
    static constexpr std::string_view kRaw = ".r2cmd ";
    size_t i = body.find_first_not_of(" \t\r\n");
    if (i != std::string::npos && body.compare(i, kRaw.size(), kRaw) == 0) {
      std::string out = s.raw_cmd(body.substr(i + kRaw.size()));
      return xsql::json{{"success", true}, {"output", out}}.dump();
    }
    return query_to_envelope(s, body);
  };
  cfg.status_fn = []() {
    return xsql::json{{"mode", "cli"}, {"tool", "r2xsql"}};
  };

  xsql::thinclient::http_query_server server(cfg);
  int port = server.start();
  if (port < 0) {
    std::fprintf(stderr, "r2xsql: failed to start HTTP server on %s:%d\n",
                 a.http_bind.c_str(), a.http_port);
    return 1;
  }

  std::printf("r2xsql HTTP server: http://%s:%d\n", a.http_bind.c_str(), port);
  std::printf("Press Ctrl+C to stop.\n");
  std::fflush(stdout);

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  while (server.is_running() && !g_shutdown_flag.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  server.stop();
  std::printf("r2xsql: HTTP server stopped.\n");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  int rc = parse_args(argc, argv, a);
  if (rc) return rc;
  if (a.show_help)    { print_help(); return 0; }
  if (a.show_version) {
#if R2XSQL_HAVE_LIBR
    std::printf("r2xsql-full %s (embedded radare2 / libr)\n" R2XSQL_COPYRIGHT_STRING "\n", r2xsql::version());
#else
    std::printf("r2xsql %s (pipe-only)\n" R2XSQL_COPYRIGHT_STRING "\n", r2xsql::version());
#endif
    return 0;
  }

  // No source and nothing else to do? Print help.
  if (a.source.empty() && a.sql.empty() && a.script_file.empty() && !a.repl && !a.http) {
    print_help();
    return 0;
  }

  auto be = open_backend(a);
  if (!be) return 3;
  r2xsql::Session s(std::move(be));

  if (!a.sql.empty())          return run_sql(s, a.sql);
  if (!a.script_file.empty())  return run_script(s, a.script_file);
  if (a.http)                  return run_http(s, a);
  if (a.repl)                  return run_repl(s);

  print_help();
  return 0;
}
