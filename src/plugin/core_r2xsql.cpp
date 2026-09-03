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
//   sql / sql?             print help
//   sql <SQL>              execute one statement, print an r2 table
//   sql,<query> <SQL>      same, filtered/formatted by r2's table query
//   sqlj <SQL>             execute one statement, print the JSON envelope
//   sql.?                  list the sql.* subcommands
//   sql.tables sql.views   list the tables/views this build exposes
//
// The `sql.` namespace is subcommands ONLY -- it never carries SQL.
//
// The plugin wraps the host RCore* with libr2xsql's LibrBackend (no
// ownership) and shares a single Session across calls so SQLite caches
// stay warm. Transport, lifecycle and projects are radare2's job.

#include <r2xsql/r2xsql.hpp>

#include <r_core.h>
#include <r_lib.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

#include <functional>

#include <xsql/json.hpp>
#include <xsql/query_script.hpp>

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

// Help goes through r2's own RCoreHelpMessage / r_core_cmd_help rather than a
// hand-rolled r_cons_println block, so `sql?` renders, aligns and colours like
// every other command's help and follows r2's `?` conventions.
//
// Note r_core_cmd_help(core, msg) is used, NOT r_cons_cmd_help(cons, msg):
// the latter's arity changed across radare2 versions (it takes a use_color
// argument on some), while r_core_cmd_help has been a stable two-argument
// wrapper that reads the colour setting from the core's config itself. It is
// what r2's own builtins call.
static RCoreHelpMessage help_msg_sql = {
    "Usage:", "sql[j,.] <SQL>", "Query radare2's analysis with SQL",
    "sql", " <SQL>", "run a statement, print a radare2 table",
    "sql,", "<tablequery> <SQL>", "same, shaped by an r2 table query",
    "sqlj", " <SQL>", "run statements, print the JSON envelope (for programs)",
    "sql?", "", "show this help",
    "sql,?", "", "show the table-query language's own help",
    "sql.?", "", "show sql.* subcommands",
    "NOTE:", "", "the table query is a SUFFIX and ends at the first space, so",
    "", "", "it never collides with SQL: sql,:csv SELECT name, size FROM funcs",
    "NOTE:", "", "prefer sqlj over sql,:json in code -- an r2 table has no null",
    "", "", "and drops empty cells, so NULL and '' both vanish from the output",
    "NOTE:", "", "over =h, wrap the whole command in double quotes or r2's own",
    "", "", "parser eats > and | first and you get an empty body, silently",
    NULL};

static RCoreHelpMessage help_msg_sql_dot = {
    "Usage:", "sql.<command>", "r2xsql subcommands (this namespace is never SQL)",
    "sql.?", "", "show this help",
    "sql.tables", "", "list the SQL tables this build exposes",
    "sql.views", "", "list the SQL views this build exposes",
    NULL};

void print_help(RCore* core) { r_core_cmd_help(core, help_msg_sql); }

void print_dot_help(RCore* core) { r_core_cmd_help(core, help_msg_sql_dot); }

// Run a SQL query/script against the session and serialize the canonical
// run_script envelope. This is what `sqlj` prints: multi-statement results
// and a real SQL-NULL mask, neither of which the text renderer can express.
std::string plugin_query_envelope(r2xsql::Session& s, const std::string& body) {
  auto exec = [&s](const std::string& sql, xsql::ScriptStatementResult& out) {
    auto r = s.query(sql);
    out.success = r.ok();
    out.error = r.error;
    out.columns = r.columns;
    out.rows.reserve(r.rows.size());
    // Carry the SQL-NULL mask alongside the values. Without it every consumer
    // that distinguishes NULL from '' -- the JSON envelope's `null`, notably --
    // silently reports an empty string instead, because `cell_null` stays empty
    // and `is_null_cell()` can never be true. query_script.hpp:966 does exactly
    // this in the library's own adapter.
    out.cell_null.reserve(r.rows.size());
    for (const auto& row : r.rows) {
      out.rows.push_back(row.values);
      out.cell_null.push_back(row.nulls);
    }
  };
  return xsql::script_result_to_json(xsql::run_script(body, {}, std::ref(exec)));
}

// Render a result through radare2's OWN table API rather than formatting it
// here. r_core_table_new picks up cfg.table.format, cfg.table.maxcol,
// cfg.table.wrap and scr.utf8, and r_table_tostring dispatches to
// fancy/simple/csv/tsv/html/json/sql/r2cmds -- so `sql` prints like every other
// r2 command, honours the user's table config, and inherits any format r2 grows
// later without a line of work here. The `sql,<tablequery>` form (see dispatch)
// feeds r_table_query, which is where :csv/:json/:quiet/sort/paging come from.
//
// Every column is declared `string`, deliberately. Sniffing numerics is
// tempting and wrong: r_table_tojson re-emits a non-numeric cell in a `number`
// column as a string, so a sniffed column is unstable row-to-row. ORDER BY in
// the SQL is the better answer and it is already available.
//
// SQL NULL renders as the empty string here -- RTable cells are plain char*
// and have no null representation at all. That is precisely why `sqlj` does
// NOT go through RTable; see plugin_query_envelope.
std::string render_table(RCore* core, const xsql::Result& res,
                         const char* table_query) {
  if (!res.ok()) return "ERROR: " + res.error + "\n";

  RTable* t = r_core_table_new(core, "sql");
  if (!t) return "ERROR: cannot create table\n";

  for (const auto& name : res.columns) {
    r_table_add_column(t, r_table_type("string"), name.c_str(), 0);
  }
  for (const auto& row : res.rows) {
    // r_table_add_row_list takes ownership of the list; r_list_newf(free) +
    // strdup is the idiom libr uses for this itself (cmd_anal.inc.c, and
    // markdown.c). wrap_items() may rewrite a cell in place, so the cells
    // must be individually owned, writable allocations -- which they are.
    RList* items = r_list_newf(free);
    for (size_t c = 0; c < row.size(); ++c) {
      r_list_append(items, strdup(row[c].c_str()));
    }
    r_table_add_row_list(t, items);
  }

  std::string out;
  if (r_table_query(t, table_query)) {
    if (char* s = r_table_tostring(t)) {
      out.assign(s);
      free(s);
    }
  } else {
    // The help path is intercepted in dispatch() before we get here, so a
    // false return at this point means the query itself was rejected.
    out = "ERROR: invalid table query\n";
  }
  r_table_free(t);
  return out;
}

// `sql.tables` / `sql.views`, answered by QUERYING sqlite_master rather than
// printing a hardcoded list.
//
// That is deliberate and it is not just tidiness: the hardcoded list this
// replaces had drifted badly, naming 33 tables and 8 views when the build
// actually exposed 47 and 13 -- `classes`, `patches`, `registers`, `relocs`,
// `rop_gadgets`, `syscalls`, `callers`, `callees`, `names` and others were
// simply invisible to anyone reading the help. A catalog derived from the
// schema cannot drift from the schema.
bool print_catalog(RCore* core, const char* kind) {
  ensure_session(core);
  std::string out;
  {
    std::lock_guard<std::mutex> lock(g_state.mu);
    try {
      const std::string sql =
          std::string("SELECT name FROM sqlite_master WHERE type = '") + kind +
          "' ORDER BY name";
      out = render_table(core, g_state.session->query(sql), "");
    } catch (const std::exception& e) {
      out = std::string("EXCEPTION: ") + e.what() + "\n";
    } catch (...) {
      out = "EXCEPTION: unknown\n";
    }
  }
  r_cons_print(core->cons, out.c_str());
  return true;
}

bool dispatch(RCore* core, const char* input) {
  if (!input) return false;

  // Three forms, told apart by the character immediately after `sql`:
  //
  //   sqlj <SQL>              JSON envelope (r2's own `j`-suffix convention,
  //                           as in afl/aflj, iz/izj)
  //   sql,<tablequery> <SQL>  text, filtered/formatted by r2's table query
  //   sql <SQL>               text
  //
  // The table query sits in the SUFFIX rather than the tail, and that is
  // forced, not a style choice. r2's table-query language reserves ',' and '/'
  // as its delimiters, and every other r2 command that takes a payload plus a
  // query (`pd,`, `abl,`) splits on the FIRST SPACE -- which for us would land
  // in the middle of a SELECT. `is,`/`iz,` solve it the other way round, and we
  // copy them exactly: scan to the first space, that is the query, the rest is
  // SQL. The two grammars then cannot collide no matter what the SQL contains.
  //
  // Both are detected before the whitespace and `.` strips, so `sqlj`,
  // `sqlj <SQL>`, `sqlj.<SQL>` and `sqlj?` all behave like their `sql`
  // counterparts.
  bool as_json = false;
  std::string table_query;
  if (*input == 'j') {
    as_json = true;
    ++input;
  } else if (*input == ',') {
    ++input;
    if (const char* sp = std::strchr(input, ' ')) {
      table_query.assign(input, static_cast<size_t>(sp - input));
      input = sp + 1;
    } else {
      table_query.assign(input);
      input += std::strlen(input);
    }
    // r_table_query prints its own help with eprintf() -- i.e. to stderr,
    // which over `=h` is invisible: the client sees HTTP 200 and an empty
    // body, the same silent-failure shape a refused `Ps` has. Intercept it and
    // print through r_cons so `sql,?` answers on every transport, not just at
    // a local console.
    const std::string kHelp = ":help";
    const bool wants_help =
        table_query == "?" ||
        (table_query.size() >= kHelp.size() &&
         table_query.compare(table_query.size() - kHelp.size(), kHelp.size(),
                             kHelp) == 0);
    if (wants_help) {
      r_cons_println(core->cons, r_table_help());
      return true;
    }
  }

  // Strip leading whitespace.
  while (*input == ' ' || *input == '\t') ++input;

  // Top-level help: `sql` alone, or `sql?`.
  if (*input == '\0' || std::strcmp(input, "?") == 0) {
    print_help(core);
    return true;
  }

  // The dotted namespace is reserved for plugin subcommands and NEVER carries
  // SQL. It used to be a `sql.<SQL>` shorthand; that is gone, because the two
  // cannot coexist -- `sql.tables` would be ambiguous between a subcommand and
  // a (nonsense) statement, and a mistyped subcommand would silently become a
  // SQL syntax error instead of saying so.
  if (*input == '.') {
    const char* sub = input + 1;
    if (*sub == '\0' || std::strcmp(sub, "?") == 0) {
      print_dot_help(core);
      return true;
    }
    if (std::strcmp(sub, "tables") == 0 || std::strcmp(sub, "tables?") == 0) {
      return print_catalog(core, "table");
    }
    if (std::strcmp(sub, "views") == 0 || std::strcmp(sub, "views?") == 0) {
      return print_catalog(core, "view");
    }
    std::string msg = "Unknown sql subcommand: sql" + std::string(input) +
                      "\nSee `sql.?` for the available subcommands, or drop "
                      "the '.' to run SQL.\n";
    r_cons_print(core->cons, msg.c_str());
    return true;
  }

  ensure_session(core);

  std::string out;
  {
    // Serializes this command against itself, and that is worth more than it
    // looks: under `=h&` radare2 runs the HTTP handler on a second thread over
    // the same RCore, and it reaches us by calling plugin_call directly -- so
    // an HTTP `sqlj` and a console `sql` both arrive here and take this lock.
    // Two SQL commands therefore cannot interleave, at this lock and then at
    // Session::query_mu_ and the backend's own.
    //
    // What it does NOT protect against is a NON-SQL r2 command: `aaa` typed at
    // the console while a SELECT is mid-scan rewrites RAnal under our walk and
    // takes none of these locks. A plugin-local mutex cannot fix that; it is a
    // host-level problem (r2's own source marks the spot in rtr_http with
    // `TODO: handle mutex lock/unlock here`).
    std::lock_guard<std::mutex> lock(g_state.mu);
    try {
      if (as_json) {
        // run_script envelope: multi-statement, and carries the SQL-NULL
        // mask that render_table() cannot express.
        out = plugin_query_envelope(*g_state.session, input);
        out += "\n";
      } else {
        auto res = g_state.session->query(input);
        out = render_table(core, res, table_query.c_str());
      }
    } catch (const std::exception& e) {
      out = as_json
                ? xsql::json{{"success", false}, {"error", e.what()}}.dump() + "\n"
                : std::string("EXCEPTION: ") + e.what() + "\n";
    } catch (...) {
      out = as_json ? xsql::json{{"success", false},
                                 {"error", "unknown exception"}}.dump() + "\n"
                    : std::string("EXCEPTION: unknown\n");
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
  // Accept "sql"/"sqlj" followed by end, space, '?' or '.', plus "sql," for
  // the table-query form. The lookahead past 'j' matters: without it "sqljunk"
  // would be claimed and mis-parsed as a JSON query for "unk".
  //
  // ',' is accepted only on the bare `sql` -- there is no `sqlj,`. The table
  // query shapes a text table; the JSON envelope is not an RTable and has
  // nothing for it to act on.
  if (*rest == 'j') {
    const char* term = rest + 1;
    if (*term != '\0' && *term != ' ' && *term != '?' && *term != '.') {
      return false;
    }
  } else if (*rest != '\0' && *rest != ' ' && *rest != '?' && *rest != '.' &&
             *rest != ',') {
    return false;
  }
  return dispatch(ctx->core, rest);
}

bool plugin_init(RCorePluginSession* /*ctx*/) {
  return true;
}

bool plugin_fini(RCorePluginSession* /*ctx*/) {
  {
  }
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
