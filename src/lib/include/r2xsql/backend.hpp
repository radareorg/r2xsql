// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// backend.hpp — abstract interface for talking to a radare2 session.
//
// Three implementations:
//   - LibrBackend   : in-process via libr (r_core_new / r_core_cmd_str)
//   - R2PipeBackend : spawns radare2.exe -q0 and pipes commands over stdio
//   - MockBackend   : canned command -> response map (in-memory, no radare2)

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace r2xsql {

struct BackendError {
  std::string message;
};

// The direct (C-API) row producers a table can use instead of running a command
// and parsing its JSON. Defined in the internal `direct.hpp`, which only the
// table files and the libr backend include — this header stays free of it, and
// a consumer that never calls Backend::direct() never needs the definition.
namespace direct { class Api; }

class Backend {
public:
  virtual ~Backend() = default;

  // Execute an r2 command and return its raw textual output.
  // Empty string is a valid result (many r2 commands produce nothing).
  virtual std::string cmd(std::string_view command) = 0;

  // Convenience: run an r2 command and parse its output as JSON.
  // Returns a null value (and sets *err if non-null) on parse failure.
  nlohmann::json cmd_json(std::string_view command, BackendError* err = nullptr);

  // True iff this backend is bound to a live r2 session. (False for a
  // freshly-default-constructed MockBackend before any canned response
  // is added; otherwise true.)
  virtual bool alive() const = 0;

  // Human-readable backend name for diagnostics ("libr", "r2pipe", "mock").
  virtual std::string_view name() const = 0;

  // Direct C-API row producers, for the tables where reading libr's state
  // in-process measured far cheaper than command + JSON. Returns nullptr on
  // every backend with no in-process radare2 to read — r2pipe talks to a
  // separate process, mock has no radare2 at all — and those keep the command
  // path, which is never removed. A table that has been ported checks this once
  // and falls back on null; a table that has not been ported ignores it.
  virtual direct::Api* direct() { return nullptr; }

  // Structural no-eval command dispatch, for write paths on the in-process
  // libr backend only. Sends `command` straight to its top-level r2 command
  // handler, seeked to `addr` first, WITHOUT evaluating radare2's own
  // command-chaining grammar (`;`, `@`, `|`, backtick, ...) at all — so any
  // such character embedded in an argument to `command` (e.g. user-controlled
  // text) is passed through as inert data to that one handler and can never be
  // reinterpreted as chaining into a second command. This is an ADDITIONAL
  // layer alongside a table's existing input validation/escaping, never a
  // replacement for it — callers keep validating input exactly as before.
  //
  // `command` must be a single command's own text with NO `@`/`;`/`|`/backtick
  // needed for addressing or chaining — pass the target address via `addr`
  // instead of splicing `@ <addr>` into the string.
  //
  // Returns false and leaves `out` untouched when this backend cannot dispatch
  // this way (every backend but libr: r2pipe talks to a separate process with
  // no in-process command handler to call into; mock has no radare2 at all) —
  // the caller must then fall back to its existing cmd()-based path unchanged.
  // Returns true and fills `out` with the command's textual output otherwise;
  // that output is checked for an error exactly like cmd()'s is (a `true`
  // return means "dispatched", not "succeeded" — an in-band diagnostic in
  // `out` is still possible and must still be checked).
  virtual bool cmd_noeval(int64_t /*addr*/, std::string_view /*command*/, std::string* /*out*/) {
    return false;
  }
};

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

struct LibrOpenOptions {
  std::string path;       // binary or project; empty == open with no file
  std::string project;    // r2 project name; reuses cached analysis when present
  bool analyze = true;    // run `aaa` after open (skipped automatically when a project loaded)
  bool write   = false;   // open in -w mode; on close, saves the project if `project` is set
};

// Returns nullptr if r2xsql was built without libr support (R2XSQL_HAVE_LIBR=0)
// or if the open fails. *err is populated on failure.
std::unique_ptr<Backend> open_libr(const LibrOpenOptions& opts, BackendError* err = nullptr);

// Wrap an existing radare2 core (an `RCore*`, passed as `void*` so this public
// header stays free of <r_core.h>) in a Backend WITHOUT taking ownership: the
// returned Backend never frees the core. This is the in-process entry used by
// the core_r2xsql plugin to share the host's RCore. The caller retains ownership
// and must keep the core alive for the Backend's lifetime. Returns nullptr in a
// pipe-only build (R2XSQL_HAVE_LIBR=0).
//
// (Declared with C++ linkage and resolved at link time by its sole caller — no
// `extern "C"` is needed since both the definition and the caller are C++ TUs
// in this project; using C linkage here would be the C4190 "C-incompatible
// return type" warning, as `std::unique_ptr` is not a C type.)
std::unique_ptr<Backend> make_libr_backend_from_core(void* core_ptr);

struct R2PipeOpenOptions {
  std::string r2_executable;  // path to radare2(.exe); searched on PATH if empty
  std::string path;           // binary to open; if empty, opens with --
  std::string project;        // r2 project name; managed after startup with Pl/P/Ps
  bool analyze = true;
  bool write   = false;
  std::vector<std::string> extra_args;  // appended after -q0
};

std::unique_ptr<Backend> open_r2pipe(const R2PipeOpenOptions& opts, BackendError* err = nullptr);

// MockBackend is constructible directly (see backend_mock.hpp).

// ---------------------------------------------------------------------------
// libr data-directory diagnostic
// ---------------------------------------------------------------------------
//
// The in-process libr backend asks radare2 to locate its data files
// (share/fcnsign/types-*.sdb for the type DB, share/format/dll/*.sdb for
// ordinal imports) relative to the *running executable*. When the r2xsql binary
// is not deployed alongside radare2.exe in the install prefix's bin/ directory,
// that lookup lands on a nonexistent path: the `types` table degrades to a
// handful of built-ins and ordinal imports stay unresolved (r2 prints a flood
// of "Cannot find ...sdb" errors).
//
// This probe reports the directory r2 will look in and whether it exists, so
// callers can detect the misdeployment. In a pipe-only build the
// data dir is resolved by the spawned radare2.exe instead, so `found` is true
// and `probe_path` is empty (not applicable).
struct LibrDataDirStatus {
  std::string probe_path;  // the share/fcnsign directory r2 will probe
  bool found = true;       // false => r2xsql is not deployed next to radare2.exe
};
LibrDataDirStatus libr_data_dir_status();

}  // namespace r2xsql
