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

namespace r2sql {

struct BackendError {
  std::string message;
};

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

// Returns nullptr if r2sql was built without libr support (R2SQL_HAVE_LIBR=0)
// or if the open fails. *err is populated on failure.
std::unique_ptr<Backend> open_libr(const LibrOpenOptions& opts, BackendError* err = nullptr);

// Wrap an existing radare2 core (an `RCore*`, passed as `void*` so this public
// header stays free of <r_core.h>) in a Backend WITHOUT taking ownership: the
// returned Backend never frees the core. This is the in-process entry used by
// the core_r2sql plugin to share the host's RCore. The caller retains ownership
// and must keep the core alive for the Backend's lifetime. Returns nullptr in a
// pipe-only build (R2SQL_HAVE_LIBR=0).
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
// ordinal imports) relative to the *running executable*. When the r2sql binary
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
  bool found = true;       // false => r2sql is not deployed next to radare2.exe
};
LibrDataDirStatus libr_data_dir_status();

}  // namespace r2sql
