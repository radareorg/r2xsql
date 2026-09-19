// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <r2xsql/backend.hpp>
#include <r2xsql/runtime_settings.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace r2xsql {

class Session {
public:
  // Create a session bound to a Backend. Registers all virtual tables.
  // Ownership of `backend` is transferred.
  explicit Session(std::unique_ptr<Backend> backend);
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Direct query access via libxsql.
  xsql::Database& db() { return db_; }
  const xsql::Database& db() const { return db_; }

  // The bound backend (never null after construction).
  Backend& backend() { return *backend_; }
  Backend* backend_ptr() { return backend_.get(); }

  // Per-session runtime settings (query timeout, hints, timeout stack, ...),
  // driven by the PRAGMA r2xsql.* surface and surfaced read-only via the
  // `runtime_settings` table. Reused by tables_runtime_settings.cpp.
  RuntimeSettings& runtime_settings() { return runtime_settings_; }
  const RuntimeSettings& runtime_settings() const { return runtime_settings_; }

  // Convenience: execute a SQL statement and return the result.
  // Thread-safe: serialized against other query()/raw_cmd() calls so a shared
  // Session can back a concurrent server with use_queue=false (concurrent
  // clients) as well as interactive use, without racing SQLite or the backend.
  xsql::Result query(std::string_view sql);

  // Escape hatch: forward an arbitrary r2 command straight to the backend
  // and return its raw textual output. For commands that have no SQL surface
  // (e.g. "aaa", "s 0x401000", "CC text @ addr"). Empty output is valid.
  // Serialized against query()/raw_cmd() (see query()).
  std::string raw_cmd(std::string command);

  // Whether the decompiler was detected at session bootstrap.
  // Populated by tables_decompiler.cpp's runtime probe.
  bool has_decompiler() const { return decompiler_kind_ != DecompilerKind::None; }
  std::string_view decompiler_command() const { return decompiler_cmd_; }

  enum class DecompilerKind { None, Ghidra, Dec, Pdc };
  DecompilerKind decompiler_kind() const { return decompiler_kind_; }

private:
  void register_all_tables_();
  void register_functions_();
  void detect_decompiler_();
  // Intercept a `PRAGMA r2xsql.*` statement and, if it matches, service it
  // through the shared runtime-pragma dispatcher. Returns true (with `out`
  // filled: a {name,value} row on success, or an error) iff the SQL was a
  // r2xsql runtime pragma; false lets the statement flow to SQLite unchanged.
  bool handle_runtime_pragma_(const char* sql, xsql::Result& out);

  std::unique_ptr<Backend> backend_;
  // Declared before db_ on purpose: db_ owns the cached `runtime_settings`
  // table whose builder captures &runtime_settings(), so runtime_settings_
  // must outlive db_ (members destruct in reverse declaration order).
  RuntimeSettings runtime_settings_;
  xsql::Database db_;
  DecompilerKind decompiler_kind_ = DecompilerKind::None;
  std::string decompiler_cmd_;
  // Serializes query()/raw_cmd(): one SQLite/backend operation at a time.
  std::mutex query_mu_;
};

}  // namespace r2xsql
