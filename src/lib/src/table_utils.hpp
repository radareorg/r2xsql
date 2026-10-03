// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Small helpers shared by table definitions.

#pragma once

#include <r2xsql/backend.hpp>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <xsql/vtable.hpp>

#include "direct.hpp"
#include "json_utils.hpp"

namespace r2xsql::table_utils {

inline std::string trim_ascii(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
    s.pop_back();
  }
  size_t first = 0;
  while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first]))) {
    ++first;
  }
  if (first > 0) s.erase(0, first);
  return s;
}

// r2 state-mutating commands (om, om-, f-, af-, CC, t-, ...) print nothing on
// success and a human-readable diagnostic on failure (e.g. "Cannot find map",
// "Invalid address", a "Usage:" line). When a writable table issues such a
// command we must not report SQL success if r2 actually rejected it.
//
// This inspects the command's textual output for a recognized error signature
// and returns that (trimmed) diagnostic, or an empty string when the output has
// no error marker. Deliberately conservative: only known error tokens trip it,
// so genuinely-empty or benign success output passes cleanly. The MockBackend
// returns "" for these commands, so mock/offline paths are unaffected.
inline std::string command_error_text(const std::string& out) {
  std::string lo;
  lo.reserve(out.size());
  for (char c : out) lo.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  static const char* const markers[] = {
      "cannot",   "invalid",  "error",     "usage:",
      "failed",   "no such",  "not find",  "out of range",
      "unknown command", "does not exist",
  };
  for (const char* m : markers) {
    if (lo.find(m) != std::string::npos) return trim_ascii(out);
  }
  return {};
}

// An integer INSERT argument (an address, a size), taken only when it is
// exactly an integer (xsql::exact_int64: 4096, 4096.0 and '4096' all are).
// SQLite applies no column affinity to a virtual table's INSERT values, so
// as_int64() would write 'main' at address 0 and 4096.5 at 4096; this refuses
// both with a vtab error naming `what` instead.
inline bool exact_write_int64(const xsql::FunctionArg& v, std::string_view what,
                              int64_t& out) {
  const auto exact = xsql::exact_int64(v);
  if (!exact) {
    xsql::set_vtab_error(std::string(what) + " must be an integer");
    return false;
  }
  out = *exact;
  return true;
}

inline bool resolve_func_owner(Backend* be, int64_t addr, int64_t& out) {
  if (auto* api = be->direct()) return api->function_owner(addr, out);
  auto info = be->cmd_json("afij @ " + json_utils::hex_addr(addr));
  const nlohmann::json* obj = nullptr;
  if (info.is_array() && !info.empty() && info[0].is_object()) {
    obj = &info[0];
  } else if (info.is_object()) {
    obj = &info;  // not every r2 build wraps this one in an array
  }
  if (!obj) return false;
  for (const char* key : {"addr", "offset"}) {
    auto it = obj->find(key);
    if (it != obj->end() && it->is_number_integer()) {
      out = it->get<int64_t>();
      return true;
    }
  }
  return false;
}

inline std::vector<int64_t> function_starts(Backend* be) {
  std::vector<int64_t> out;
  if (auto* api = be->direct()) {
    api->function_starts(out);
  } else {
    auto funcs = be->cmd_json("aflj");
    if (funcs.is_array()) {
      for (const auto& f : funcs) out.push_back(json_utils::i64_addr(f));
    }
  }
  return out;
}

// Scoped r2 commands accept interior addresses; SQL equality requires a start.
inline bool func_addr_is_start(Backend* be, int64_t addr) {
  if (auto* api = be->direct()) return api->function_is_start(addr);
  int64_t owner = 0;
  return resolve_func_owner(be, addr, owner) && owner == addr;
}

// Direct producers already validate their function lookup; command-only paths
// need the explicit start check because scoped r2 commands accept interiors.
inline bool func_addr_pushdown_ok(Backend* be, int64_t addr) {
  return be->direct() || func_addr_is_start(be, addr);
}

inline size_t quick_count(Backend* be, direct::Collection collection,
                          std::string_view command, size_t fallback) {
  if (!be) return fallback;
  if (auto* api = be->direct()) return api->estimate_count(collection);
  std::string out = trim_ascii(be->cmd(command));
  if (out.empty()) return fallback;
  try {
    return static_cast<size_t>(std::stoull(out, nullptr, 0));
  } catch (...) {
    return fallback;
  }
}

// Assemble at addr without command expansion; pa prints hex on success.
inline bool assemble_hex(Backend* be, int64_t addr, const std::string& asm_text,
                          std::string* out_hex) {
  const std::string command = "pa " + asm_text;
  std::string out = trim_ascii(be->cmd_noeval(addr, command));
  if (out.empty() || !json_utils::valid_hex_bytes(out)) return false;
  *out_hex = out;
  return true;
}

}  // namespace r2xsql::table_utils
