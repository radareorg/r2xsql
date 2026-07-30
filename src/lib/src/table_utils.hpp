// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Small helpers shared by table definitions.

#pragma once

#include <r2sql/backend.hpp>

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace r2sql::table_utils {

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

inline size_t quick_count(Backend* be, std::string_view command, size_t fallback) {
  if (!be) return fallback;
  std::string out = trim_ascii(be->cmd(command));
  if (out.empty()) return fallback;
  try {
    return static_cast<size_t>(std::stoull(out, nullptr, 0));
  } catch (...) {
    return fallback;
  }
}

}  // namespace r2sql::table_utils
