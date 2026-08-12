// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
#include <r2xsql/backend.hpp>

namespace r2xsql {

nlohmann::json Backend::cmd_json(std::string_view command, BackendError* err) {
  std::string text = cmd(command);
  if (text.empty()) return nlohmann::json::value_t::null;
  // r2 sometimes appends a trailing newline / nul; trim them.
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r' ||
                            text.back() == '\0' || text.back() == ' ')) {
    text.pop_back();
  }
  if (text.empty()) return nlohmann::json::value_t::null;
  try {
    return nlohmann::json::parse(text);
  } catch (const std::exception& e) {
    if (err) err->message = std::string("json parse error: ") + e.what();
    return nlohmann::json::value_t::null;
  }
}

}  // namespace r2xsql
