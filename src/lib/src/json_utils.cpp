// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
#include "json_utils.hpp"
#include <r_util.h>

#include <cctype>
#include <cstdio>

namespace r2xsql::json_utils {

std::string str(const nlohmann::json& obj, std::string_view key, std::string_view dflt) {
  std::string k(key);
  if (!obj.is_object()) return std::string(dflt);
  auto it = obj.find(k);
  if (it == obj.end() || it->is_null()) return std::string(dflt);
  if (it->is_string()) return it->get<std::string>();
  return it->dump();
}

int64_t i64(const nlohmann::json& obj, std::string_view key, int64_t dflt) {
  std::string k(key);
  if (!obj.is_object()) return dflt;
  auto it = obj.find(k);
  if (it == obj.end() || it->is_null()) return dflt;
  if (it->is_number_integer())  return it->get<int64_t>();
  if (it->is_number_unsigned()) return static_cast<int64_t>(it->get<uint64_t>());
  if (it->is_number_float())    return static_cast<int64_t>(it->get<double>());
  if (it->is_string()) {
    try { return std::stoll(it->get<std::string>(), nullptr, 0); } catch (...) { return dflt; }
  }
  return dflt;
}

int32_t i32(const nlohmann::json& obj, std::string_view key, int32_t dflt) {
  return static_cast<int32_t>(i64(obj, key, dflt));
}

int64_t i64_addr(const nlohmann::json& obj, int64_t dflt) {
  if (!obj.is_object()) return dflt;
  // Try `addr` first (current r2 6.x convention for aflj/afbj/pdfj/fj/...).
  auto it = obj.find("addr");
  if (it != obj.end() && !it->is_null()) return i64(obj, "addr", dflt);
  // Fall back to `offset` (used by CCj and some older surfaces).
  return i64(obj, "offset", dflt);
}

bool boolean(const nlohmann::json& obj, std::string_view key, bool dflt) {
  std::string k(key);
  if (!obj.is_object()) return dflt;
  auto it = obj.find(k);
  if (it == obj.end() || it->is_null()) return dflt;
  if (it->is_boolean()) return it->get<bool>();
  if (it->is_number()) return it->get<double>() != 0.0;
  return dflt;
}




std::string r2_quote(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      default:   out.push_back(c);
    }
  }
  out.push_back('"');
  return out;
}

bool valid_type_text(std::string_view type) {
  if (type.empty()) return false;
  for (unsigned char c : type) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '.' ||
                    c == '*' || c == ' ' || c == '[' || c == ']';
    if (!ok) return false;
  }
  return true;
}

bool valid_c_signature(std::string_view text) {
  if (text.empty()) return false;
  int parens = 0;
  int brackets = 0;
  bool saw_function_paren = false;
  for (unsigned char c : text) {
    if (std::isalnum(c)) continue;
    switch (c) {
      case ' ':
      case '\t':
      case '_':
      case '.':
      case '*':
      case ',':
      case ':':
      case '=':
      case '+':
      case '-':
        break;
      case '(':
        ++parens;
        saw_function_paren = true;
        break;
      case ')':
        if (--parens < 0) return false;
        break;
      case '[':
        ++brackets;
        break;
      case ']':
        if (--brackets < 0) return false;
        break;
      default:
        return false;
    }
  }
  return saw_function_paren && parens == 0 && brackets == 0;
}

bool valid_perm(std::string_view perm) {
  if (perm.empty()) return false;
  for (unsigned char c : perm) {
    if (c != 'r' && c != 'w' && c != 'x' && c != '-') return false;
  }
  return true;
}

bool valid_asm_source_text(std::string_view text) {
  if (text.empty()) return false;
  for (unsigned char c : text) {
    if (std::isalnum(c)) continue;
    switch (c) {
      case ' ': case ',': case '.': case '+': case '-': case '*': case '/':
      case '[': case ']': case '(': case ')': case ':': case '%': case '#':
      case '_': case '$':
        continue;
      default:
        return false;
    }
  }
  return true;
}

std::string hex_addr(int64_t addr) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(addr));
  return std::string(buf);
}

bool is_hex_digit(char c) {
  return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

std::string compact_hex(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in)
    if (!std::isspace(static_cast<unsigned char>(c))) out += c;
  return out;
}

bool valid_hex_bytes(std::string_view hex) {
  if (hex.empty() || (hex.size() % 2) != 0) return false;
  for (char c : hex)
    if (!is_hex_digit(c)) return false;
  return true;
}

namespace {
int hex_nibble_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  return -1;
}
}  // namespace

bool hex_decode(std::string_view hex, std::vector<uint8_t>& out) {
  out.clear();
  if (!valid_hex_bytes(hex)) return false;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    const int hi = hex_nibble_value(hex[i]);
    const int lo = hex_nibble_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {  // unreachable given valid_hex_bytes(), kept defensive
      out.clear();
      return false;
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

void hex_decode_partial(std::string_view hex, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    const int hi = hex_nibble_value(hex[i]);
    const int lo = hex_nibble_value(hex[i + 1]);
    if (hi < 0 || lo < 0) break;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
}

std::string base64_encode(std::string_view s) {
  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((s.size() + 2) / 3) * 4);
  const unsigned char* d = reinterpret_cast<const unsigned char*>(s.data());
  const size_t n = s.size();
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    const uint32_t v = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8) | d[i + 2];
    out.push_back(tbl[(v >> 18) & 0x3f]);
    out.push_back(tbl[(v >> 12) & 0x3f]);
    out.push_back(tbl[(v >> 6) & 0x3f]);
    out.push_back(tbl[v & 0x3f]);
  }
  if (n - i == 1) {
    const uint32_t v = uint32_t(d[i]) << 16;
    out.push_back(tbl[(v >> 18) & 0x3f]);
    out.push_back(tbl[(v >> 12) & 0x3f]);
    out += "==";
  } else if (n - i == 2) {
    const uint32_t v = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8);
    out.push_back(tbl[(v >> 18) & 0x3f]);
    out.push_back(tbl[(v >> 12) & 0x3f]);
    out.push_back(tbl[(v >> 6) & 0x3f]);
    out.push_back('=');
  }
  return out;
}

std::unordered_map<std::string, std::string> parse_tk_dump(std::string_view tk) {
  std::unordered_map<std::string, std::string> out;
  size_t pos = 0;
  // tk* emits one key=value record per line; type names can contain spaces.
  const bool multiline = tk.find('\n') != std::string_view::npos;
  auto is_sep = [multiline](char c) { return c == '\n' || (!multiline && c == ' '); };
  while (pos < tk.size()) {
    size_t end = pos;
    while (end < tk.size() && !is_sep(tk[end])) ++end;
    std::string_view rec(tk.data() + pos, end - pos);
    pos = end + 1;

    while (!rec.empty() && rec.front() == '\r') {
      rec.remove_prefix(1);
    }
    while (!rec.empty() && (rec.back() == '\r')) {
      rec.remove_suffix(1);
    }
    if (rec.empty() || rec.front() == '#') continue;

    auto eq = rec.find('=');
    if (eq == std::string_view::npos) continue;

    std::string name(rec.substr(0, eq));
    std::string kind(rec.substr(eq + 1));
    // Member rows look like `NAME.field=...`; only top-level entries are types.
    if (name.find('.') != std::string::npos) continue;
    if (kind != "atomic" && kind != "struct" && kind != "union" &&
        kind != "enum" && kind != "typedef" && kind != "func" &&
        kind != "type") {
      continue;
    }
    out.emplace(std::move(name), std::move(kind));
  }
  return out;
}

}  // namespace r2xsql::json_utils
