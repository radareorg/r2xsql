// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace r2xsql::json_utils {

// Safe accessors that never throw on missing keys / wrong types.
std::string str(const nlohmann::json& obj, std::string_view key, std::string_view dflt = "");
int64_t     i64(const nlohmann::json& obj, std::string_view key, int64_t dflt = 0);
int32_t     i32(const nlohmann::json& obj, std::string_view key, int32_t dflt = 0);
bool        boolean(const nlohmann::json& obj, std::string_view key, bool dflt = false);

// Address field accessor. r2's JSON commands inconsistently name the
// virtual-address field: `aflj` / `afbj` / `pdfj` / `fj` use `addr`,
// while `CCj` and older surfaces use `offset`. This helper tries
// `addr` first and falls back to `offset`, returning `dflt` if neither
// is present. Use this for every "the address of this record" lookup
// so the tables don't break when r2 renames a key between versions.
int64_t     i64_addr(const nlohmann::json& obj, int64_t dflt = 0);

// Quote a string for use as a shell-ish r2 command argument. r2 itself is
// not a shell, but spaces, quotes and backslashes need escaping in CC args.
std::string r2_quote(std::string_view s);

// True iff `name` is safe to splice into an r2 flag command unquoted: a
// non-empty string of [A-Za-z0-9._$] only. This is roughly r2's own flag-name
// charset; rejecting anything else prevents a name with spaces or command
// separators (`;`, `@`, `|`, backtick, …) from breaking parsing or injecting
// extra r2 commands. Use to gate INSERT/UPDATE on the flags/bookmarks tables.
bool valid_flag_name(std::string_view name);

// True iff `type` is a safe C type string to splice into an r2 `afvt` command
// unquoted: a non-empty string of type-syntax characters only —
// [A-Za-z0-9_.* space []] . r2's `afvt <name> <type>` takes the type verbatim
// (and stores literal quotes if you wrap it), so spaces and `*`/`[]` for
// pointer/array types are allowed, but every r2 command metacharacter
// (`@ ; | & < > $ " ' backtick newline` ...) is rejected so a type value can't
// split into extra `afvt` args or inject r2 commands. Use to gate UPDATE ...
// SET type on the locals table.
bool valid_type_text(std::string_view type);

// True iff `text` is a one-line C declaration that can be placed inside a
// fully r2-quoted `td` command.
bool valid_c_declaration(std::string_view text);

// True iff `text` is a balanced C function signature safe to pass unquoted to
// `afs`. Unlike `valid_c_declaration`, this rejects every r2 command separator,
// including semicolons and ampersands.
bool valid_c_signature(std::string_view text);

// True iff `perm` is a safe radare2 IO-map permission spec: a non-empty string
// of [rwx-] only (e.g. "rwx", "r-x", "rw-"). Rejecting anything else prevents a
// perm value with spaces/metacharacters from splitting into extra `om` args or
// injecting r2 commands when spliced into `om $d <vaddr> <size> <paddr> <perm>`.
bool valid_perm(std::string_view perm);

// Hex address formatter ("0x401000").
std::string hex_addr(int64_t addr);

// Base64-encode arbitrary bytes (standard alphabet, '=' padding). Use to pass
// free-form text to radare2 commands that accept a `base64:...` argument (e.g.
// `CCu base64:<b64> @ addr`), which avoids all quoting/escaping/injection
// issues — r2's plain `CCu <text>` takes the text verbatim, so quoting it would
// store the quotes literally.
std::string base64_encode(std::string_view s);

// Parse `tk*` output (sdb format). Each non-empty record is "NAME=KIND".
// Records may be separated by '\n', "\r\n", or ' ' depending on which r2
// command path produced them (libr cmd vs r2pipe interactive). Returns the
// map of top-level type entries (those without '.' in the name) whose kind
// is one of: atomic, struct, union, enum, typedef, func, type.
std::unordered_map<std::string, std::string> parse_tk_dump(std::string_view tk);

}  // namespace r2xsql::json_utils
