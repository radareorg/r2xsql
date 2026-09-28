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
#include <vector>

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




// True iff `type` is a safe C type string to splice into an r2 `afvt` command
// unquoted: a non-empty string of type-syntax characters only —
// [A-Za-z0-9_.* space []] . r2's `afvt <name> <type>` takes the type verbatim
// (and stores literal quotes if you wrap it), so spaces and `*`/`[]` for
// pointer/array types are allowed, but every r2 command metacharacter
// (`@ ; | & < > $ " ' backtick newline` ...) is rejected so a type value can't
// split into extra `afvt` args or inject r2 commands. Use to gate UPDATE ...
// SET type on the locals table.
bool valid_type_text(std::string_view type);

// True iff `text` is a balanced C function signature safe to pass unquoted to
// `afs`. This rejects every r2 command separator,
// including semicolons and ampersands.
bool valid_c_signature(std::string_view text);

// True iff `perm` is a safe radare2 IO-map permission spec: a non-empty string
// of [rwx-] only (e.g. "rwx", "r-x", "rw-"). Rejecting anything else prevents a
// perm value with spaces/metacharacters from splitting into extra `om` args or
// injecting r2 commands when spliced into `om $d <vaddr> <size> <paddr> <perm>`.
bool valid_perm(std::string_view perm);

// True iff `text` is safe assembly-mnemonic source text to splice unquoted
// into radare2's assembler-family commands (`pa`/`/a`, see tables_assemble.cpp
// and the `patches` table's `asm_text` INSERT column): alnum, space, and the
// punctuation real disassembly/assembly text actually uses
// (`, . + - * / [ ] ( ) : % # _ $`). Rejects every r2 command
// separator/metacharacter (`; @ | & < > " ' backtick newline`, ...), so a
// caller-supplied instruction can never inject a second command -- the same
// allowlist-over-quoting CHOICE tables_rop.cpp's local `valid_gadget_pattern`
// already made for the nearly identical "opstr text" shape (a separate,
// slightly narrower charset there since it only ever matches EXISTING
// disassembly text, never assembles new instructions -- this one is shared
// across `assemble`/`search_asm`/`patches.asm_text`, which all splice
// caller-supplied ASSEMBLY SOURCE, so it lives here in json_utils rather
// than as a fourth local copy). NOT used for `demangle`'s `mangled` input:
// MSVC/Rust manglings routinely need `?`/`@` characters this charset
// excludes, so that table uses Backend::cmd_noeval instead (see
// tables_demangle.cpp).
bool valid_asm_source_text(std::string_view text);

// Hex address formatter ("0x401000").
std::string hex_addr(int64_t addr);

// True iff `c` is one of [0-9a-fA-F].
bool is_hex_digit(char c);

// Strip whitespace so "48 89" and "4889" both reach r2's hex-taking commands
// (which want a contiguous token). Shared normalizer for every hex-string
// input surface (byte_search's pattern, patches' patched_bytes, ...).
std::string compact_hex(std::string_view in);

// True iff `hex` is a non-empty, even-length string of hex digits only -- no
// wildcards, no mask separator, no whitespace. The strict format a caller
// must hand to a "concrete bytes" surface (as opposed to byte_search's
// wildcard-capable search pattern). Run `hex` through compact_hex() first if
// it may carry whitespace.
bool valid_hex_bytes(std::string_view hex);

// Decode a strict hex string (see valid_hex_bytes) into raw bytes. Returns
// false and clears `out` if `hex` is not valid_hex_bytes(). The shared exact
// decoder behind byte_search's full-match re-read and the patches table's
// INSERT validation -- one decode routine backs both, so neither can drift
// from the other's definition of "valid hex."
bool hex_decode(std::string_view hex, std::vector<uint8_t>& out);

// Lenient decode used for a short/partial read (e.g. p8's response can be
// truncated): decodes complete byte-pairs greedily and stops at the first
// invalid or odd-trailing nibble instead of failing outright. `out` holds
// whatever decoded cleanly, which may be shorter than `hex.size()/2`.
void hex_decode_partial(std::string_view hex, std::vector<uint8_t>& out);

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
