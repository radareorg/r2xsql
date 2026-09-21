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

inline bool resolve_func_owner(Backend* be, int64_t addr, int64_t& out) {
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

// Fixed seek anchor for structural no-eval dispatch of a command that is NOT
// address-scoped at all -- currently only radare2's type-system commands,
// `td`/`t-` (see tables_types.cpp's INSERT/DELETE). Each address-scoped
// table write has a real row address to pass to `Backend::cmd_noeval`; the type system has none (a
// struct/union/enum definition is not tied to any address). Verified against
// radare2's own source rather than assumed: `cmd_type.inc.c`'s handlers for
// both `td` (case 'd', the `input[1]==' '` branch) and `t-` (case '-') read
// only from `core->anal` -- never `core->addr` or the current seek -- so
// which address is current during their dispatch is unobservable to them,
// and any fixed value works. `r_core_call_at` (`libr/core/cmd.c`) also skips
// the seek entirely when the target already equals the current position
// (`mustseek = addr != oaddr`), so this constant is not even guaranteed to
// cost a seek; when it does, that cost is the same plain `r_io_seek` +
// block-buffer re-read (restored right after -- `cmd_noeval`'s seek is
// strictly temporary) that every other ported table's write already pays
// whenever its own real address differs from the current position. 0 was
// chosen simply because it needs no session state to produce.
constexpr int64_t kTypeSystemAnchorAddr = 0;

// Structural no-eval dispatch for a command with NO address anywhere in its
// own grammar (unlike `dispatch_write`-shaped helpers elsewhere, which splice
// `@ <addr>` onto the fallback command) -- currently only the type system's
// `td`/`t-`. Tries `Backend::cmd_noeval` first, seeked to
// `kTypeSystemAnchorAddr`; falls back to `fallback_command` VERBATIM (no
// address suffix -- there is nothing to suffix) on every backend that reports
// it unsupported (r2pipe, mock), so those backends keep issuing the exact
// byte-for-byte command text this write path always issued.
//
// `noeval_command` and `fallback_command` may differ: a command whose
// fallback needs r2's own quoting to survive `r_core_cmd0`'s command-chaining
// evaluation (e.g. `td` wrapped in `json_utils::r2_quote`) must NOT be quoted
// for the no-eval path -- `cmd_noeval` already never evaluates that grammar
// (it dispatches through `r_cmd_call`, which does no re-scanning at all), so
// a quote wrapper would be taken as literal argument text instead of being
// stripped the way `r_core_cmd0`'s evaluator strips it.
inline std::string dispatch_type_write(Backend* be, const std::string& noeval_command,
                                        const std::string& fallback_command) {
  std::string out;
  if (be->cmd_noeval(kTypeSystemAnchorAddr, noeval_command, &out)) return out;
  return be->cmd(fallback_command);
}

// Convenience overload for when the same command text is correct on both
// paths (e.g. `t-`, which never needed quoting on either path).
inline std::string dispatch_type_write(Backend* be, const std::string& command) {
  return dispatch_type_write(be, command, command);
}

// Assemble `asm_text` at `addr` via radare2's `pa` command (verified live
// against the current radare2 build: `pa <asm>` prints a bare hexpairs line
// on success -- no JSON mode exists, confirmed against `cmd_print.inc.c`'s
// `cmd_pa`/help_msg_pa -- and prints NOTHING to stdout on failure; its
// diagnostic, e.g. "Cannot assemble '<asm>' at line 1", goes to stderr via
// R_LOG_ERROR and is invisible to Backend::cmd()/cmd_noeval's captured
// output, so an empty result is the only failure signal available here).
//
// `addr` matters even for a simple assemble: `cmd_pa` calls
// `r_asm_set_pc(core->rasm, core->addr)` before assembling, so pc-relative
// encodings (rip-relative loads, short branches) depend on which address is
// current. `Backend::cmd_noeval`'s own temporary seek supplies this
// correctly on the libr backend; the pipe/mock fallback uses the plain
// `@ <addr>` seek suffix every other address-scoped write in this project
// already relies on (tables_patches.cpp's `dispatch_write`, etc.).
//
// `asm_text` MUST already pass `json_utils::valid_asm_source_text` before
// this is called (not re-checked here, so a caller can produce its own
// table-specific error message) -- that charset allowlist is what makes
// splicing `asm_text` unquoted into the command safe on every backend, the
// same reasoning `patches`' hex-validated `wx` path and `rop_gadgets`'
// charset-validated `pattern` already established; cmd_noeval is layered on
// top for defense-in-depth (same "wired in anyway... not because a real gap
// was found here" posture tables_patches.cpp documents for its own `wx`),
// not because the charset guarantee alone is insufficient.
//
// Returns false (leaving `out_hex` untouched) when radare2 produced no
// usable output at all -- a bad mnemonic, an operand radare2's assembler
// rejects, or (defensively) a result that isn't valid hex.
inline bool assemble_hex(Backend* be, int64_t addr, const std::string& asm_text,
                          std::string* out_hex) {
  const std::string command = "pa " + asm_text;
  std::string out;
  if (!be->cmd_noeval(addr, command, &out)) {
    out = be->cmd(command + " @ " + json_utils::hex_addr(addr));
  }
  out = trim_ascii(out);
  if (out.empty() || !json_utils::valid_hex_bytes(out)) return false;
  *out_hex = out;
  return true;
}

}  // namespace r2xsql::table_utils
