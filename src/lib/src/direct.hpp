// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// direct.hpp — the seam between a table and radare2's C API.
//
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace r2xsql::direct {

enum class Collection { Functions, Flags, Imports, Entries, Exports, Strings, Sections, Segments, Maps };

// radare2's xref-type vocabulary, from R_ANAL_REF_TYPE_* via
// `r_anal_ref_type_tostring`: CALL, CODE, JUMP, ICOD, DATA, STRN, UNKN, NULL —
// plus the empty string, which is what a zero-typed ref looks like through
// `axtj` (that emitter omits the "type" key entirely rather than printing
// "NULL"). Classified in exactly one place so the command path and the C-API
// path cannot drift apart on what counts as code.
inline bool xref_type_is_code(std::string_view t) {
  return t == "CALL" || t == "CODE" || t == "JUMP" || t == "ICOD";
}
inline bool xref_type_is_data(std::string_view t) {
  return t == "DATA" || t == "STRN";
}

// `xrefs.kind` — r2xsql's OWN human-facing normalization of the vocabulary
// above into a smaller set. NOT a family-ratified cross-tool vocabulary --
// no shared spelling has been agreed across the tool family yet for xrefs;
// this is a deliberate, owner-approved deviation, not a quiet override.
// Exhaustive: every value `type` can take maps to exactly one of five
// buckets, so `kind` is never left unset for a row that has a `type`.
//
//   CALL       -> "call"     the single most common query shape ("who calls
//                              X") gets its own bucket rather than folding
//                              into "code".
//   JUMP       -> "jump"     a distinct control-flow shape from a call (no
//                              return expected); common enough on its own to
//                              keep separate too.
//   CODE, ICOD -> "code"     CODE is already a generic code reference; ICOD
//                              (an INDIRECT code reference) carries no more
//                              specific call/jump shape than CODE does, so it
//                              groups with it instead of getting its own
//                              bucket.
//   DATA, STRN -> "data"     STRN is a string reference, itself a DATA
//                              reference to a specific kind of memory
//                              (radare2 tracks it separately for that
//                              reason) -- `kind` stays intentionally coarse
//                              and does not carry that subtype.
//   anything else
//   (UNKN, "NULL",
//   empty/absent) -> "unknown" mirrors is_code/is_data already treating
//                              UNKN/NULL/empty as neither -- "unknown" is
//                              where every value with no more specific
//                              classification lands.
inline std::string xref_kind_for_type(std::string_view t) {
  if (t == "CALL") return "call";
  if (t == "JUMP") return "jump";
  if (t == "CODE" || t == "ICOD") return "code";
  if (t == "DATA" || t == "STRN") return "data";
  return "unknown";
}

struct XrefRow {
  int64_t     from_addr = 0;
  int64_t     to_addr   = 0;
  std::string type;

  // The function the reference originates in, as an ADDRESS (not a name).
  // `has_from_func` is false when the source is not inside any function, which
  // SQL sees as NULL — the same convention idasql and bnsql use.
  int64_t from_func     = 0;
  bool    has_from_func = false;

  bool is_code = false;
  bool is_data = false;
  std::string kind;  // r2xsql's own normalization of `type` — see above.

  // Set `type` and derive the flags/kind from it. Always assign the type
  // through this rather than touching the field, so a producer cannot forget
  // any of the three.
  void set_type(std::string t) {
    type    = std::move(t);
    is_code = xref_type_is_code(type);
    is_data = xref_type_is_data(type);
    kind    = xref_kind_for_type(type);
  }
};

// One case entry inside a block's switch_op — the command path's
// `switch_op.cases[].{addr,jump,value}`.
struct SwitchCaseData {
  int64_t addr  = 0;
  int64_t jump  = 0;
  int64_t value = 0;
};

// One basic block, carrying every field `blocks`/`cfg_edges`/`switch_tables`/
// `dominators`/`post_dominators`/`loops` read out of `afbj @ <fa>`'s JSON
// today. Promoted here (not kept in any one table's anonymous namespace)
// because ALL SIX of those tables need it once ported: they issue the
// IDENTICAL `aflj` + N×`afbj` scan in production, independently, and
// `dominators`/`post_dominators`/`loops` add only a backend-invariant local
// computation (`xsql::graph`) on top. Same TU-boundary reason FuncRow/XrefRow
// live here: each of the four `tables_*.cpp` files and `direct_libr.cpp`
// build this shape from either leg (command JSON or the C API).
//
struct BlockData {
  int64_t addr = 0;
  int64_t size = 0;
  bool    has_jump = false;
  int64_t jump     = 0;
  bool    has_fail = false;
  int64_t fail     = 0;

  bool    has_switch        = false;
  int64_t switch_instr_addr = 0;
  bool    switch_has_min    = false;
  int64_t switch_min        = 0;
  bool    switch_has_max    = false;
  int64_t switch_max        = 0;
  bool    switch_has_default = false;
  int64_t switch_default     = 0;
  std::vector<SwitchCaseData> switch_cases;
};

// One row of `instructions`' REPORTED-DATA columns -- the command path's
// `pdfj @ <fa>` (per function) or `pdj <count> @ <addr>` (arbitrary range),
// minus `disasm`/`mnemonic`. Those two are deliberately NOT here: they are
// RENDERED TEXT (radare2's disassembly renderer -- mnemonic ->
// ds_sub_jumps -> r_asm_parse_filter, all driven by RDisasmState/mid-flag/
// mid-BB state), with no exported C-API equivalent (verified by reading
// `r_core_print_disasm_json_ipi`, `libr/core/disasm.c`, in full).
// `instructions`' SQL surface is PROJECTION-GATED:
// this producer is used only when a query's column mask does not include
// `disasm`/`mnemonic`; a query that selects either always falls back to the
// unchanged command path (`tables_instructions.cpp`'s `insns_for_func`/
// `insns_from_range`), so rendered text stays exactly what radare2's own
// renderer produces.
//
// A genuine two-decoder quirk in the command path's own emitter, verified
// by reading the source rather than assumed: `size` there is
// `ds->analop.size` (the ANAL-side decode, `r_anal_op`), but `bytes` is
// sliced by `asmop.size` (a SEPARATE ASM-side decode, `r_asm_disassemble`).
// This producer calls only `r_anal_op` (never `r_asm_disassemble` -- that
// call exists purely to build the mnemonic), reading `bytes` from its own
// per-block/per-range read buffer sliced by `op.size` -- measured, the two decoders never
// disagreed on length or
// on which addresses fail to decode, across five real/generated fixtures,
// but this is a live risk to keep in mind if a future radare2 arch plugin
// ever changes that.
struct InsnRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string bytes;
  int64_t     func_addr = 0;
  std::string esil;
  std::string op_type;
  std::string family;
};

struct FuncRow {
  int64_t     addr = 0;
  std::string name;
  int64_t     size  = 0;
  int64_t     nbbs  = 0;
  int64_t     edges = 0;
  int64_t     cc    = 0;
  std::string type;
  std::string calltype;
  std::string prototype;

  // Fields `aflj` has always emitted and this table used to discard. Free on
  // the command path (they arrive in the same JSON object) and one call each on
  // the C-API path.
  //
  int64_t end_addr   = 0;   // `maxaddr`: past the highest block, NOT addr+size
  int64_t ninstrs    = 0;
  int64_t stackframe = 0;
  int64_t cost       = 0;
  int64_t tracecov   = 0;
  bool    is_noreturn  = false;
  bool    is_pure      = false;
  bool    is_recursive = false;
};

// One row of `locals`'s flattened variable/argument list — the command
// path's `aflj` + one `afvj @ <fa>` PER FUNCTION, one row per (reg/sp/bp)
// entry in that call's JSON.
//
// `storage` uses r2xsql's OWN naming, not radare2's RAnalVarKind letters:
// the command path's "sp" JSON group (radare2's R_ANAL_VAR_KIND_SPV) is
// `storage = "stack"`, and its "bp" group (R_ANAL_VAR_KIND_BPV) is
// `storage = "spv"`. Do not "correct" this to match radare2's own BPV/SPV
// letters — it would silently swap the two on a column already shipped.
//
// `size` stays 0 on both legs by design: `afvj` carries no size, so there is
// nothing for either producer to read.
struct LocalRow {
  int64_t     func_addr = 0;
  std::string name;
  std::string kind;         // "reg" (always, for a REG-kind var) | "arg" | "var"
  std::string storage;      // "reg" | "stack" | "spv" -- see the naming note above
  std::string storage_ref;  // register name for "reg"; "<base>+/-0x<hex>" otherwise
  std::string type;
  int64_t     size = 0;
};

// One row of `flags` -- the command path's `fj` (full dump) + one
// `fs <space>; fj; fs *` PER FLAGSPACE to attribute the real space onto each
// flag by name (see tables_flags.cpp's `build_flags`). The already-shipped
// real-flagspace fix stays intact through either producer: both read the
// SAME underlying truth (radare2's own `RFlagItem::space`), so this struct's
// `space` field is never a guess on either leg.
//
// `realname` carries a real quirk of radare2's own `fj` emitter
// (`print_flag_json`, libr/flag/flag.c:422-450) that a producer must
// reproduce exactly: the JSON key is omitted under a POINTER-EQUALITY test
// (`fi->realname && fi->name != fi->realname`), not a string-content one --
// `r_flag_set`'s `set_name` helper points a fresh flag's `realname` at the
// EXACT SAME pooled string as `name` until something (e.g. demangling) gives
// it a genuinely distinct one. `realname` therefore reads back "" for the
// common case on both legs, and only a non-empty, ACTUALLY different string
// otherwise -- never the same text re-echoed under a different pointer.
struct FlagRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string name;
  std::string realname;
  std::string space;
};

// One row of `strings` -- the command path's `izj`. `izj`'s own command
// handler already calls `r_bin_get_strings` itself (verified by reading
// `bin_strings`, libr/core/cbin.c) -- this is not "parse vs read a struct",
// it is "read the struct, JSON-serialize it, then re-parse the JSON" vs
// "read the struct", so both producers walk the SAME underlying
// `RVecRBinString` in the SAME order. `section` has no backing field on
// `RBinString` at all -- it is resolved per row via `r_bin_get_section_at`;
// `vaddr` is rebased through `r_bin_get_vaddr`, not read off the raw member;
// `type` is rendered through `r_bin_string_type`, not the raw char code.
// Measured at 26-86x across a real PE, a large generated
// fixture, and a real large DLL, with exact field parity.
struct StringRow {
  int64_t     addr = 0;
  int64_t     length = 0;
  std::string section;
  std::string type;
  std::string content;
  int64_t     paddr = 0;
  int64_t     size = 0;
};

// One row of `sections` (`iSj`) or `segments` (`iSSj`) -- both commands
// share ONE radare2 producer, `r_bin_get_sections_vec`, filtered by
// `RBinSection::is_segment` in opposite directions (confirmed by reading
// `bin_sections`, libr/core/cbin.c, which takes a `print_segments` bool and
// filters the SAME vector both ways). `perm` is a RENDERED string
// (`r_str_srwx_i`), not the raw permission bitmask, and `addr` silently
// downgrades to NO rebase for a section lacking the READ permission bit --
// a real per-row branch on the section's own `perm`, not a fixed `va` mode
// for the whole table. Measured at 19-58x (`sections`) and
// 58-195x (`segments`, vacuous on every PE fixture tested -- no PE section
// sets `is_segment`, so this rides `sections`' proven-live shared producer)
// with exact field parity.
struct SectionRow {
  int64_t     addr = 0;
  int64_t     vsize = 0;
  int64_t     paddr = 0;
  int64_t     size = 0;
  std::string name;
  std::string perm;
};

// One row of `imports` -- the command path's `iij`. `name` is NOT
// `RBinImport::name` -- `bin_imports` (libr/core/cbin.c) builds it from
// `r_bin_name_tostring`, then (since `bin.demangle` defaults to true)
// reshapes it through `r_bin_demangle` to `"sym.imp.<demangled>"` whenever
// demangling succeeds. `addr` (the "plt" column) is `r_core_bin_impaddr`,
// computed with the ORIGINAL (pre-demangle) name and gated on
// `RBinInfo::has_lit`. All of this goes through PUBLIC `R_API` calls, never
// a private/static helper -- the producer calls the same functions the
// emitter calls, it does not reimplement demangling or address resolution.
// Measured at 10-13x across a real PE, a large generated
// fixture, and a real 1986-import DLL, with exact field parity (the
// genuine C++-demangling branch itself is unexercised by any available
// fixture -- radare2 is a C codebase, so every fixture's imports are
// unmangled; recorded as a scope limit, not assumed safe).
struct ImportRow {
  int64_t     addr = 0;   // "plt"
  int64_t     ordinal = 0;
  std::string bind;
  std::string type;
  std::string name;
  std::string module;
};

// One row of `comments` -- the command path's `CCj`, a single full-scan
// command (not an N+1-per-function shape, unlike `funcs`/`xrefs`/`locals`/the
// blocks cluster -- the same "one command already" shape measured for
// `strings`/`sections`/`imports`/`entries`). Measured at 5-70x with exact field parity, including two quirks found by
// reading `r_meta_print` (`libr/anal/meta.c`) rather than assumed from the
// struct:
//
//   * `type` is NEVER the literal string "comment" -- it is
//     `r_meta_type_tostring(R_META_TYPE_COMMENT)`, which resolves through a
//     static lookup table to the literal string "CCu" (the r2 WRITE command
//     that creates a comment). This is pre-existing production behavior on
//     the command path, not something this port introduces.
//   * `text` is `r_str_escape(item->str)`, not the raw stored bytes, for the
//     JSON render path specifically: a real newline becomes the two
//     characters `\` + `n`, a real backslash becomes two backslashes, and any
//     byte outside ASCII 0x20-0x7E (including every byte of a multi-byte
//     UTF-8 sequence) becomes a four-character `\xHH` hex escape. Also
//     pre-existing production behavior -- the producer below reproduces it by
//     calling the SAME public `r_str_escape` R_API function the command
//     emitter itself calls, not by copying `item->str` or reimplementing the
//     escaping rules.
//
// A meta node whose `str` is NULL (created by e.g. `CCu ""`, which stores an
// empty comment as a NULL `str`) is invisible to `CCj` and must be skipped
// here too, not surfaced as a placeholder row.
struct CommentRow {
  int64_t     addr = 0;
  std::string type;
  std::string text;
};

// One row of `entries` -- the command path's `iej` (entry points) + `iEj`
// (exports), merged by address (this project's own `merge_row`, preserved
// exactly on the API leg). `iej`'s JSON never emits `name`/`size`/`bind`
// (confirmed by reading `bin_entry`'s JSON block field-by-field) but DOES
// emit `type` via `r_bin_entry_type_string` -- an early probe omitted
// this and showed a real parity failure before the producer was corrected.
// `entries.name` is NOT the demangled name despite living one call away from
// a full demangling pipeline: reading `bin_symbols`' JSON emit block found
// the `"name"` key is `r_bin_name_tostring2(sym->name, 'o')` (the ORIGINAL
// name), UTF8-escaped -- the demangled form goes to a separate `"demname"`
// key this table never reads. `its_an_export` (`!is_imported && bind ==
// "GLOBAL"`) is a private/static helper in radare2 but trivial to reproduce
// without calling it. Measured at 9-78x across a real PE,
// a large generated fixture, and a real 755-export DLL, with exact
// field parity.
struct EntryRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string type;
  std::string bind;
  std::string name;
};

struct SymbolRow : EntryRow {
  bool is_imported = false;
};

struct IoMapRow {
  int64_t     start_addr = 0;
  int64_t     end_addr = 0;
  int64_t     paddr = 0;
  int64_t     map_id = 0;
  int64_t     fd = 0;
  std::string perm;
  std::string name;
};

struct PatchRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string original_bytes;
  std::string patched_bytes;
  int         committed = 0;
  bool        is_stack_top = false;
};

struct SyscallRow {
  std::string name;
  int64_t     num = 0;
  std::string arch;
  std::string os;
};

struct RegisterRow {
  std::string                name;
  std::string                type;
  int64_t                    size   = 0;
  int64_t                    offset = 0;
  std::optional<std::string> role;
  std::string                arch;
  std::string                bits;
};

struct CallingConventionRow {
  std::string                name;
  std::vector<std::string>   args;
  std::optional<std::string> ret;
  std::vector<std::string>   rets;
  std::optional<std::string> argn;
};

struct ClassRow {
  std::string                name;
  std::optional<std::string> base_name;
  std::optional<int64_t>     vtable_addr;
};

struct ClassMethodRow {
  std::string             class_name;
  std::string              name;
  int64_t                  addr = 0;
  std::optional<int64_t>   vtable_offset;
};

struct LibRow {
  std::string name;
};

struct ProjectRow {
  std::string name;
};

struct TypeRow {
  int64_t     ordinal = 0;
  std::string name;
  std::string kind;
  int64_t     size = 0;
  std::string format;
};

struct MemberRow {
  std::string type_name;
  std::string parent_kind;
  std::string member_name;
  std::string member_type;
  int64_t     offset = 0;
  int64_t     size = 0;
  int64_t     array_size = 1;
  int64_t     value = 0;
};

struct BinaryRow {
  std::string key;
  std::string value;
  std::string type;
};

struct RelocRow {
  int64_t                     addr  = 0;
  int64_t                     paddr = 0;
  std::string                 type;
  int64_t                     ntype = 0;
  std::optional<std::string>  name;
  std::optional<std::string>  demname;
  std::optional<int64_t>      sym_vaddr;
  bool                        is_ifunc = false;
};

// The C-API row producers, one method per command shape a ported table has.
// Implemented only by libr; see `Backend::direct()`, which returns nullptr on
// every backend that has no in-process radare2.
class Api {
 public:
  virtual ~Api() = default;
  virtual size_t estimate_count(Collection collection) = 0;
  virtual void binary_info(std::vector<BinaryRow>& out) = 0;
  virtual std::string file_path() = 0;
  virtual std::string engine_version() = 0;
  // Demangle an arbitrary symbol using the current RBinFile and bin.lang
  // setting. Empty result means radare2 could not demangle the name; error
  // receives the same diagnostic as iDj in that case.
  virtual std::string demangle(const std::string& mangled,
                               const std::string& lang, std::string& error) = 0;
  virtual bool entry_address(int64_t& out) = 0;
  virtual void relocs_scan(std::vector<RelocRow>& out) = 0;
  virtual void type_members_scan(std::vector<MemberRow>& out) = 0;
  virtual void types_scan(std::vector<TypeRow>& out) = 0;
  virtual void projects_scan(std::vector<ProjectRow> &out) = 0;
  virtual void libs_scan(std::vector<LibRow> &out) = 0;
  virtual void class_methods_scan(std::vector<ClassMethodRow> &out) = 0;
  virtual void classes_scan(std::vector<ClassRow> &out) = 0;
  virtual void calling_conventions_scan(std::vector<CallingConventionRow> &out) = 0;
  virtual void registers_scan(std::vector<RegisterRow> &out) = 0;
  virtual void syscalls_scan(std::vector<SyscallRow> &out) = 0;

  // True only when addr is exactly a function entry. Avoids command/JSON
  // round-trips for scoped SQL pushdowns on the in-process backend.
  virtual bool function_is_start(int64_t addr) = 0;
  virtual bool function_owner(int64_t addr, int64_t& out) = 0;
  virtual void function_starts(std::vector<int64_t>& out) = 0;
  virtual bool function_details(int64_t addr, bool with_prototype, FuncRow& out) = 0;
  virtual bool calling_convention_exists(const std::string& name) = 0;

  // `xrefs` full scan — the command path's `aflj` + one `afxj` per function.
  virtual void xrefs_scan(std::vector<XrefRow>& out) = 0;

  // `xrefs` refs TO an address — the command path's `axtj @ <addr>`.
  virtual void xrefs_to(int64_t to_addr, std::vector<XrefRow>& out) = 0;

  // `xrefs` refs FROM an address — the command path's `axfj @ <addr>`.
  virtual void xrefs_from(int64_t from_addr, std::vector<XrefRow>& out) = 0;

  // `xrefs` refs originating anywhere INSIDE one function — the command path's
  // `afxj @ <func_addr>`, i.e. one iteration of the full scan. `func_addr` must
  // be the function's start; an address merely inside one yields nothing, since
  // that is what `from_func = <that address>` means.
  virtual void xrefs_in_func(int64_t func_addr, std::vector<XrefRow>& out) = 0;

  // Raw bytes from radare2's IO layer — the command path's `p8 <len> @ <addr>`.
  // Returns false when the read fails or is short; `out` is then untouched.
  //
  // This is not a table producer: it removes a per-row command from one. It is
  // deliberately NOT a reimplementation of anything — the caller still asks
  // radare2 to do the work it is good at, and only the byte fetch moves.
  virtual bool read_bytes(int64_t addr, size_t len, std::vector<uint8_t>& out) = 0;

  // `funcs` full scan — the command path's `aflj`.
  //
  // `with_prototype` exists because the signature is not free the way the other
  // eight fields are: radare2 builds it per function from the type database,
  // and it dominates the cost of this scan. The caller passes false whenever
  // the query does not read that column.
  // `with_cost` gates r_anal_function_cost, which decodes every instruction
  // and is most of a prototype-less scan (it left cost 0 when false).
  virtual void funcs_scan(bool with_prototype, bool with_cost,
                          std::vector<FuncRow>& out) = 0;

  // `funcs` equality lookup -- the command path's `afij @ <addr>`, restricted
  // to a function STARTING at `addr`. False when none does.
  virtual bool func_at(int64_t addr, bool with_prototype, bool with_cost,
                       FuncRow& out) = 0;

  // `blocks`/`cfg_edges`/`switch_tables`/`dominators`/`post_dominators`/
  // `loops` — ONE function's basic-block list, the command path's
  // `afbj @ <func_addr>`. `out` is left empty if `func_addr` is not a
  // function start (matching `afbj`'s "no function here" behaviour, which
  // prints an empty array).
  virtual void blocks_in_func(int64_t func_addr, std::vector<BlockData>& out) = 0;

  // The same six tables' full scan — the command path's `aflj` + one
  // `afbj @ <fa>` PER FUNCTION. `out` gets one (func_addr, block list) entry
  // per function, in `core->anal->fcns` order; a function with zero blocks
  // still gets an entry with an empty block list.
  virtual void blocks_scan(
      std::vector<std::pair<int64_t, std::vector<BlockData>>>& out) = 0;

  // `locals` full scan — the command path's `aflj` + one `afvj @ <fa>` PER
  // FUNCTION. A REG-kind variable whose register index does not resolve is
  // silently OMITTED, mirroring `afvj`'s own JSON, which never opens the row
  // object for such a variable — never emitted as a placeholder row.
  virtual void locals_scan(std::vector<LocalRow>& out) = 0;

  // `instructions`' REPORTED-DATA columns, ONE function — the command path's
  // `pdfj @ <func_addr>`, minus `disasm`/`mnemonic` (see InsnRow's comment).
  // Walks `fcn->bbs` SORTED BY ADDRESS (matching `pdfj`'s own `bb_cmpaddr`
  // sort — required for a non-contiguous function, whose lowest-address
  // block can sit below the function's own entry; measured live against a
  // 64-bit PE's `entry0`, the exact shape, coming out right this way).
  // `out` is left empty if `func_addr` is not a function start.
  virtual void instructions_in_func(int64_t func_addr, std::vector<InsnRow>& out) = 0;

  // `instructions`' REPORTED-DATA columns, full scan — the command path's
  // `aflj` + one `pdfj @ <fa>` PER FUNCTION, minus `disasm`/`mnemonic`. `out`
  // is flat, in `core->anal->fcns` order (matching the command path's own
  // `aflj` iteration order), each row's `func_addr` naming its owner.
  virtual void instructions_scan(std::vector<InsnRow>& out) = 0;

  // `instructions`' REPORTED-DATA columns for an arbitrary address RANGE —
  // the command path's `pdj <count> @ <start_addr>`, minus `disasm`/
  // `mnemonic`. NOT function-scoped: `func_addr` is always 0 on these rows
  // (see `tables_instructions.cpp`'s file header for why — a linear walk
  // cannot resolve an owning function the way `func_addr` does). Decodes
  // exactly `count` instructions starting at `start_addr`, or fewer if a
  // decode fails or runs off mapped memory (matching `pdj`'s own behaviour).
  virtual void instructions_range(int64_t start_addr, int64_t count,
                                  std::vector<InsnRow>& out) = 0;

  // `flags` full scan -- the command path's `fj` (full dump) + one
  // `fs <name>; fj; fs *` PER FLAGSPACE (to attribute the real space back
  // onto each flag by name). One pass over `r_flag_foreach`, reading
  // `fi->{addr,size,name,realname,space->name}` directly -- no `fs`
  // selection, no per-space re-listing, no session-state save/restore at
  // all, since `r_flag_foreach` is not scoped by the currently-selected
  // flagspace the way the `fj` COMMAND is. Measured at
  // 17-47x on a full scan across a real binary and generated fixtures, plus
  // a real large DLL, with exact field parity -- including the pointer-
  // equality `realname` quirk -- before being ported.
  virtual void flags_scan(std::vector<FlagRow>& out, const char* space = nullptr,
                          bool current_space = false) = 0;
  virtual bool flag_at(const std::string& name, const std::string& space, int64_t addr) = 0;

  // `strings` full scan -- the command path's `izj`. `with_content` mirrors
  // the existing projection optimization (skip copying the string body when
  // the query does not read `content`); the section/type lookups are always
  // cheap enough to do unconditionally.
  virtual void strings_scan(bool with_content, std::vector<StringRow>& out) = 0;

  // `sections` (`want_segment=false`, `iSj`) or `segments`
  // (`want_segment=true`, `iSSj`) full scan -- ONE shared producer,
  // `r_bin_get_sections_vec`, filtered by `is_segment` in opposite
  // directions, exactly as the two commands filter the same vector.
  virtual void sections_scan(bool want_segment, std::vector<SectionRow>& out) = 0;

  // `imports` full scan -- the command path's `iij`.
  virtual void imports_scan(std::vector<ImportRow>& out) = 0;

  // `entries` full scan -- the command path's `iej` + `iEj`, merged by
  // address exactly as `tables_exports.cpp`'s own `merge_row` does.
  virtual void entries_scan(std::vector<EntryRow>& out) = 0;
  virtual void symbols_scan(std::vector<SymbolRow>& out) = 0;
  virtual void io_maps_scan(std::vector<IoMapRow>& out) = 0;
  virtual void patches_scan(std::vector<PatchRow>& out) = 0;

  // `comments` full scan -- the command path's `CCj`, a single full-scan
  // command (no per-function or per-address loop to collapse). Walks
  // `core->anal->meta` directly, filtered to `R_META_TYPE_COMMENT` and to the
  // currently-selected meta-space (if any -- see CommentRow's comment for
  // why that guard is load-bearing, not optional), skipping any node whose
  // `str` is NULL exactly as `CCj` does.
  virtual void comments_scan(std::vector<CommentRow>& out) = 0;

  // --- WRITE paths -----------------------------------------------------
  //
  // Unlike every READ producer above (an N+1-per-row scan, where command
  // dispatch is paid once per row), a single write is one command either
  // way -- there is no N+1 shape to collapse. A benchmark
  // measured a BULK workload instead (N repeated writes in a loop,
  // simulating a bulk-rename/bulk-annotate script) and found each of the
  // four operations examined pays a real, per-call fixed cost for
  // command-string build + parse + dispatch -- 30-150x on N up to 500
  // writes, consistently, across five fixtures. Three of the four are
  // ported below (`comments.text`, `flags.name`, `locals.name`/`.type`);
  // `funcs.name` is NOT, because reading the actual command handler source
  // (not just its declared C-API "equivalent") found it does substantially
  // more than the raw C-API call -- see the comment on the funcs table for
  // why that is a parity failure, not a speed question.

  // `comments.text` set/update -- the command path's `CCu base64:<b64>`.
  // Reproduces `CCu`'s own dedup-skip quirk, verified by reading
  // `cmd_meta.inc.c`'s `case 'u'` handler: if the EXISTING comment at `addr`
  // already contains `text` as a byte substring, the write is silently
  // skipped (a no-op), not overwritten. `r_meta_set_string` itself has no
  // such check -- the caller must reproduce it, or a real, observable
  // behavior a SQL UPDATE could rely on today would change under this port.
  // Returns false only when `r_meta_set_string` itself reports failure
  // (never observed in practice for a validated, non-null address/text; the
  // dedup-skip path returns true, since a skip is not a failure).
  virtual bool comment_set(int64_t addr, const std::string& text) = 0;

  // `flags.name` rename -- the command path's `fr <old> <new>`. Verified by
  // reading `cmd_flag.inc.c`'s `case 'r'` handler: it is a plain
  // `r_flag_get` (by name) + `r_flag_rename`, with no other side effect --
  // unlike `funcs.name`'s `afn`, `fr` does NOT also touch any sdb key or
  // fire a rename callback. No address parameter: neither `r_flag_get` nor
  // `r_flag_rename` needs one (the command path only carries an address at
  // all because `Backend::cmd_noeval` requires a seek anchor to dispatch
  // through -- a workaround this C-API leg needs none of). Returns false
  // when no flag named `old_name` exists, or the rename itself is rejected
  // (e.g. `new_name` collides with an existing flag).
  virtual bool flag_rename(const std::string& old_name, const std::string& new_name) = 0;

  // `locals.name` rename -- the command path's
  // `afvn <new> <old> @ <func_addr>`. Verified by reading `cmd_anal.inc.c`'s
  // `case 'n'` (under `afv`) handler: once the old/new names are parsed, it
  // is exactly `r_anal_function_get_var_byname` + `r_anal_var_rename` -- no
  // other side effect (the handler's `r_core_anal_op` call is dead work on
  // this path, only used when the OLD name is omitted and must be inferred
  // from the cursor, which r2xsql never does). Returns false when the
  // function or the named variable does not exist, or radare2 rejects the
  // new name (`r_anal_var_check_name`, or a collision with an existing
  // variable of that name).
  virtual bool var_rename(int64_t func_addr, const std::string& old_name,
                           const std::string& new_name) = 0;

  // `locals.type` retype -- the command path's
  // `afvt <name> <type> @ <func_addr>`. Verified by reading
  // `cmd_anal.inc.c`'s `case 't'` (under `afv`) handler: exactly
  // `r_anal_function_get_var_byname` + `r_anal_var_set_type`, no other side
  // effect. Returns false only when the function or the named variable does
  // not exist; `r_anal_var_set_type` itself is `void` (unconditional once a
  // var is found).
  virtual bool var_set_type(int64_t func_addr, const std::string& name,
                             const std::string& type) = 0;
};

std::unique_ptr<Api> make_libr_api(void* core, std::mutex& core_mutex);

}  // namespace r2xsql::direct
