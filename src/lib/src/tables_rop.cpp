// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// rop_gadgets / rop_gadget_instructions — ROP/JOP/COP gadget search, backed
// by radare2's `/g` gadget-search family (`/gj`, `/gRj`/`/gCj`/`/gJj` for
// return-/call-/jump-terminated). Every gadget search command emits one JSON
// object per gadget with an `opcodes` array, a `retaddr` (the address of the
// gadget's own terminating instruction, NOT a resolved branch target), a
// total `size`, and a `classes` array that radare2 computes unconditionally
// (no extra command, no config gate). `rop_gadgets` is one summary row per
// gadget; `rop_gadget_instructions` is one row per constituent instruction,
// keyed back to its parent by `gadget_addr` — the project's existing
// parent/child pattern (funcs+locals, types+types_members), applied here
// because a gadget's instruction sequence doesn't fit one flat row.
//
// Hidden input columns on `rop_gadgets`: `pattern` (an opstring substring
// match, validated below before it's spliced into a command), `terminator`
// (`ret`/`call`/`jmp`/`any`, selecting `/gRj`/`/gCj`/`/gJj`/`/gj`), `klass`
// (radare2's own gadget-class vocabulary, matched client-side against the
// `classes` array a search already returns — see the note below on why this
// is NOT routed through `/gkj`), and `max_results` (client-side cap on the
// result count, same convention as byte_search.max_results). None are
// required: an unfiltered `/gj` scan over the whole configured search scope
// is a real, bounded answer, not an error.
//
// `search.in` is r2 session config that leaks past the command that sets it
// (verified directly: set it, run an unrelated command, read it back — the
// new value is still there). There is no automatic restore, exactly the
// property that forced the flags table's atomic flagspace-select pattern.
// Every search here runs as ONE `Backend::cmd()`/`cmd_json()` call that sets
// the scope, searches, and puts the scope back — never as separate calls
// with anything else in between, since the in-process plugin shares one
// core across its interactive/HTTP/MCP callers and a leaked scope would
// corrupt a concurrent caller's search. The scope is always restored to
// radare2's own documented default (`io.maps`) rather than a value read back
// in a separate round trip first — the same "restore to the neutral
// default, not a racily-read prior value" choice the flagspace fix already
// made for the same class of hazard.
//
// The default search scope is `io.maps.x` (executable maps only), not
// radare2's own CLI default of `io.maps` (all IO maps, code and data).
// Measured directly: `io.maps` surfaces real false positives — gadgets whose
// first instruction sits in a non-executable region (string tables, data
// manufactured into "gadgets" that were never code). A caller who genuinely
// wants to search data-as-code can still do so outside this table's surface;
// the default here must not manufacture false positives.
//
// `klass` is matched client-side against each gadget's own `classes` array,
// NOT by issuing `/gkj <klass>`. Reading the radare2 source that backs `/gk`
// (rop_kuery / gadget_kuery_json) shows it does not run a search at all: it
// queries a persistent, on-disk-shaped cache keyed by gadget class that is
// only populated when the `gadget.sdb` config is enabled (default OFF,
// documented "experimental") during an EARLIER `/g` search, and even then it
// emits a different, thinner shape (address/size/type/effect strings) with
// no `opcodes` array — not enough to build `rop_gadget_instructions` rows,
// and it would add a second leaking, off-by-default global config to
// save/restore on top of `search.in`. Filtering the already-free `classes`
// field from a normal search produces the identical final row set (radare2
// computes membership in exactly this vocabulary to build `classes` in the
// first place) without either problem.
//
// IMPORTANT, verified directly against a real search (not assumed from the
// source): the unfiltered ("any" terminator) gadget set is NOT a strict
// superset of a terminator-filtered one, address for address. `/gj` walks
// backward from qualifying end instructions and marks consumed start bytes
// per pass, so a start address `/gRj` finds is not guaranteed to also start
// a gadget in a bare `/gj` pass, even though `/gj`'s per-instruction
// end-of-gadget test is a logical OR of the ret/call/jump tests. Consequence:
// `rop_gadget_instructions` carries the SAME hidden columns as `rop_gadgets`
// (`pattern`/`terminator`/`klass`/`max_results`), not a fixed default search,
// so a caller who filtered `rop_gadgets` and wants the matching instructions
// must apply the SAME filter values to `rop_gadget_instructions` (e.g. `...
// JOIN rop_gadget_instructions gi ON gi.gadget_addr = g.addr WHERE
// g.terminator = 'ret' AND gi.terminator = 'ret'`) -- an unfiltered scan of
// one side and a filtered scan of the other are two genuinely different
// gadget sets, not a superset/subset pair.
//
// Cost characteristic this implies: a lookup scoped to a SINGLE known
// `gadget_addr` (the normal drill-in pattern -- find a gadget via
// `rop_gadgets`, then read its instructions with the same filters) costs one
// search, same as any other query against this table. A JOIN against MANY
// `rop_gadgets` rows at once re-runs that search ONCE PER OUTER ROW, because
// neither table exposes an address-equality pushdown cheap enough for
// SQLite to bind into a nested-loop join -- there is no such primitive to
// bind it to. A caller that wants every gadget's instructions together
// should query `rop_gadget_instructions` directly with the same filters
// (it already carries `gadget_addr` as a plain output column, and one scan
// covers every matching gadget), rather than join it against `rop_gadgets`
// row by row. Making a cross-row join cheap would need a cache shared
// across the whole session, which every other table in this project
// deliberately avoids for state radare2 can mutate out of band; whether
// that trade-off is worth making for this specifically expensive,
// otherwise-immutable-per-session search is left open, matching the
// design's own explicit deferral of any "at-scale" cost mitigation beyond
// what was measured.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {

// One constituent instruction of a gadget, as radare2's `/g...j` emits it.
struct GadgetOp {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string opcode;  // rendered disassembly text, same renderer as pdfj/pdj
  std::string type;    // radare2's own op-type classification
};

// One gadget, as radare2's `/g...j` emits it -- the full shape, before it is
// split across the two SQL tables below.
struct GadgetRec {
  int64_t                  addr = 0;     // first instruction's address
  int64_t                  retaddr = 0;  // terminating instruction's OWN address
  int64_t                  size = 0;     // total byte length
  std::vector<std::string> classes;      // radare2's klass vocabulary, verbatim
  std::vector<GadgetOp>    ops;
};

// radare2's own gadget-class vocabulary (the full set the engine can
// compute, including the two conditional-jump refinements gated behind
// `gadget.esil`), used verbatim so `klass` never invents a parallel naming
// scheme.
const std::unordered_set<std::string>& klass_vocab() {
  static const std::unordered_set<std::string> v = {
      "ret", "jop", "cop", "cond.always", "cond.controlled", "syscall",
      "pivot", "memread", "memwrite", "www", "rww", "signal", "mov",
      "ldconst", "arithm", "logic", "shift", "cmp", "nop", "arithm_ct",
  };
  return v;
}

// `pattern` is spliced into a live r2 command as an opstring substring match
// (see the command construction below). Accept only characters that can
// appear in rendered disassembly text -- alnum, space, and the punctuation
// disasm actually uses (`, . + - * [ ] ( ) : % # _`) -- and reject every r2
// command separator/metacharacter (`; @ | & $ < > " ' backtick newline`, ...)
// so a pattern can never inject a second command.
bool valid_gadget_pattern(const std::string& p) {
  if (p.empty()) return false;
  for (unsigned char c : p) {
    if (std::isalnum(c)) continue;
    switch (c) {
      case ' ': case ',': case '.': case '+': case '-': case '*':
      case '[': case ']': case '(': case ')': case ':': case '%':
      case '#': case '_':
        continue;
      default:
        return false;
    }
  }
  return true;
}

struct SearchParams {
  std::string pattern;
  std::string terminator = "any";
  std::string klass;
  int64_t     max_results = 0;
};

// Validates params that came from user input (pattern/terminator/klass).
// Returns an empty string when valid, else a caller-facing error message.
std::string validate_params(const SearchParams& p) {
  if (!p.pattern.empty() && !valid_gadget_pattern(p.pattern)) {
    return "rop_gadgets: pattern accepts only disassembly-safe characters "
           "(letters, digits, space, and ,.+-*[]():%#_)";
  }
  if (p.terminator != "any" && p.terminator != "ret" &&
      p.terminator != "call" && p.terminator != "jmp") {
    return "rop_gadgets: terminator must be one of 'ret', 'call', 'jmp', 'any'";
  }
  if (!p.klass.empty() && klass_vocab().find(p.klass) == klass_vocab().end()) {
    return "rop_gadgets: klass must be one of radare2's own gadget klass "
           "names (ret, jop, cop, cond.always, cond.controlled, syscall, "
           "pivot, memread, memwrite, www, rww, signal, mov, ldconst, "
           "arithm, logic, shift, cmp, nop, arithm_ct)";
  }
  return {};
}

char terminator_letter(const std::string& t) {
  if (t == "ret") return 'R';
  if (t == "call") return 'C';
  if (t == "jmp") return 'J';
  return 0;  // "any" -> plain /gj, no letter
}

std::string join_comma(const std::vector<std::string>& parts) {
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) out += ',';
    out += parts[i];
  }
  return out;
}

// Runs one gadget search (params already validated by the caller) and
// returns the full parsed result set, `classes`-filtered by `klass` and
// capped by `max_results` client-side. Empty (not an error) on a search that
// finds nothing, or if the command's JSON fails to parse.
std::vector<GadgetRec> run_gadget_search(Backend* be, const SearchParams& p) {
  std::vector<GadgetRec> out;

  std::string search_cmd = "/g";
  if (const char letter = terminator_letter(p.terminator)) search_cmd += letter;
  search_cmd += 'j';
  if (!p.pattern.empty()) {
    search_cmd += ' ';
    search_cmd += p.pattern;
  }

  // Atomic: set scope, search, restore scope -- one command, see file header.
  const std::string atomic =
      "e search.in=io.maps.x; " + search_cmd + "; e search.in=io.maps";
  auto hits = be->cmd_json(atomic);
  if (!hits.is_array()) return out;

  for (auto& g : hits) {
    if (!g.is_object()) continue;
    GadgetRec rec;
    rec.retaddr = json_utils::i64(g, "retaddr");
    rec.size    = json_utils::i64(g, "size");

    auto ops_it = g.find("opcodes");
    if (ops_it != g.end() && ops_it->is_array()) {
      rec.ops.reserve(ops_it->size());
      for (auto& op : *ops_it) {
        GadgetOp o;
        o.addr   = json_utils::i64_addr(op);
        o.size   = json_utils::i64(op, "size");
        o.opcode = json_utils::str(op, "opcode");
        o.type   = json_utils::str(op, "type");
        rec.ops.push_back(std::move(o));
      }
    }
    if (!rec.ops.empty()) rec.addr = rec.ops.front().addr;

    auto classes_it = g.find("classes");
    if (classes_it != g.end() && classes_it->is_array()) {
      rec.classes.reserve(classes_it->size());
      for (auto& c : *classes_it) {
        if (c.is_string()) rec.classes.push_back(c.get<std::string>());
      }
    }

    if (!p.klass.empty() &&
        std::find(rec.classes.begin(), rec.classes.end(), p.klass) ==
            rec.classes.end()) {
      continue;
    }

    out.push_back(std::move(rec));
    if (p.max_results > 0 &&
        static_cast<int64_t>(out.size()) >= p.max_results) {
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// rop_gadgets
// ---------------------------------------------------------------------------

struct GadgetRow {
  int64_t     addr = 0;
  int64_t     retaddr = 0;
  int64_t     size = 0;
  std::string classes;
  int64_t     ninstrs = 0;
};

// Visible columns first, hidden inputs after -- keep in sync with the
// .column_*()/.hidden_column_*() declaration order below.
enum GadgetCol {
  kGAddr = 0, kGRetaddr = 1, kGSize = 2, kGClasses = 3, kGNinstrs = 4,
  kGPattern = 5, kGTerminator = 6, kGKlass = 7, kGMaxResults = 8,
};

class RopGadgetsGen : public xsql::Generator<GadgetRow> {
  std::vector<GadgetRow> rows_;
  size_t idx_ = 0;
  GadgetRow cur_;
 public:
  explicit RopGadgetsGen(std::vector<GadgetRec> recs) {
    rows_.reserve(recs.size());
    for (auto& r : recs) {
      GadgetRow row;
      row.addr    = r.addr;
      row.retaddr = r.retaddr;
      row.size    = r.size;
      row.classes = join_comma(r.classes);
      row.ninstrs = static_cast<int64_t>(r.ops.size());
      rows_.push_back(std::move(row));
    }
  }
  bool next() override {
    if (idx_ >= rows_.size()) return false;
    cur_ = rows_[idx_++];
    return true;
  }
  const GadgetRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

std::unique_ptr<xsql::Generator<GadgetRow>> make_gadgets_gen(
    Backend* be, const SearchParams& p) {
  const std::string err = validate_params(p);
  if (!err.empty()) {
    xsql::set_vtab_error(err);
    return std::make_unique<RopGadgetsGen>(std::vector<GadgetRec>{});
  }
  return std::make_unique<RopGadgetsGen>(run_gadget_search(be, p));
}

// ---------------------------------------------------------------------------
// rop_gadget_instructions
// ---------------------------------------------------------------------------

struct GadgetInstrRow {
  int64_t     gadget_addr = 0;
  int64_t     seq = 0;
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string opcode;
  std::string type;
};

// Visible columns first, hidden inputs after -- same shape/order as
// GadgetCol above, and MUST take the same input values for a join against
// `rop_gadgets` to see a consistent gadget set (see the file header).
enum GadgetInstrCol {
  kGiGadgetAddr = 0, kGiSeq = 1, kGiAddr = 2, kGiSize = 3, kGiOpcode = 4, kGiType = 5,
  kGiPattern = 6, kGiTerminator = 7, kGiKlass = 8, kGiMaxResults = 9,
};

class RopGadgetInstructionsGen : public xsql::Generator<GadgetInstrRow> {
  std::vector<GadgetInstrRow> rows_;
  size_t idx_ = 0;
  GadgetInstrRow cur_;
 public:
  explicit RopGadgetInstructionsGen(std::vector<GadgetRec> recs) {
    for (auto& r : recs) {
      int64_t seq = 0;
      for (auto& op : r.ops) {
        GadgetInstrRow row;
        row.gadget_addr = r.addr;
        row.seq         = seq++;
        row.addr        = op.addr;
        row.size        = op.size;
        row.opcode      = op.opcode;
        row.type        = op.type;
        rows_.push_back(std::move(row));
      }
    }
  }
  bool next() override {
    if (idx_ >= rows_.size()) return false;
    cur_ = rows_[idx_++];
    return true;
  }
  const GadgetInstrRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

std::unique_ptr<xsql::Generator<GadgetInstrRow>> make_gadget_instrs_gen(
    Backend* be, const SearchParams& p) {
  const std::string err = validate_params(p);
  if (!err.empty()) {
    xsql::set_vtab_error(err);
    return std::make_unique<RopGadgetInstructionsGen>(std::vector<GadgetRec>{});
  }
  return std::make_unique<RopGadgetInstructionsGen>(run_gadget_search(be, p));
}

}  // namespace

void register_rop_gadgets_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<GadgetRow>> {
    SearchParams p;
    for (const auto& a : args) {
      switch (a.column_index) {
        case kGPattern: {
          const char* v = a.value.as_c_str();
          if (v) p.pattern = v;
          break;
        }
        case kGTerminator: {
          const char* v = a.value.as_c_str();
          if (v && *v) p.terminator = v;
          break;
        }
        case kGKlass: {
          const char* v = a.value.as_c_str();
          if (v) p.klass = v;
          break;
        }
        case kGMaxResults:
          p.max_results = a.value.as_int64();
          break;
        default:
          break;
      }
    }
    return make_gadgets_gen(be, p);
  };

  auto def = xsql::generator_table<GadgetRow>("rop_gadgets")
    .estimate_rows([]() -> size_t { return 128; })
    .generator([be = s.backend_ptr()]() {
      return make_gadgets_gen(be, SearchParams{});
    })
    .column_int64("addr",    [](const GadgetRow& r) { return r.addr; })
    .column_int64("retaddr", [](const GadgetRow& r) { return r.retaddr; })
    .column_int64("size",    [](const GadgetRow& r) { return r.size; })
    .column_text ("classes", [](const GadgetRow& r) { return r.classes; })
    .column_int64("ninstrs", [](const GadgetRow& r) { return r.ninstrs; })
    .hidden_column_text ("pattern")
    .hidden_column_text ("terminator")
    .hidden_column_text ("klass")
    .hidden_column_int64("max_results")
    .constraint_filter(
        {xsql::optional_eq("pattern"), xsql::optional_eq("terminator"),
         xsql::optional_eq("klass"), xsql::optional_eq("max_results")},
        make_gen, 2.0, 128.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

void register_rop_gadget_instructions_table(Session& s) {
  auto make_gen = [be = s.backend_ptr()](
      const std::vector<xsql::GeneratorConstraintArg>& args)
      -> std::unique_ptr<xsql::Generator<GadgetInstrRow>> {
    SearchParams p;
    for (const auto& a : args) {
      switch (a.column_index) {
        case kGiPattern: {
          const char* v = a.value.as_c_str();
          if (v) p.pattern = v;
          break;
        }
        case kGiTerminator: {
          const char* v = a.value.as_c_str();
          if (v && *v) p.terminator = v;
          break;
        }
        case kGiKlass: {
          const char* v = a.value.as_c_str();
          if (v) p.klass = v;
          break;
        }
        case kGiMaxResults:
          p.max_results = a.value.as_int64();
          break;
        default:
          break;
      }
    }
    return make_gadget_instrs_gen(be, p);
  };

  auto def = xsql::generator_table<GadgetInstrRow>("rop_gadget_instructions")
    .estimate_rows([]() -> size_t { return 1024; })
    .generator([be = s.backend_ptr()]() {
      return make_gadget_instrs_gen(be, SearchParams{});
    })
    .column_int64("gadget_addr", [](const GadgetInstrRow& r) { return r.gadget_addr; })
    .column_int64("seq",         [](const GadgetInstrRow& r) { return r.seq; })
    .column_int64("addr",        [](const GadgetInstrRow& r) { return r.addr; })
    .column_int64("size",        [](const GadgetInstrRow& r) { return r.size; })
    .column_text ("opcode",      [](const GadgetInstrRow& r) { return r.opcode; })
    .column_text ("type",        [](const GadgetInstrRow& r) { return r.type; })
    .hidden_column_text ("pattern")
    .hidden_column_text ("terminator")
    .hidden_column_text ("klass")
    .hidden_column_int64("max_results")
    .constraint_filter(
        {xsql::optional_eq("pattern"), xsql::optional_eq("terminator"),
         xsql::optional_eq("klass"), xsql::optional_eq("max_results")},
        make_gen, 2.0, 512.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
