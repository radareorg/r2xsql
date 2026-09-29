// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// instructions — per-function disassembly via `pdfj @ <addr>`. A `func_addr`
// equality filter is pushed down: `WHERE func_addr = X` issues a single
// `pdfj @ X` instead of enumerating every function. An unfiltered scan walks
// `aflj` then issues `pdfj @` per function.
//
// A SECOND, independent pushdown reads an arbitrary address range instead of
// a function: `WHERE start_addr = X AND count = N` issues `pdj N @ X`, which
// emits op objects field-identical to pdfj's own (same underlying emitter,
// no new parsing). It is NOT a substitute for `func_addr`: `pdj` walks bytes
// linearly from `start_addr`, so it cannot reach a block that sits below its
// own function's entry (non-contiguous functions are real), and it does not
// know which function (if any) owns the addresses it walks, so `func_addr`
// is always 0 on rows this pushdown produces.
//
// A THIRD axis, orthogonal to which of the two shapes above ran: PROJECTION
// GATING. This table conflates two kinds of column — REPORTED DATA (`addr`,
// `size`, `bytes`, `func_addr`, `esil`, `op_type`, `family`, plus the
// client-computed `seq`/`canonical_op`) and RENDERED TEXT (`disasm`, and
// `mnemonic` derived from it — radare2's own disassembly renderer, no
// exported C-API entry point). Whenever a query's projection does NOT read
// `disasm`/`mnemonic`, every producer below (full scan, `func_addr`
// pushdown, `start_addr`/`count` pushdown) uses a fast C-API leg instead
// (`direct::Api::instructions_scan`/`instructions_in_func`/
// `instructions_range`, `direct_libr.cpp`) — measured at 3.97-8.11x with
// exact field parity on every reported-data column in a private standalone
// benchmark before this port was built. A query that DOES read either
// rendered-text column always falls back to the unchanged command path
// below, on every producer shape, so `disasm`/`mnemonic` stay exactly what
// radare2's own renderer produces — never approximated. The pipe backend
// has no C-API leg at all
// (`Backend::direct()` is null there), so it always uses the command path
// regardless of projection — unaffected by this gate.

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
struct InsnRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string mnemonic;
  std::string disasm;
  std::string bytes;
  int64_t     func_addr = 0;
  std::string esil;        // radare2's stack IL for this instruction
  int         seq = 0;         // per-function instruction index (cross-tool low-IR)
  std::string op_type;         // radare2 semantic op type ("add", "call", "cjmp", ...)
  std::string canonical_op;    // cross-tool canonical P-code-style op; "" if none
  std::string family;          // radare2 op family ("cpu", "fpu", "sse", "priv", ...)
};

// radare2 op `type` string -> canonical P-code-style op (cross-tool low-IR).
// r2 is the lowest-fidelity leg (disasm/ESIL, no SSA); "" for types with no clean
// canonical (stack push/pop, cmp/test flag ops, nop, trap, ...).
std::string r2_canonical_op(const std::string& t) {
  if (t == "mov" || t == "lea" || t == "cast" || t == "movs") return "COPY";
  if (t == "load") return "LOAD";
  if (t == "store") return "STORE";
  if (t == "add") return "INT_ADD";
  if (t == "sub") return "INT_SUB";
  if (t == "mul") return "INT_MULT";
  if (t == "div") return "INT_DIV";
  if (t == "mod") return "INT_REM";
  if (t == "and") return "INT_AND";
  if (t == "or")  return "INT_OR";
  if (t == "xor") return "INT_XOR";
  if (t == "shl") return "INT_LEFT";
  if (t == "shr") return "INT_RIGHT";
  if (t == "sar") return "INT_SRIGHT";
  if (t == "not" || t == "cpl") return "INT_NEGATE";
  if (t == "call" || t == "rcall" || t == "ccall") return "CALL";
  if (t == "ucall" || t == "icall" || t == "ircall" || t == "uccall") return "CALLIND";
  if (t == "jmp" || t == "rjmp") return "BRANCH";
  if (t == "ujmp" || t == "ijmp" || t == "mjmp" || t == "irjmp") return "BRANCHIND";
  if (t == "cjmp" || t == "mcjmp" || t == "rcjmp" || t == "ucjmp") return "CBRANCH";
  if (t == "ret" || t == "cret") return "RETURN";
  return "";
}

// One scoped `pdfj @ <fa>` call → the instructions of a single function.
std::string mnemonic_from_op(const nlohmann::json& op) {
  std::string text = json_utils::str(op, "opcode");
  if (text.empty()) text = json_utils::str(op, "disasm");
  if (text.empty()) return json_utils::str(op, "type");
  const size_t pos = text.find_first_of(" \t\r\n");
  return pos == std::string::npos ? text : text.substr(0, pos);
}

// Shared per-op field extraction: pdfj's ops and pdj's ops are the same
// emitter, same shape, so both producers below build an InsnRow this way.
InsnRow row_from_op(const nlohmann::json& op, int64_t func_addr, int seq) {
  InsnRow r;
  r.addr      = json_utils::i64_addr(op);
  r.size      = json_utils::i64(op, "size");
  r.mnemonic  = mnemonic_from_op(op);
  r.disasm    = json_utils::str(op, "disasm");
  r.bytes     = json_utils::str(op, "bytes");
  r.esil      = json_utils::str(op, "esil");
  r.func_addr = func_addr;
  r.seq       = seq;
  r.op_type   = json_utils::str(op, "type");
  r.canonical_op = r2_canonical_op(r.op_type);
  r.family    = json_utils::str(op, "family");
  return r;
}

std::vector<InsnRow> insns_for_func(Backend* be, int64_t fa) {
  std::vector<InsnRow> out;
  auto pdf = be->cmd_json("pdfj @ " + json_utils::hex_addr(fa));
  if (!pdf.is_object()) return out;
  auto ops = pdf.find("ops");
  if (ops == pdf.end() || !ops->is_array()) return out;
  int seq = 0;
  for (auto& op : *ops) out.push_back(row_from_op(op, fa, seq++));
  return out;
}

// `pdj <count> @ <start_addr>` — a linear walk from an arbitrary address,
// not scoped to any function (func_addr is always 0 on these rows; see
// the file header for why this can't resolve an owning function the way
// func_addr does). `pdj`'s own JSON is a bare array of op objects (unlike
// pdfj's `{ops: [...]}` object wrapper).
std::vector<InsnRow> insns_from_range(Backend* be, int64_t start_addr, int64_t count) {
  std::vector<InsnRow> out;
  if (count <= 0) return out;
  auto ops = be->cmd_json("pdj " + std::to_string(count) + " @ " +
                          json_utils::hex_addr(start_addr));
  if (!ops.is_array()) return out;
  int seq = 0;
  for (auto& op : ops) out.push_back(row_from_op(op, 0, seq++));
  return out;
}

// --- Projection gate ---------------------------------------------------
//
// Column indices below are POSITIONAL, matching the `.column_*` call order
// in `register_instructions_table` (addr=0, size=1, mnemonic=2, disasm=3,
// ...) — the same "colUsed bit == column index" convention `tables_funcs.cpp`
// already uses for its own `prototype` projection gate.
constexpr uint64_t kColUsedAll    = 1ull << 63;
constexpr uint64_t kMnemonicColBit = 1ull << 2;
constexpr uint64_t kDisasmColBit   = 1ull << 3;

// True whenever the query's projection could read RENDERED TEXT
// (`mnemonic`/`disasm` — see the file header). Every producer below stays on
// the unchanged command path whenever this is true, so rendered text is
// always exactly what radare2's own renderer produces; only when false, AND
// a C-API leg is available (`Backend::direct()` non-null — never true for
// the pipe backend), does a producer switch to the fast leg.
bool needs_render(uint64_t col_used) {
  return (col_used & kColUsedAll) || (col_used & kMnemonicColBit) ||
         (col_used & kDisasmColBit);
}

// --- C-API leg: converts direct::InsnRow (reported-data columns only,
// direct.hpp) into this table's own InsnRow, leaving mnemonic/disasm empty
// (never produced by this leg — see the file header) and computing
// seq/canonical_op client-side exactly as the command-path producers above
// do. Measured at 3.97-8.11x with exact field parity across five fixtures
// and two probe shapes, in a private standalone benchmark, before this port
// was built.
// -------------------------------------------------------------------------

InsnRow insn_from_direct(const direct::InsnRow& d, int seq) {
  InsnRow r;
  r.addr         = d.addr;
  r.size         = d.size;
  // mnemonic/disasm intentionally left empty: rendered text, never produced
  // by the C-API leg. This function is only ever called when the query's
  // projection does not read either column (needs_render() gates every
  // call site below), so an empty value here is never observed by SQL.
  r.bytes        = d.bytes;
  r.func_addr    = d.func_addr;
  r.esil         = d.esil;
  r.seq          = seq;
  r.op_type      = d.op_type;
  r.canonical_op = r2_canonical_op(d.op_type);
  r.family       = d.family;
  return r;
}

std::vector<InsnRow> insns_for_func_api(direct::Api* api, int64_t fa) {
  std::vector<direct::InsnRow> raw;
  api->instructions_in_func(fa, raw);
  std::vector<InsnRow> out;
  out.reserve(raw.size());
  int seq = 0;
  for (auto& d : raw) out.push_back(insn_from_direct(d, seq++));
  return out;
}

// Full scan: `direct::Api::instructions_scan` walks functions in
// `core->anal->fcns` order, one function's rows contiguous — mirrored here
// by resetting `seq` at each `func_addr` change, exactly matching the
// command path's own per-function reset (one `pdfj` call per function,
// `seq` restarting at 0 each time).
std::vector<InsnRow> insns_scan_api(direct::Api* api) {
  std::vector<direct::InsnRow> raw;
  api->instructions_scan(raw);
  std::vector<InsnRow> out;
  out.reserve(raw.size());
  int seq = 0;
  int64_t last_func = 0;
  bool first = true;
  for (auto& d : raw) {
    if (first || d.func_addr != last_func) {
      seq = 0;
      first = false;
      last_func = d.func_addr;
    }
    out.push_back(insn_from_direct(d, seq++));
  }
  return out;
}

std::vector<InsnRow> insns_range_api(direct::Api* api, int64_t start_addr, int64_t count) {
  std::vector<direct::InsnRow> raw;
  api->instructions_range(start_addr, count, raw);
  std::vector<InsnRow> out;
  out.reserve(raw.size());
  int seq = 0;
  for (auto& d : raw) out.push_back(insn_from_direct(d, seq++));
  return out;
}

// Generic generator wrapping an already-materialized row vector — shared by
// every producer that computes its full row set up front: both C-API legs,
// and the pdj-based start_addr/count range pushdown's command-path leg
// (which was already eager before the projection gate existed).
class InsnsVecGen : public xsql::Generator<InsnRow> {
  std::vector<InsnRow> rows_;
  size_t idx_ = 0;
  InsnRow cur_;
 public:
  explicit InsnsVecGen(std::vector<InsnRow> rows) : rows_(std::move(rows)) {}
  bool next() override {
    if (idx_ >= rows_.size()) return false;
    cur_ = rows_[idx_++];
    return true;
  }
  const InsnRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

// Full, unfiltered scan — command-path leg. Lazily streams: `aflj` is issued
// once, and each function's `pdfj` runs only as `next()` reaches it, so a
// `LIMIT`-bounded query never pays for functions past what it consumed.
class InsnsGen : public xsql::Generator<InsnRow> {
  Backend* be_;
  std::vector<int64_t> funcs_;
  size_t fi_ = 0;
  std::vector<InsnRow> buf_;
  size_t bi_ = 0;
  InsnRow cur_;
 public:
  explicit InsnsGen(Backend* be) : be_(be), funcs_(table_utils::function_starts(be)) {}
  bool next() override {
    for (;;) {
      if (bi_ < buf_.size()) { cur_ = buf_[bi_++]; return true; }
      if (fi_ >= funcs_.size()) return false;
      buf_ = insns_for_func(be_, funcs_[fi_++]);
      bi_ = 0;
    }
  }
  const InsnRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

class InsnsInFuncIterator : public xsql::RowIterator {
  std::vector<InsnRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  explicit InsnsInFuncIterator(std::vector<InsnRow> rows) : rows_(std::move(rows)) {}
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const InsnRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;
      case 1: ctx.result_int64(r.size); break;
      case 2: ctx.result_text(r.mnemonic); break;
      case 3: ctx.result_text(r.disasm); break;
      case 4: ctx.result_text(r.bytes); break;
      case 5: ctx.result_int64(r.func_addr); break;
      case 6: ctx.result_text(r.esil); break;
      case 7: ctx.result_int(r.seq); break;
      case 8: ctx.result_text(r.op_type); break;
      case 9: ctx.result_text(r.canonical_op); break;
      case 10: ctx.result_text(r.family); break;
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return rows_[i_].addr; }
};
}  // namespace

void register_instructions_table(Session& s) {
  auto def = xsql::generator_table<InsnRow>("instructions")
    .estimate_rows([]() -> size_t { return 100000; })
    // Full scan: projection-gated between the command path (InsnsGen, lazy)
    // and the C-API leg (InsnsVecGen over instructions_scan) — see the file
    // header. The pipe backend's Backend::direct() is always null, so it
    // always takes the command-path branch regardless of colUsed.
    .projection_generator([be = s.backend_ptr()](uint64_t col_used)
        -> std::unique_ptr<xsql::Generator<InsnRow>> {
      if (!needs_render(col_used)) {
        if (auto* api = be->direct()) {
          return std::make_unique<InsnsVecGen>(insns_scan_api(api));
        }
      }
      return std::make_unique<InsnsGen>(be);
    })
    .column_int64("addr",      [](const InsnRow& r) { return r.addr; })
    .column_int64("size",      [](const InsnRow& r) { return r.size; })
    .column_text ("mnemonic",  [](const InsnRow& r) { return r.mnemonic; })
    .column_text ("disasm",    [](const InsnRow& r) { return r.disasm; })
    .column_text ("bytes",     [](const InsnRow& r) { return r.bytes; })
    .column_int64("func_addr", [](const InsnRow& r) { return r.func_addr; })
    // ESIL (radare2's stack IL), from the same pdfj op object — no extra r2 command.
    .column_text ("esil",      [](const InsnRow& r) { return r.esil; })
    // Cross-tool low-IR: per-function seq + radare2 semantic op type + canonical map.
    .column_int  ("seq",          [](const InsnRow& r) { return r.seq; })
    .column_text ("op_type",      [](const InsnRow& r) { return r.op_type; })
    .column_text ("canonical_op", [](const InsnRow& r) { return r.canonical_op; })
    // radare2's instruction family — the cheap way to find FPU/SSE/privileged
    // code without pattern-matching mnemonics. Same pdfj object, no extra cost.
    .column_text ("family",       [](const InsnRow& r) { return r.family; })
    // func_addr pushdown: projection-gated the same way as the full scan.
    .filter_eq_projection("func_addr",
      [be = s.backend_ptr()](int64_t fa, uint64_t col_used) -> std::unique_ptr<xsql::RowIterator> {
        if (!needs_render(col_used)) {
          if (auto* api = be->direct()) {
            return std::make_unique<InsnsInFuncIterator>(insns_for_func_api(api, fa));
          }
        }
        // Rendered projections use pdfj even when a direct API is available.
        if (!table_utils::func_addr_is_start(be, fa)) {
          return std::make_unique<InsnsInFuncIterator>(std::vector<InsnRow>{});
        }
        return std::make_unique<InsnsInFuncIterator>(insns_for_func(be, fa));
      }, 5.0, 64.0)
    // Arbitrary-address disassembly: WHERE start_addr = X AND count = N
    // (both required together — a linear pdj walk, not a function scope).
    // Independent of the func_addr pushdown above; see the file header.
    // Also projection-gated the same way.
    .hidden_column_int64("start_addr")
    .hidden_column_int64("count")
    .parametric_filter_projection({"start_addr", "count"},
      [be = s.backend_ptr()](const std::vector<xsql::FunctionArg>& args, uint64_t col_used)
          -> std::unique_ptr<xsql::Generator<InsnRow>> {
        // omit=1: exact integers only (xsql::exact_int64); 4096.5 or NULL is
        // no rows, never a walk from a truncated address.
        const auto start_opt = xsql::exact_int64(args[0]);
        const auto count_opt = xsql::exact_int64(args[1]);
        if (!start_opt || !count_opt) return nullptr;
        const int64_t start_addr = *start_opt;
        const int64_t count = *count_opt;
        if (!needs_render(col_used)) {
          if (auto* api = be->direct()) {
            return std::make_unique<InsnsVecGen>(insns_range_api(api, start_addr, count));
          }
        }
        return std::make_unique<InsnsVecGen>(insns_from_range(be, start_addr, count));
      }, 3.0, 64.0)
    .build();
  s.db().register_and_create_generator_table(def);

  // NOTE: the cross-tool low-IR views (ir_ops / ir_v_* / ir_operands / ir_maturities) now
  // project from the FINER esil_ops / esil_operands stream (see tables_esil.cpp), not the
  // coarse one-op.type-per-instruction path. The coarse op_type/canonical_op columns stay on
  // `instructions` for cheap per-instruction classification.
}

}  // namespace r2xsql
