// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// direct_libr.cpp — the libr (in-process radare2) side of the `direct.hpp`
// seam. Compiled ONLY into the `r2xsql_libr` OBJECT library, alongside
// `backend_libr.cpp`; the core `r2xsql` library links no radare2 and never
// sees this TU.
//
// The contract each producer must honour is stricter than "return the same
// rows": it must return what the corresponding radare2 COMMAND would have
// printed, quirks included, because both backends answer the same SQL and the
// e2e suite compares their rows. Each producer below therefore names the
// emitter it mirrors and the specific quirk it reproduces.

#include "direct.hpp"

#include <r_core.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace r2xsql::direct {

namespace {

// `r_list_foreach` expands to `pos = it->data` with `data` a void*: legal C, a
// hard error in C++. Same walk, done type-safely.
template <typename T, typename F>
void for_each_rlist(RList* list, F&& fn) {
  if (!list) return;
  for (RListIter* it = list->head; it; it = it->n) {
    if (it->data) fn(static_cast<T*>(it->data));
  }
}

// `afxj` and `axfj` both print `r_anal_ref_type_tostring(ref->type)`
// unconditionally, so a zero-typed ref reads back as the literal "NULL".
std::string ref_type_string(RAnalRefType type) {
  const char* s = r_anal_ref_type_tostring(type);
  return s ? s : "";
}

// `axtj` is the exception: it guards the field with `if (ref->type)`, so a
// zero-typed ref has NO "type" key and our JSON reader yields "". Reproduce the
// absence rather than printing "NULL", or the two backends disagree on a row
// that neither of them is wrong about.
std::string ref_type_string_axtj(RAnalRefType type) {
  return type ? ref_type_string(type) : std::string();
}

// The function containing `addr`, or none. This is the same call `axtj` makes
// to fill its `fcn_addr` field. For the from_addr producer it stands in for the
// command path's `afij @ <addr>`, which filters `core->anal->fcns` by
// `r_anal_function_contains` and takes the first hit; `r_anal_get_fcn_in` takes
// the first of `r_anal_get_functions_in`. The two agree whenever one function
// contains the address, and can only differ where functions overlap — the e2e
// row-level parity check against r2pipe is what would catch that.
void set_owner(XrefRow& r, RCore* core, ut64 addr) {
  RAnalFunction* fcn = r_anal_get_fcn_in(core->anal, addr, R_ANAL_FCN_TYPE_NULL);
  if (fcn) {
    r.from_func     = static_cast<int64_t>(fcn->addr);
    r.has_from_func = true;
  }
}

// Every producer takes the owning backend's mutex, the same one `Backend::cmd`
// takes — the in-r2 plugin shares one core between its interactive and concurrent
// callers, so a direct read must not interleave with a command. It is a
// plain std::mutex, so a producer must NEVER call back into `Backend::cmd`:
// that is a self-deadlock, not a slow path. If a future port needs a command
// mid-producer, run it before taking the lock.
class LibrApi : public Api {
 public:
  LibrApi(RCore* core, std::mutex& mu) : core_(core), mu_(mu) {}

  bool function_is_start(int64_t addr) override {
    std::lock_guard lock(mu_);
    return core_ && core_->anal &&
        r_anal_get_function_at(core_->anal, static_cast<ut64>(addr));
  }

  bool function_owner(int64_t addr, int64_t& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, addr, R_ANAL_FCN_TYPE_NULL);
    if (!fcn) return false;
    out = fcn->addr;
    return true;
  }

  void function_starts(std::vector<int64_t>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      out.push_back(fcn->addr);
    });
  }

  bool function_details(int64_t addr, bool with_prototype, FuncRow& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, addr);
    if (!fcn) return false;
    out.addr = fcn->addr;
    out.stackframe = fcn->maxstack;
    if (const char* cc = r_anal_function_cc(fcn)) out.calltype = cc;
    if (with_prototype) {
      if (char* sig = r_anal_function_format_sig(core_->anal, fcn, nullptr,
                                                nullptr, nullptr, nullptr)) {
        r_str_trim(sig);
        out.prototype = sig;
        free(sig);
      }
    }
    return true;
  }

  bool calling_convention_exists(const std::string& name) override {
    std::lock_guard lock(mu_);
    return core_ && core_->anal && r_anal_cc_exist(core_->anal, name.c_str());
  }

  // Mirrors the command path's `aflj` + `afxj @ <fn>` per function.
  void xrefs_scan(std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      RVecAnalRef* refs = r_anal_function_get_refs(fcn);
      if (!refs) return;
      RAnalRef* ref;
      R_VEC_FOREACH (refs, ref) {
        XrefRow r;
        // Refs FROM a function: the varying source is `ref->at`, the target is
        // `ref->addr`. This is the OPPOSITE of `r_anal_xrefs_get` below, where
        // `at` comes back equal to the queried address on every row. Reading
        // `at` for both yields the right row COUNT and entirely wrong data.
        r.from_addr = static_cast<int64_t>(ref->at);
        r.to_addr   = static_cast<int64_t>(ref->addr);
        r.set_type(ref_type_string(ref->type));
        r.from_func     = static_cast<int64_t>(fcn->addr);
        r.has_from_func = true;
        out.push_back(std::move(r));
      }
      RVecAnalRef_free(refs);
    });
  }

  // Mirrors `axtj @ <to_addr>`.
  void xrefs_to(int64_t to_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RVecAnalRef* refs = r_anal_xrefs_get(core_->anal, static_cast<ut64>(to_addr));
    if (!refs) return;
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      // Refs TO an address: `at` is the queried end (constant on every row),
      // so the source is `ref->addr`.
      r.from_addr = static_cast<int64_t>(ref->addr);
      r.to_addr   = to_addr;
      r.set_type(ref_type_string_axtj(ref->type));
      set_owner(r, core_, ref->addr);
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors one iteration of the scan — `afxj @ <func_addr>`, which resolves
  // the function containing the address and lists its references.
  void xrefs_in_func(int64_t func_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, func_addr);
    // `from_func` is a function START, so an address merely inside a function
    // matches nothing. Without this, `afxj`'s "resolve the containing function"
    // behaviour would return that function's rows under a from_func the caller
    // never asked for — rows that violate the very constraint being pushed down.
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    RVecAnalRef* refs = r_anal_function_get_refs(fcn);
    if (!refs) return;
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      r.from_addr = static_cast<int64_t>(ref->at);
      r.to_addr   = static_cast<int64_t>(ref->addr);
      r.set_type(ref_type_string(ref->type));
      r.from_func     = func_addr;
      r.has_from_func = true;
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors `axfj @ <from_addr>`, including its owner resolution: `axfj` emits
  // no `fcn_name`/`fcn_addr` at all, so the command path resolves the owning
  // function of the source address itself with one extra `afij`.
  void xrefs_from(int64_t from_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RVecAnalRef* refs = r_anal_refs_get(core_->anal, static_cast<ut64>(from_addr));
    if (!refs) return;
    XrefRow owner;                       // resolved once, as the command path does
    set_owner(owner, core_, static_cast<ut64>(from_addr));
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      // Refs FROM an address: `at` is the queried end, `addr` is the target.
      r.from_addr = static_cast<int64_t>(ref->at);
      r.to_addr   = static_cast<int64_t>(ref->addr);
      r.set_type(ref_type_string(ref->type));
      r.from_func     = owner.from_func;
      r.has_from_func = owner.has_from_func;
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors `p8 <len> @ <addr>` — the same IO read, without rendering the bytes
  // to a hex string and parsing them back.
  bool read_bytes(int64_t addr, size_t len, std::vector<uint8_t>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->io || len == 0) return false;
    std::vector<uint8_t> buf(len);
    if (!r_io_read_at(core_->io, static_cast<ut64>(addr), buf.data(),
                      static_cast<int>(len))) {
      return false;
    }
    out = std::move(buf);
    return true;
  }

  // Mirrors `aflj`, whose per-function object radare2 builds in
  // `fcn_print_json` (libr/core/canal.c). Every field below uses the SAME call
  // that emitter uses — three of them are NOT the obvious struct member, and
  // each was verified against that function rather than guessed:
  //
  //   * `name` is `r_core_anal_fcn_name`, not `fcn->name`: it applies the
  //     demangler when `bin.demangle` is on, so the raw member can differ.
  //   * `calltype` is `r_anal_function_cc`, not `fcn->callconv`: the member can
  //     still hold the unresolved "dyncc" marker until that call resolves it.
  //   * `edges` is `r_anal_function_count_edges`, not a hand count of each
  //     block's jump/fail targets. Those can disagree, and only one of them is
  //     what `aflj` prints.
  //
  // A field-by-field parity test against the command path guards all nine.
  void funcs_scan(bool with_prototype, std::vector<FuncRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      FuncRow r;
      r.addr = static_cast<int64_t>(fcn->addr);
      if (char* name = r_core_anal_fcn_name(core_, fcn)) {
        r.name = name;
        free(name);
      }
      r.size = static_cast<int64_t>(r_anal_function_linear_size(fcn));
      r.nbbs = static_cast<int64_t>(r_list_length(fcn->bbs));
      int ebbs = 0;
      r.edges = r_anal_function_count_edges(fcn, &ebbs);
      r.cc    = r_anal_function_complexity(fcn);
      if (const char* t = r_anal_functiontype_tostring(fcn->type)) r.type = t;
      // `aflj` omits `calltype` entirely when radare2 has none, which reads
      // back as the empty string — so an absent convention must stay empty
      // rather than becoming some default.
      if (const char* cc = r_anal_function_cc(fcn)) r.calltype = cc;

      // The fields `aflj` emits and the table used to drop. Same calls
      // `fcn_print_json` makes, in the same order.
      r.end_addr    = static_cast<int64_t>(r_anal_function_max_addr(fcn));
      r.ninstrs     = r_anal_function_instrcount(fcn);
      r.stackframe  = fcn->maxstack;
      r.cost        = r_anal_function_cost(fcn);
      r.tracecov    = r_anal_function_coverage(fcn);
      r.is_noreturn = fcn->is_noreturn;
      r.is_pure     = r_anal_function_purity(fcn);
      // `recursive` has no single call behind it: radare2 computes it inline
      // (a static helper) as "does this function call itself". Same test here.
      if (RVecAnalRef* calls = r_core_anal_fcn_get_calls(core_, fcn)) {
        RAnalRef* callref;
        R_VEC_FOREACH (calls, callref) {
          if (callref->addr == fcn->addr) { r.is_recursive = true; break; }
        }
        RVecAnalRef_free(calls);
      }
      if (with_prototype) {
        // `aflj` fills `signature` by running `afcf`, which is
        // r_anal_function_format_sig with the function's own name (the NULL
        // default below), then trimming. Note this is a DIFFERENT function
        // from r_anal_function_get_signature_string, which formats its own way.
        if (char* sig = r_anal_function_format_sig(core_->anal, fcn, nullptr,
                                                   nullptr, nullptr, nullptr)) {
          r_str_trim(sig);
          r.prototype = sig;
          free(sig);
        }
      }
      out.push_back(std::move(r));
    });
  }

  // Reads one RAnalBlock into BlockData — shared by both `blocks_in_func` and
  // `blocks_scan` below so the two can never drift on what a block carries.
  static void fill_block(RAnalBlock* b, BlockData& d) {
    d.addr = static_cast<int64_t>(b->addr);
    d.size = static_cast<int64_t>(b->size);
    if (b->jump != UT64_MAX) { d.has_jump = true; d.jump = static_cast<int64_t>(b->jump); }
    if (b->fail != UT64_MAX) { d.has_fail = true; d.fail = static_cast<int64_t>(b->fail); }
    if (b->switch_op) {
      RAnalSwitchOp* sw = b->switch_op;
      d.has_switch = true;
      d.switch_instr_addr = static_cast<int64_t>(sw->addr);
      d.switch_has_min = true; d.switch_min = static_cast<int64_t>(sw->min_val);
      d.switch_has_max = true; d.switch_max = static_cast<int64_t>(sw->max_val);
      d.switch_has_default = true; d.switch_default = static_cast<int64_t>(sw->def_val);
      // sw->daddr (the jump table's own memory address) is deliberately NOT
      // read here — see BlockData's comment in direct.hpp for why it never
      // reaches `switch_tables.table_addr`.
      for_each_rlist<RAnalCaseOp>(sw->cases, [&](RAnalCaseOp* cop) {
        SwitchCaseData sc;
        sc.addr  = static_cast<int64_t>(cop->addr);
        sc.jump  = static_cast<int64_t>(cop->jump);
        sc.value = static_cast<int64_t>(cop->value);
        d.switch_cases.push_back(sc);
      });
    }
  }

  // Mirrors `afbj @ <func_addr>`: one function's block list, read straight
  // from `fcn->bbs` instead of parsed JSON.
  void blocks_in_func(int64_t func_addr, std::vector<BlockData>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, static_cast<ut64>(func_addr),
                                           R_ANAL_FCN_TYPE_NULL);
    // afbj resolves the function CONTAINING the address; the pushdown these
    // tables use is always keyed on a function START, so mirror that here too
    // — an address merely inside a function must not silently answer for it.
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
      BlockData d;
      fill_block(b, d);
      out.push_back(std::move(d));
    });
  }

  // Mirrors `aflj` + N×`afbj @ <fa>`: every function's block list, read
  // straight from `core->anal->fcns` + each function's `fcn->bbs` — no
  // commands at all.
  void blocks_scan(
      std::vector<std::pair<int64_t, std::vector<BlockData>>>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      std::vector<BlockData> blocks;
      for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
        BlockData d;
        fill_block(b, d);
        blocks.push_back(std::move(d));
      });
      out.emplace_back(static_cast<int64_t>(fcn->addr), std::move(blocks));
    });
  }

  // Formats a base register plus a signed delta as "<base>+0x.." /
  // "<base>-0x.." -- byte-identical to the command path's
  // `storage_ref_of`/`compact_type`-adjacent helper in tables_locals.cpp, so
  // the two backends can never disagree on this string's spelling.
  static std::string base_delta_ref(const char* base, int64_t delta) {
    const std::string b = base ? base : "";
    char buf[48];
    if (delta < 0) {
      const uint64_t magnitude = uint64_t{0} - static_cast<uint64_t>(delta);
      std::snprintf(buf, sizeof(buf), "%s-0x%llx", b.c_str(),
                    static_cast<unsigned long long>(magnitude));
    } else {
      std::snprintf(buf, sizeof(buf), "%s+0x%llx", b.c_str(),
                    static_cast<unsigned long long>(delta));
    }
    return std::string(buf);
  }

  // Mirrors `aflj` + N×`afvj @ <fa>`: every function's variables/arguments,
  // read straight from `fcn->vars` — no command, no per-function JSON DOM.
  // Reproduces three quirks of `r_anal_var_list_show` (the literal `afvj`
  // emitter, `libr/anal/var.c:1888-2033`) verified by reading that function,
  // not assumed from the struct:
  //
  //   * For a REG-kind var, `delta` is a REGISTER INDEX (resolved through
  //     `r_reg_index_get`), not a byte offset — unlike SPV/BPV, where it is
  //     added to `fcn->maxstack`/`fcn->bp_off`.
  //   * A REG-kind var whose index does not resolve is DROPPED entirely, not
  //     emitted with an empty ref — reproduced with `continue`, not a
  //     placeholder row, so a row-count mismatch would surface a real bug.
  //   * A REG-kind var's `kind` is always the literal "reg", never "arg",
  //     regardless of `isarg` — SPV/BPV report "arg"/"var" from `isarg`.
  //
  // `storage` uses r2xsql's OWN naming (see LocalRow's comment in
  // direct.hpp): SPV -> "stack", BPV -> "spv" — the opposite of what the
  // letters suggest.
  void locals_scan(std::vector<LocalRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      RAnalVar** it;
      R_VEC_FOREACH(&fcn->vars, it) {
        RAnalVar* var = *it;
        if (!var || !var->name || !*var->name) continue;

        LocalRow r;
        r.func_addr = static_cast<int64_t>(fcn->addr);
        r.name      = var->name;
        r.type      = var->type ? var->type : "";
        r.size      = 0;  // afvj carries no size on either leg

        switch (var->kind) {
          case R_ANAL_VAR_KIND_REG: {
            RRegItem* ri = r_reg_index_get(core_->anal->reg, var->delta);
            if (!ri) continue;  // afvj silently omits this row too
            r.kind        = "reg";
            r.storage     = "reg";
            r.storage_ref = ri->name ? ri->name : "";
            break;
          }
          case R_ANAL_VAR_KIND_SPV: {
            const char* spreg = r_reg_alias_getname(core_->anal->reg, R_REG_ALIAS_SP);
            r.kind        = var->isarg ? "arg" : "var";
            r.storage     = "stack";
            r.storage_ref = base_delta_ref(spreg ? spreg : "SP",
                                           static_cast<int64_t>(var->delta) + fcn->maxstack);
            break;
          }
          case R_ANAL_VAR_KIND_BPV: {
            const char* bpreg = r_reg_alias_getname(core_->anal->reg, R_REG_ALIAS_BP);
            r.kind        = var->isarg ? "arg" : "var";
            r.storage     = "spv";
            r.storage_ref = base_delta_ref(bpreg ? bpreg : "BP",
                                           static_cast<int64_t>(var->delta) + fcn->bp_off);
            break;
          }
          default:
            continue;
        }
        out.push_back(std::move(r));
      }
    });
  }

  // Decode mask for `instructions`' REPORTED-DATA columns -- matches what the
  // command path's own `pdfj`/`pdj` emitter requests for JSON output
  // (`ds->decode_mask`, `disasm.c:1049-1051`: BASIC|HINT|VAL|DISASM, plus
  // ESIL unconditionally since `for_json` is always true for pdfj/pdj) MINUS
  // `R_ARCH_OP_MASK_DISASM` -- that mask only fills `RAnalOp->mnemonic`,
  // rendered text this producer never reads (mnemonic/disasm always come
  // from the unchanged command path; see InsnRow's comment in direct.hpp).
  static constexpr RAnalOpMask kInsnMask = static_cast<RAnalOpMask>(
      R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_VAL |
      R_ARCH_OP_MASK_ESIL);

  static std::string hex_bytes(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
      out.push_back(digits[p[i] >> 4]);
      out.push_back(digits[p[i] & 0xf]);
    }
    return out;
  }

  // Decodes one RAnalOp at `addr` from `buf[off..)` (`buf_len - off` bytes
  // available) into an InsnRow. Mirrors the command path's own invalid-decode
  // row (`libr/core/disasm.c:7881-7897`) on a decode failure: size=1,
  // `bytes` = that one raw byte, `type` = "invalid", no esil/family key
  // (json_utils reads an absent key as ""). Returns the number of bytes
  // consumed (always >= 1), so callers advance the same amount pdfj/pdj do.
  static int decode_one_insn(RAnal* anal, ut64 addr, const uint8_t* buf,
                             int buf_len, int64_t func_addr, InsnRow& r) {
    r.addr      = static_cast<int64_t>(addr);
    r.func_addr = func_addr;
    RAnalOp op;
    int ret = r_anal_op(anal, &op, addr, buf, buf_len, kInsnMask);
    if (ret < 1 || op.size < 1) {
      r.size    = 1;
      r.bytes   = hex_bytes(buf, 1);
      r.op_type = "invalid";
      r_anal_op_fini(&op);
      return 1;
    }
    r.size  = op.size;
    r.bytes = hex_bytes(buf, static_cast<size_t>(op.size));
    r.esil  = R_STRBUF_SAFEGET(&op.esil);
    if (const char* t = r_anal_optype_tostring(op.type)) r.op_type = t;
    if (const char* f = r_anal_op_family_tostring(op.family)) r.family = f;
    const int consumed = op.size;
    r_anal_op_fini(&op);
    return consumed;
  }

  // One function's instructions, walked over `fcn->bbs` SORTED BY ADDRESS --
  // matching `pdfj`'s own `bb_cmpaddr` sort (`cmd_print.inc.c`), which is
  // what makes a non-contiguous function (a block below the function's own
  // entry address -- real, e.g. a shared-prologue PE entry point) come out
  // right: measured live against this exact shape on a 64-bit PE's `entry0`
  // and confirmed exact parity.
  void instructions_for_func(RAnalFunction* fcn, std::vector<InsnRow>& out) {
    struct Bb { ut64 addr; int size; };
    std::vector<Bb> bbs;
    for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
      if (b->size > 0) bbs.push_back({b->addr, static_cast<int>(b->size)});
    });
    std::sort(bbs.begin(), bbs.end(),
              [](const Bb& a, const Bb& b) { return a.addr < b.addr; });

    std::vector<uint8_t> buf;
    for (const Bb& bb : bbs) {
      buf.assign(static_cast<size_t>(bb.size), 0);
      if (!r_io_read_at(core_->io, bb.addr, buf.data(), bb.size)) continue;
      int i = 0;
      while (i < bb.size) {
        InsnRow r;
        int consumed = decode_one_insn(core_->anal, bb.addr + i, buf.data() + i,
                                       bb.size - i, static_cast<int64_t>(fcn->addr), r);
        out.push_back(std::move(r));
        i += consumed;
      }
    }
  }

  // Mirrors `pdfj @ <func_addr>` minus disasm/mnemonic. `out` is left empty
  // if `func_addr` is not a function start -- the same START-only contract
  // `blocks_in_func`/`xrefs_in_func` already enforce, and the shape
  // `tables_instructions.cpp`'s existing `func_addr` pushdown already has
  // (an address merely inside a function must not silently answer for it).
  void instructions_in_func(int64_t func_addr, std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io) return;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, static_cast<ut64>(func_addr),
                                           R_ANAL_FCN_TYPE_NULL);
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    instructions_for_func(fcn, out);
  }

  // Mirrors `aflj` + N x `pdfj @ <fa>` minus disasm/mnemonic: every
  // function's instructions, in `core->anal->fcns` order (the same order
  // `aflj` walks), each row's `func_addr` naming its owner.
  void instructions_scan(std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      instructions_for_func(fcn, out);
    });
  }

  // Mirrors `pdj <count> @ <start_addr>` minus disasm/mnemonic: a linear
  // walk, NOT bb-scoped (see InsnRow's comment in direct.hpp for why
  // `func_addr` stays 0 on every row here). Refills its read buffer from IO
  // whenever fewer than 32 bytes remain -- the same low-water threshold the
  // command path's own `pdj` loop uses (`disasm.c`, `i >= nb_bytes - 32`,
  // confirmed by `pd-range-lab`), since the longest x86 instruction is under
  // 16 bytes and every other arch this project targets is shorter still.
  void instructions_range(int64_t start_addr, int64_t count,
                          std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io || count <= 0) return;
    constexpr int kBufSize = 256;
    constexpr int kLowWater = 32;
    std::vector<uint8_t> buf(kBufSize, 0);
    ut64 addr = static_cast<ut64>(start_addr);
    int off = 0;
    if (!r_io_read_at(core_->io, addr, buf.data(), kBufSize)) return;
    for (int64_t n = 0; n < count; ++n) {
      if (off >= kBufSize - kLowWater) {
        addr += static_cast<ut64>(off);
        if (!r_io_read_at(core_->io, addr, buf.data(), kBufSize)) break;
        off = 0;
      }
      InsnRow r;
      int consumed = decode_one_insn(core_->anal, addr + static_cast<ut64>(off),
                                     buf.data() + off, kBufSize - off,
                                     /*func_addr=*/0, r);
      out.push_back(std::move(r));
      off += consumed;
    }
  }

  // Mirrors `fj` (full dump) + N x `fs <name>; fj; fs *` (real-space
  // attribution) -- read straight off `RFlagItem` via `r_flag_foreach`, one
  // pass, no command, no per-flagspace re-listing at all.
  //
  // `r_flag_foreach` (FOREACH_BODY(true), flag.c:1316-1335) walks the flag
  // database's `by_addr` skiplist unconditionally -- unlike the `fj` COMMAND,
  // which is filtered to the currently-selected flagspace
  // (`r_flag_foreach_space(f, r_flag_space_cur(f), ...)`, flag.c:551/595) --
  // so this producer needs no `fs`/session-state save-select-restore dance:
  // `fi->space->name` is the real flagspace already, read straight off the
  // item.
  //
  // `realname` reproduces `print_flag_json`'s own POINTER-EQUALITY test
  // (flag.c:429: `if (fi->realname && fi->name != fi->realname)`), not a
  // string-content comparison: `set_name` (flag.c:181-186) points a fresh
  // flag's `realname` at the exact same pooled string as `name` until
  // something (e.g. demangling) gives it a genuinely distinct one, so the
  // common case must read back "" here too, exactly as the command path's
  // `fj` does when the JSON key is absent.
  void flags_scan(std::vector<FlagRow>& out, const char* space, bool current_space) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return;
    RSpace* selected = space ? r_flag_space_get(core_->flags, space) :
        (current_space ? r_flag_space_cur(core_->flags) : nullptr);
    if (space && !selected) return;
    struct Ctx {
      std::vector<FlagRow>* out;
    } ctx{&out};
    r_flag_foreach_space(
        core_->flags, selected,
        [](RFlagItem* fi, void* user) -> bool {
          auto* c = static_cast<Ctx*>(user);
          FlagRow r;
          r.addr = static_cast<int64_t>(fi->addr);
          r.size = static_cast<int64_t>(fi->size);
          r.name = fi->name ? fi->name : "";
          r.realname = (fi->realname && fi->name != fi->realname) ? fi->realname : "";
          r.space = (fi->space && fi->space->name) ? fi->space->name : "";
          c->out->push_back(std::move(r));
          return true;  // never stop early -- a full scan
        },
        &ctx);
  }

  bool flag_at(const std::string& name, const std::string& space, int64_t addr) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return false;
    RFlagItem* item = r_flag_get(core_->flags, name.c_str());
    return item && item->addr == static_cast<ut64>(addr) && item->space &&
        space == item->space->name;
  }

  // Mirrors `izj` (`_print_strings`'s JSON branch, libr/core/cbin.c). That
  // command handler already calls `r_bin_get_strings` itself -- this walks
  // the SAME `RVecRBinString` in the SAME order the command path re-parses
  // from JSON, so the two producers agree row-for-row positionally, not just
  // by content. `section` has no backing field on `RBinString` -- resolved
  // per row via `r_bin_get_section_at`; `vaddr` is rebased through
  // `r_bin_get_vaddr`; `type` is rendered through `r_bin_string_type`. The
  // `r_bin_string_filter`/`bin.str.min`/`bin.str.max` gate the emitter
  // applies is reproduced here too (defaults are permissive: both 0).
  void strings_scan(bool with_content, std::vector<StringRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RVecRBinString* list = r_bin_get_strings(core_->bin);
    if (!list) return;
    RBinObject* obj = r_bin_cur_object(core_->bin);
    const int minstr = r_config_get_i(core_->config, "bin.str.min");
    const int maxstr = r_config_get_i(core_->config, "bin.str.max");
    RBinString* s;
    R_VEC_FOREACH(list, s) {
      const ut64 vaddr = r_config_get_b(core_->config, "io.va") && s->paddr != UT64_MAX
          ? r_bin_get_vaddr(core_->bin, s->paddr, s->vaddr) : s->paddr;
      if (!r_bin_string_filter(core_->bin, s->string, vaddr)) continue;
      if (static_cast<int>(s->length) < minstr) continue;
      if (maxstr && static_cast<int>(s->length) > maxstr) continue;

      StringRow r;
      r.addr   = static_cast<int64_t>(vaddr);
      r.length = static_cast<int64_t>(s->length);
      r.size = static_cast<int64_t>(s->size);
      RBinSection* sec = obj ? r_bin_get_section_at(obj, s->paddr, 0) : nullptr;
      r.section = (sec && sec->name) ? sec->name : "";
      if (const char* t = r_bin_string_type(s->type)) r.type = t;
      if (with_content) r.content = s->string ? s->string : "";
      r.paddr = static_cast<int64_t>(s->paddr);
      out.push_back(std::move(r));
    }
  }

  // Mirrors `bin_sections` (libr/core/cbin.c), which drives BOTH `iSj`
  // (`want_segment=false`) and `iSSj` (`want_segment=true`) off the SAME
  // `RVecRBinSection`, filtered by `is_segment` in opposite directions.
  // `perm` is rendered through `r_str_srwx_i`, not the raw bitmask; `addr`
  // downgrades to no rebase for a section lacking R_PERM_R, matching the
  // emitter's own `va_sect` branch exactly.
  void sections_scan(bool want_segment, std::vector<SectionRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin || !core_->bin->cur) return;
    // `iSj`/`iSSj` select the binary's descriptor before reading sections.
    // Preserve that selection for subsequent physical IO reads.
    r_io_use_fd(core_->io, core_->bin->cur->fd);
    RVecRBinSection* secs = r_bin_get_sections_vec(core_->bin);
    if (!secs) return;
    const bool io_va = r_config_get_b(core_->config, "io.va");
    RBinSection* s;
    R_VEC_FOREACH(secs, s) {
      if (s->is_segment != want_segment) continue;
      const int64_t addr = io_va && !(s->perm & R_PERM_R) ? s->vaddr :
          (io_va && s->paddr != UT64_MAX
              ? r_bin_get_vaddr(core_->bin, s->paddr, s->vaddr) : s->paddr);
      SectionRow r;
      r.addr  = addr;
      r.vsize = static_cast<int64_t>(s->vsize);
      r.paddr = static_cast<int64_t>(s->paddr);
      r.size  = static_cast<int64_t>(s->size);
      r.name  = s->name ? s->name : "";
      if (const char* p = r_str_srwx_i(static_cast<int>(s->perm))) r.perm = p;
      out.push_back(std::move(r));
    }
  }

  // Mirrors `bin_imports` (libr/core/cbin.c) field-by-field: `name` goes
  // through `r_bin_name_tostring` then (if `bin.demangle`) `r_bin_demangle`,
  // reshaped to "sym.imp.<demangled>" on success; `addr` ("plt") is
  // `r_core_bin_impaddr`, computed from the PRE-demangle name and gated on
  // `info->has_lit`. Every helper here is a public `R_API` call -- none of
  // this reimplements radare2's demangling or address-resolution logic.
  void imports_scan(std::vector<ImportRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RBinInfo* info = r_bin_get_info(core_->bin);
    if (!info) return;
    const bool bin_demangle = r_config_get_b(core_->config, "bin.demangle");
    const bool keep_lib = r_config_get_b(core_->config, "bin.demangle.pfxlib");
    const bool lit = info->has_lit;
    const bool va = r_config_get_b(core_->config, "io.va");

    RVecRBinImport* imports = r_bin_get_imports_vec(core_->bin);
    if (!imports) return;
    RBinImport* imp;
    R_VEC_FOREACH(imports, imp) {
      char* iname = r_bin_name_tostring(imp->name);
      std::string symname = iname ? iname : "";

      int64_t addr = lit
          ? static_cast<int64_t>(r_core_bin_impaddr(core_->bin, va ? 1 : 0, symname.c_str()))
          : 0;

      if (bin_demangle) {
        char* dname = r_bin_demangle(core_->bin->cur, nullptr, symname.c_str(),
                                      static_cast<ut64>(addr), keep_lib);
        if (dname && *dname) symname = std::string("sym.imp.") + dname;
        free(dname);
      }
      if (core_->bin->prefix) {
        symname = std::string(core_->bin->prefix) + "." + symname;
      }

      ImportRow r;
      r.ordinal = static_cast<int64_t>(imp->ordinal);
      r.bind    = imp->bind ? imp->bind : "";
      r.type    = imp->type ? imp->type : "";
      r.name    = symname;
      r.module  = imp->libname ? imp->libname : "";
      r.addr    = (addr && addr != static_cast<int64_t>(UT64_MAX)) ? addr : 0;
      out.push_back(std::move(r));
    }
  }

  // Merges one incoming row into the by-address map, byte-for-byte the same
  // rule as `tables_exports.cpp`'s own `merge_row`: richer (`prefer_fields`)
  // data replaces sparse fields at a duplicate address; sparse data never
  // overwrites something already there.
  static void merge_entry(std::map<int64_t, EntryRow>& by_addr, EntryRow incoming,
                           bool prefer_fields) {
    auto [it, inserted] = by_addr.emplace(incoming.addr, incoming);
    if (inserted) return;
    EntryRow& current = it->second;
    auto merge_text = [prefer_fields](std::string& dst, const std::string& src) {
      if (!src.empty() && (prefer_fields || dst.empty())) dst = src;
    };
    if (incoming.size != 0 && (prefer_fields || current.size == 0)) current.size = incoming.size;
    merge_text(current.type, incoming.type);
    merge_text(current.bind, incoming.bind);
    merge_text(current.name, incoming.name);
  }

  // Mirrors `tables_exports.cpp`'s cache_builder exactly: `r_bin_get_entries`
  // (RBinAddr, `R_BIN_ENTRY_TYPE_PROGRAM` only -- the same filter `iej`'s
  // handler uses) merged with `r_bin_get_symbols_vec` filtered by
  // `its_an_export` (`!is_imported && bind == "GLOBAL"`, reproduced rather
  // than called since the real helper is `static` in radare2). `iej` never
  // emits name/size/bind (only `type`, when non-empty) -- reproduced by
  // leaving those fields at their defaults on the entry-point pass.
  // `entries.name` is the ORIGINAL name (`r_bin_name_tostring2(.., 'o')`),
  // NOT the demangled one -- that lives under a "demname" key this table
  // never reads.
  void symbols_scan(std::vector<SymbolRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RVecRBinSymbol* symbols = r_bin_get_symbols_vec(core_->bin);
    if (!symbols) return;
    RBinSymbol* sym;
    R_VEC_FOREACH(symbols, sym) {
      const char* display_name = r_bin_name_tostring(sym->name);
      if (!display_name) continue;
      SymbolRow r;
      r.addr = sym->paddr == UT64_MAX ? sym->vaddr :
          (r_config_get_b(core_->config, "io.va")
              ? r_bin_get_vaddr(core_->bin, sym->paddr, sym->vaddr) : sym->paddr);
#if R2_ABIVERSION >= 136
      r.size = sym->attr.size;
#else
      r.size = sym->size;
#endif
      r.type = sym->type ? sym->type : "";
      r.bind = sym->bind ? sym->bind : "";
      r.is_imported = sym->is_imported;
      const char* name = r_bin_name_tostring2(sym->name, 'o');
      if (!name) name = display_name;
      if (name) {
        char* escaped = r_str_escape_utf8(name, false, true);
        r.name = escaped ? escaped : name;
        free(escaped);
      }
      out.push_back(std::move(r));
    }
  }

  void entries_scan(std::vector<EntryRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    std::map<int64_t, EntryRow> by_addr;

    const RList* entries = r_bin_get_entries(core_->bin);
    for_each_rlist<RBinAddr>(const_cast<RList*>(entries), [&](RBinAddr* e) {
      if (e->type != R_BIN_ENTRY_TYPE_PROGRAM) return;
      const int64_t vaddr = (e->paddr == UT64_MAX)
          ? static_cast<int64_t>(e->vaddr)
          : static_cast<int64_t>(r_bin_get_vaddr(core_->bin, e->paddr, e->vaddr));
      EntryRow r;
      r.addr = vaddr;
      if (const char* t = r_bin_entry_type_string(e->type)) {
        if (*t) r.type = t;
      }
      merge_entry(by_addr, r, false);
    });

    RVecRBinSymbol* symbols = r_bin_get_symbols_vec(core_->bin);
    if (symbols) {
      RBinSymbol* sym;
      R_VEC_FOREACH(symbols, sym) {
        if (sym->is_imported) continue;
        if (!sym->bind || strcmp(sym->bind, R_BIN_BIND_GLOBAL_STR) != 0) continue;
        const int64_t vaddr = (sym->paddr == UT64_MAX)
            ? static_cast<int64_t>(sym->vaddr)
            : static_cast<int64_t>(r_bin_get_vaddr(core_->bin, sym->paddr, sym->vaddr));
        EntryRow r;
        r.addr = vaddr;
#if R2_ABIVERSION >= 136
        r.size = static_cast<int64_t>(sym->attr.size);
#else
        r.size = static_cast<int64_t>(sym->size);
#endif
        r.type = sym->type ? sym->type : "";
        r.bind = sym->bind ? sym->bind : "";
        char* orig = r_bin_name_tostring2(sym->name, 'o');
        char* name = orig ? orig : r_bin_name_tostring(sym->name);
        if (name) {
          char* esc = r_str_escape_utf8(name, false, true);
          r.name = esc ? esc : name;
          free(esc);
        }
        merge_entry(by_addr, r, true);
      }
    }

    out.reserve(by_addr.size());
    for (auto& [addr, row] : by_addr) out.push_back(std::move(row));
  }

  // Mirrors `CCj` (`r_meta_print_list_all(anal, R_META_TYPE_COMMENT, 'j', ...)`
  // -> `print_meta_list` with addr/from/to all UT64_MAX, so none of that
  // function's function-scoping/range filtering applies to a full scan).
  // Walks `core->anal->meta` (an `RIntervalTree`) directly instead of
  // building and re-parsing a JSON array.
  //
  // `r_interval_tree_foreach`'s own macro expansion assigns the node's
  // `void* data` straight into a typed pointer -- legal C, a hard error in
  // C++ (the same trap `for_each_rlist` above works around for `RList`), so
  // this walks the underlying rbtree iterator directly instead of using the
  // macro.
  void comments_scan(std::vector<CommentRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->anal->meta.root) return;
    // `r_meta_print`'s own space guard: if a meta-space is currently
    // selected (`CS <name>`), only items in that exact space are visible;
    // if none is selected (the common case), every item is, regardless of
    // its own space. Read once, outside the loop -- selecting a space is
    // session state, not per-row.
    RSpace* cur_space = r_spaces_current(&core_->anal->meta_spaces);
    RIntervalTreeIter it;
    for (it = r_rbtree_first(&core_->anal->meta.root->node); r_rbtree_iter_has(&it);
         r_rbtree_iter_next(&it)) {
      RIntervalNode* node = r_interval_tree_iter_get(&it);
      if (!node || !node->data) continue;
      RAnalMetaItem* item = static_cast<RAnalMetaItem*>(node->data);
      if (item->type != R_META_TYPE_COMMENT) continue;
      if (cur_space && item->space != cur_space) continue;
      // A NULL `str` (e.g. from `CCu ""`) is a real interval-tree node that
      // `CCj` never prints -- skip it here too, rather than emit a
      // placeholder row `CCj` would never have shown.
      if (!item->str) continue;

      CommentRow r;
      r.addr = static_cast<int64_t>(node->start);
      // Same public R_API calls the CCj emitter itself makes for these two
      // fields -- NOT the literal "comment", and NOT a copy of item->str.
      // `r_meta_type_tostring(R_META_TYPE_COMMENT)` resolves to the literal
      // "CCu" (the write command, not a description of the meta kind); a
      // comment containing a newline/tab/quote/backslash/non-ASCII byte is
      // rendered through `r_str_escape` into its escaped TEXT form on the
      // JSON render path, exactly as production's CCj already does today.
      if (const char* t = r_meta_type_tostring(item->type)) r.type = t;
      if (char* esc = r_str_escape(item->str)) {
        r.text = esc;
        free(esc);
      }
      out.push_back(std::move(r));
    }
  }

  // Mirrors `CCu`'s own logic exactly (`cmd_meta.inc.c`'s `case 'u'`
  // handler), NOT just `r_meta_set_string` alone: skip the write when the
  // EXISTING comment at `addr` already contains `text` as a byte substring
  // (`strstr`). This is production behavior on the command path today --
  // reproduced here, not invented or "fixed" by this port.
  bool comment_set(int64_t addr, const std::string& text) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    const ut64 a = static_cast<ut64>(addr);
    const char* old = r_meta_get_string(core_->anal, R_META_TYPE_COMMENT, a);
    if (old && strstr(old, text.c_str())) return true;  // CCu's own no-op case
    return r_meta_set_string(core_->anal, R_META_TYPE_COMMENT, a, text.c_str());
  }

  // Mirrors `fr <old> <new>` (`cmd_flag.inc.c`'s `case 'r'` handler): a
  // plain by-name lookup + rename, no address needed at all (see the
  // rationale on `Api::flag_rename` in direct.hpp).
  bool flag_rename(const std::string& old_name, const std::string& new_name) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return false;
    RFlagItem* item = r_flag_get(core_->flags, old_name.c_str());
    if (!item) return false;
    return r_flag_rename(core_->flags, item, new_name.c_str());
  }

  // Mirrors `afvn <new> <old> @ <func_addr>` (`cmd_anal.inc.c`'s `case 'n'`
  // under `afv`): resolve the function, resolve the variable by its OLD
  // name, rename it. No other side effect (see the rationale on
  // `Api::var_rename` in direct.hpp).
  bool var_rename(int64_t func_addr, const std::string& old_name,
                   const std::string& new_name) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, static_cast<ut64>(func_addr));
    if (!fcn) return false;
    RAnalVar* var = r_anal_function_get_var_byname(fcn, old_name.c_str());
    if (!var) return false;
    return r_anal_var_rename(core_->anal, var, new_name.c_str());
  }

  // Mirrors `afvt <name> <type> @ <func_addr>` (`cmd_anal.inc.c`'s
  // `case 't'` under `afv`): resolve the function, resolve the variable by
  // name, set its type. `r_anal_var_set_type` is `void` -- success is
  // "the variable was found", matching the command handler's own
  // `R_LOG_ERROR ("Cant find variable named %s")` failure shape.
  bool var_set_type(int64_t func_addr, const std::string& name,
                     const std::string& type) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, static_cast<ut64>(func_addr));
    if (!fcn) return false;
    RAnalVar* var = r_anal_function_get_var_byname(fcn, name.c_str());
    if (!var) return false;
    r_anal_var_set_type(core_->anal, var, type.c_str());
    return true;
  }

 private:
  RCore*      core_ = nullptr;
  std::mutex& mu_;
};

}  // namespace

std::unique_ptr<Api> make_libr_api(void* core, std::mutex& core_mutex) {
  if (!core) return nullptr;
  return std::make_unique<LibrApi>(static_cast<RCore*>(core), core_mutex);
}

}  // namespace r2xsql::direct
