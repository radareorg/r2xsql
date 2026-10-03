// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// bytes — one row per byte in radare2's live IO maps (`omj`). Values come from
// `p8 <n> @ <addr>`; binary sections (`iSj`) distinguish raw-backed bytes from
// BSS tails. Uninitialized or unreadable bytes expose SQL NULL, never a made-up
// zero. `WHERE addr = X` reads one mapped byte; an unmapped point yields no row.
//
// `value` is writable: `UPDATE bytes SET value = X WHERE addr = Y` overwrites
// one byte via `wx`. This is deliberately a DIRECT, IMMEDIATE overwrite, never
// an INSERT/DELETE (a byte can't be created or removed, only changed) and
// NEVER routed through the `patches` table's revertible `io.cache` overlay --
// see the design note above the setter below for why and how.
//
// `addr`/`is_initialized` stay read-only: an address is defined by what's
// mapped, and `is_initialized` is derived from static section metadata, not
// something a write changes.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"
#include "table_sources.hpp"

namespace r2xsql {

namespace {

struct ByteRow {
  int64_t addr = 0;
  int     value = 0;         // 0..255 when has_value
  bool    has_value = false;
  int     is_initialized = 0;
};

struct Sect {
  int64_t vaddr = 0;
  int64_t end = 0;           // exclusive virtual end
  int64_t raw_end = 0;       // exclusive raw-backed end
};

struct MapSpan {
  int64_t start = 0;
  int64_t end = 0;           // exclusive
  int64_t fd = -1;
};

int64_t saturated_end(int64_t start, int64_t length) {
  if (length <= 0) return start;
  if (start > std::numeric_limits<int64_t>::max() - length)
    return std::numeric_limits<int64_t>::max();
  return start + length;
}

std::vector<Sect> load_sections(Backend* be) {
  std::vector<Sect> out;
  for (const auto& s : table_sources::sections(be)) {
    Sect sec;
    sec.vaddr = s.addr;
    int64_t raw_size = std::max<int64_t>(0, s.size);
    int64_t virtual_size = s.vsize;
    if (virtual_size <= 0) virtual_size = raw_size;
    if (virtual_size <= 0) continue;
    sec.end = saturated_end(sec.vaddr, virtual_size);
    sec.raw_end = saturated_end(sec.vaddr, std::min(raw_size, virtual_size));
    if (sec.end > sec.vaddr) out.push_back(sec);
  }
  return out;
}

std::vector<MapSpan> load_maps(Backend* be) {
  std::vector<MapSpan> out;
  if (auto* api = be->direct()) {
    std::vector<direct::IoMapRow> maps;
    api->io_maps_scan(maps);
    for (const auto& m : maps) {
      if (m.end_addr > m.start_addr) out.push_back({m.start_addr, m.end_addr, m.fd});
    }
  } else {
    auto j = be->cmd_json("omj");
    if (!j.is_array()) return out;
    for (const auto& m : j) {
      MapSpan span;
      span.start = json_utils::i64(m, "from");
      const int64_t last = json_utils::i64(m, "to");
      if (last < span.start) continue;
      span.end = last == std::numeric_limits<int64_t>::max()
                     ? last
                     : last + 1;
      span.fd = json_utils::i64(m, "fd", -1);
      if (span.end > span.start) out.push_back(span);
    }
  }
  std::sort(out.begin(), out.end(), [](const MapSpan& a, const MapSpan& b) {
    if (a.start != b.start) return a.start < b.start;
    return a.end < b.end;
  });
  return out;
}

bool is_mapped_at(const std::vector<MapSpan>& maps, int64_t addr) {
  for (const auto& m : maps) {
    if (m.start > addr) break;
    if (addr >= m.start && addr < m.end) return true;
  }
  return false;
}

// Binary section metadata is authoritative for BSS. Bytes in a live map but
// outside a section are considered initialized only when the map has a backing
// file descriptor.
int is_initialized_at(const std::vector<Sect>& secs,
                      const std::vector<MapSpan>& maps, int64_t addr) {
  for (const auto& s : secs) {
    if (addr >= s.vaddr && addr < s.end)
      return addr < s.raw_end ? 1 : 0;
  }
  for (const auto& m : maps) {
    if (m.start > addr) break;
    if (addr >= m.start && addr < m.end) return m.fd >= 0 ? 1 : 0;
  }
  return 0;
}

std::vector<std::pair<int64_t, int64_t>> merged_map_spans(
    const std::vector<MapSpan>& maps) {
  std::vector<std::pair<int64_t, int64_t>> spans;
  spans.reserve(maps.size());
  for (const auto& m : maps) {
    if (spans.empty() || m.start > spans.back().second) {
      spans.emplace_back(m.start, m.end);
    } else if (m.end > spans.back().second) {
      spans.back().second = m.end;
    }
  }
  return spans;
}

// Read `count` raw bytes at `addr` via `p8` (hex string). Returns the decoded
// byte values (0..255); short-reads yield fewer than `count`. Decoding goes
// through the shared lenient decoder (json_utils::hex_decode_partial) so a
// truncated response still yields whatever decoded cleanly, same as before.
std::vector<int> read_p8(Backend* be, int64_t addr, int64_t count) {
  std::vector<int> out;
  if (count <= 0) return out;
  std::vector<uint8_t> bytes;
  if (auto* api = be->direct()) {
    api->read_bytes(addr, static_cast<size_t>(count), bytes);
  } else {
    std::string hex = be->cmd("p8 " + std::to_string(count) + " @ " + json_utils::hex_addr(addr));
    json_utils::hex_decode_partial(hex, bytes);
  }
  out.reserve(bytes.size());
  for (uint8_t b : bytes) out.push_back(b);
  return out;
}

// Decode mapped addresses in [start, start+n). A short p8 response leaves the
// affected values NULL instead of silently fabricating zeroes.
std::vector<ByteRow> window_rows(Backend* be, const std::vector<Sect>& secs,
                                 const std::vector<MapSpan>& maps,
                                 int64_t start, int64_t n) {
  std::vector<ByteRow> rows;
  if (n <= 0) return rows;
  if (n == 1 && !is_mapped_at(maps, start)) return rows;
  std::vector<int> raw = read_p8(be, start, n);
  rows.reserve(static_cast<size_t>(n));
  for (int64_t i = 0; i < n; ++i) {
    ByteRow r;
    r.addr = start + i;
    if (!is_mapped_at(maps, r.addr)) continue;
    r.is_initialized = is_initialized_at(secs, maps, r.addr);
    r.has_value =
        r.is_initialized && i < static_cast<int64_t>(raw.size());
    if (r.has_value) r.value = raw[static_cast<size_t>(i)];
    rows.push_back(r);
  }
  return rows;
}

constexpr int64_t kChunk = 65536;  // p8 read size for the full scan

// Full-scan generator: stream the union of all live IO-map spans. Overlapping
// maps are merged so an address is never returned twice.
class BytesGen : public xsql::Generator<ByteRow> {
  Backend* be_;
  std::vector<Sect> secs_;
  std::vector<MapSpan> maps_;
  std::vector<std::pair<int64_t, int64_t>> spans_;
  size_t si_ = 0;
  std::vector<ByteRow> buf_;
  size_t bi_ = 0;
  int64_t span_pos_ = 0;
  ByteRow cur_;

  bool refill() {
    while (true) {
      if (bi_ < buf_.size()) return true;
      if (si_ >= spans_.size()) return false;
      const auto& span = spans_[si_];
      const int64_t span_size = span.second - span.first;
      if (span_pos_ >= span_size) {
        ++si_;
        span_pos_ = 0;
        continue;
      }
      int64_t chunk = std::min<int64_t>(kChunk, span_size - span_pos_);
      buf_ = window_rows(
          be_, secs_, maps_, span.first + span_pos_, chunk);
      bi_ = 0;
      span_pos_ += chunk;
      if (buf_.empty()) continue;
    }
  }

 public:
  explicit BytesGen(Backend* be)
      : be_(be), secs_(load_sections(be)), maps_(load_maps(be)),
        spans_(merged_map_spans(maps_)) {}
  bool next() override {
    if (!refill()) return false;
    cur_ = buf_[bi_++];
    return true;
  }
  const ByteRow& current() const override { return cur_; }
  int64_t rowid() const override { return cur_.addr; }
};

// Pushdown iterator for a windowed read (addr point, or start_addr + n).
class BytesWindowIterator : public xsql::RowIterator {
  std::vector<ByteRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  BytesWindowIterator(Backend* be, int64_t start, int64_t n) {
    auto maps = load_maps(be);
    rows_ = window_rows(be, load_sections(be), maps, start, n);
  }
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const ByteRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_int64(r.addr); break;            // addr
      case 1:
        if (r.has_value) ctx.result_int64(r.value);
        else ctx.result_null();
        break;                                             // value
      case 2: ctx.result_int64(r.is_initialized); break;  // is_initialized
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return rows_[i_].addr; }
};

std::string dispatch_write(Backend* be, int64_t addr, const std::string& command) {
  std::string out;
  if (be->cmd_noeval(addr, command, &out)) return out;
  return be->cmd(command + " @ " + json_utils::hex_addr(addr));
}

// UPDATE bytes SET value = X WHERE addr = Y -- a direct, immediate, ONE-BYTE
// overwrite via `wx`. This is deliberately separate from the `patches` table
// (tables_patches.cpp): `patches` stages a REVERTIBLE change into radare2's
// `io.cache` overlay (visible via `wcj`, undoable via `wcu`, committed via
// `wci`); this write must land permanently with no pending/uncommitted state
// at all, regardless of whatever io.cache happens to be set to when the
// UPDATE runs -- even mid-flight, e.g. while an unrelated `patches` row is
// still staged.
//
// The problem this solves: `wx <hex> @ <addr>` stages into `io.cache`
// whenever io.cache is enabled -- the EXACT SAME mechanism `patches`
// deliberately uses. A bare `wx` here would silently create an untracked
// write-cache entry indistinguishable from something `patches` should own,
// with the two tables quietly fighting over the same underlying state (this
// write would look "pending" via `wcj`/`patches`, and a later `wci`/`wcu`
// issued through `patches` would then affect a byte no one asked it to).
//
// The fix: bypass io.cache entirely, using the same read-current/disable/
// operate/restore idiom radare2's OWN code already uses for exactly this
// purpose (`libr/core/panels.inc.c`'s `panel_single_step_over`: `bool
// io_cache = r_config_get_i(...); r_config_set_b(..., false); <op>;
// r_config_set_b(..., io_cache)`) -- confirmed against that source, not
// invented here. Read io.cache's CURRENT value (never assume it's off, and
// never force a hardcoded default the way the `search.in`/flagspace fixes
// do for THEIR config keys -- io.cache's prior state may be a `patches` row
// legitimately mid-flight, so the exact value must round-trip), disable it,
// issue the write (now landing straight on the underlying IO instead of the
// cache layer), then restore io.cache's prior value UNCONDITIONALLY -- even
// if the write itself reports an error -- so this table can never leak a
// changed io.cache setting into a concurrent caller sharing the same
// in-process core (the reasoning `search.in`/flagspace already documented:
// the libr plugin shares one core across its interactive/remote callers).
// This is `e io.cache`/`e io.cache=false`/`e io.cache=<prior>` as three
// plain Backend::cmd() calls (not chained into one string), matching
// radare2's own C-API idiom's shape -- read, then set, then [operate], then
// restore -- rather than search.in/flagspace's single-command-with-a-fixed-
// restore-value bundling, which does not apply here since io.cache's
// restore target is a value read at runtime, not a hardcoded constant.
//
// The byte value is validated to a strict 0-255 integer BEFORE any of this
// runs, so the only text ever spliced into `wx` is exactly two hex digits
// derived from that already-range-checked int -- never raw user text. That
// validation is the layer that actually closes any injection surface here;
// `dispatch_write`'s cmd_noeval attempt below is wired in for consistency
// with every other address-scoped write in this project (comments/funcs/
// flags/bookmarks/patches), not because there is a free-text argument left
// for it to protect -- same "nothing new to harden, wired in anyway"
// finding already recorded for `patches`' INSERT.
// Physically re-reads exactly one byte via `p8` (bypassing the
// is_initialized-gated `has_value` machinery `window_rows` normally applies)
// so write verification checks what is actually AT the address, not this
// table's static, write-independent classification of whether that address
// falls in a raw-file-backed section. See write_byte_direct's caller for why
// this distinction matters.
bool read_one_byte(Backend* be, int64_t addr, int* out_value) {
  std::vector<int> raw = read_p8(be, addr, 1);
  if (raw.empty()) return false;
  if (out_value) *out_value = raw[0];
  return true;
}

bool write_byte_direct(Backend* be, int64_t addr, int value, std::string* err_out) {
  char hex_buf[3];
  std::snprintf(hex_buf, sizeof(hex_buf), "%02x", static_cast<unsigned>(value));
  const std::string hex(hex_buf);

  const std::string prior = table_utils::trim_ascii(be->cmd("e io.cache"));
  be->cmd("e io.cache=false");
  const std::string out = dispatch_write(be, addr, "wx " + hex);
  // Restore unconditionally, even on failure below -- io.cache must never be
  // left disabled by a failed write. radare2's own default is "false" (see
  // cconfig.c's SETCB), used only if the read above somehow came back empty.
  be->cmd("e io.cache=" + (prior.empty() ? std::string("false") : prior));

  if (std::string e = table_utils::command_error_text(out); !e.empty()) {
    if (err_out) *err_out = e;
    return false;
  }
  return true;
}

}  // namespace

void register_bytes_table(Session& s) {
  auto def = xsql::generator_table<ByteRow>("bytes")
    // Large estimate biases the planner toward the windowed pushdowns.
    .estimate_rows([]() -> size_t { return 1000000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
      return std::make_unique<BytesGen>(be);
    })
    .column_int64("addr",           [](const ByteRow& r) { return r.addr; })
    .column_rw("value", xsql::ColumnType::Integer,
      [](xsql::FunctionContext& ctx, const ByteRow& r) {
        if (r.has_value) ctx.result_int64(r.value);
        else ctx.result_null();
      },
      [be = s.backend_ptr()](ByteRow& r, xsql::FunctionArg v) -> bool {
        if (v.is_null()) {
          xsql::set_vtab_error("bytes: UPDATE value cannot be set to NULL");
          return false;
        }
        // Exact integers only: 65.5 is refused, never truncated to 65.
        const auto exact = xsql::exact_int64(v);
        if (!exact) {
          xsql::set_vtab_error(
              "bytes: UPDATE value must be an integer between 0 and 255");
          return false;
        }
        const int64_t iv = *exact;
        if (iv < 0 || iv > 255) {
          xsql::set_vtab_error(
              "bytes: UPDATE value must be an integer between 0 and 255 (got " +
              std::to_string(iv) + ")");
          return false;
        }

        // Restricted to a currently-initialized (file-backed) byte. This
        // table's own `is_initialized` classification comes from static
        // section metadata (raw-backed extent vs. virtual size) and a write
        // through this table can't and doesn't change that classification --
        // so writing into a BSS/unbacked address would leave `value` reading
        // SQL NULL forever afterward (has_value is gated on is_initialized,
        // permanently 0 for that address), an unreadable-back write no
        // caller could distinguish from one that silently failed. Refuse it
        // up front with a clear reason instead of leaving that trap.
        if (!r.is_initialized) {
          xsql::set_vtab_error(
              "bytes: UPDATE refused (addr=" + json_utils::hex_addr(r.addr) +
              "): this address is not in an initialized (file-backed) "
              "region, so a write here could never be read back through "
              "this table");
          return false;
        }

        std::string err;
        if (!write_byte_direct(be, r.addr, static_cast<int>(iv), &err)) {
          xsql::set_vtab_error("bytes: UPDATE failed (addr=" +
                               json_utils::hex_addr(r.addr) + "): " + err);
          return false;
        }

        // Readback verification (same discipline as patches'/types' writes):
        // confirm the byte actually changed rather than trusting a silent
        // "success" from wx. Reads the raw byte directly (read_one_byte),
        // not the is_initialized-gated has_value machinery -- see
        // read_one_byte's comment.
        int actual = 0;
        if (!read_one_byte(be, r.addr, &actual) || actual != static_cast<int>(iv)) {
          xsql::set_vtab_error(
              "bytes: UPDATE failed (addr=" + json_utils::hex_addr(r.addr) +
              "): byte did not change after wx");
          return false;
        }

        r.value = static_cast<int>(iv);
        r.has_value = true;
        return true;
      })
    .column_int64("is_initialized", [](const ByteRow& r) -> int64_t { return r.is_initialized; })
    // WHERE addr = X -> a single byte via p8 1 @ X.
    .filter_eq("addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<BytesWindowIterator>(be, addr, 1);
      }, 1.0, 1.0)
    // UPDATE resolves its target row through this: fetch the single mapped
    // byte at `rowid` (== addr, per BytesGen/BytesWindowIterator::rowid()).
    // No INSERT/DELETE -- a byte can't be created or removed, only changed --
    // so no .insertable()/.deletable() is registered.
    .row_lookup([be = s.backend_ptr()](ByteRow& row, int64_t rowid) -> bool {
      auto rows = window_rows(be, load_sections(be), load_maps(be), rowid, 1);
      if (rows.empty()) return false;
      row = rows[0];
      return true;
    })
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2xsql
