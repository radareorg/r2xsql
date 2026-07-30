// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// bytes — one row per byte in radare2's live IO maps (`omj`). Values come from
// `p8 <n> @ <addr>`; binary sections (`iSj`) distinguish raw-backed bytes from
// BSS tails. Uninitialized or unreadable bytes expose SQL NULL, never a made-up
// zero. `WHERE addr = X` reads one mapped byte; an unmapped point yields no row.

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

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
  auto j = be->cmd_json("iSj");
  if (!j.is_array()) return out;
  for (auto& s : j) {
    Sect sec;
    sec.vaddr = json_utils::i64(s, "vaddr");
    int64_t raw_size = std::max<int64_t>(0, json_utils::i64(s, "size"));
    int64_t virtual_size = json_utils::i64(s, "vsize");
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

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Read `count` raw bytes at `addr` via `p8` (hex string). Returns the decoded
// byte values (0..255); short-reads yield fewer than `count`.
std::vector<int> read_p8(Backend* be, int64_t addr, int64_t count) {
  std::vector<int> out;
  if (count <= 0) return out;
  std::string hex = be->cmd("p8 " + std::to_string(count) + " @ " + json_utils::hex_addr(addr));
  out.reserve(static_cast<size_t>(count));
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    int hi = hex_nibble(hex[i]);
    int lo = hex_nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) break;
    out.push_back((hi << 4) | lo);
  }
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
}  // namespace

void register_bytes_table(Session& s) {
  auto def = xsql::generator_table<ByteRow>("bytes")
    // Large estimate biases the planner toward the windowed pushdowns.
    .estimate_rows([]() -> size_t { return 1000000; })
    .generator([be = s.backend_ptr()]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
      return std::make_unique<BytesGen>(be);
    })
    .column_int64("addr",           [](const ByteRow& r) { return r.addr; })
    .column("value", xsql::ColumnType::Integer,
      [](xsql::FunctionContext& ctx, const ByteRow& r) {
        if (r.has_value) ctx.result_int64(r.value);
        else ctx.result_null();
      })
    .column_int64("is_initialized", [](const ByteRow& r) -> int64_t { return r.is_initialized; })
    // WHERE addr = X -> a single byte via p8 1 @ X.
    .filter_eq("addr",
      [be = s.backend_ptr()](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<BytesWindowIterator>(be, addr, 1);
      }, 1.0, 1.0)
    .build();
  s.db().register_and_create_generator_table(def);
}

}  // namespace r2sql
