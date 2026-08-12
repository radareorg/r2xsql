// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// segments — `iSSj`.

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
// Same row shape as `sections` -- both commands (`iSj`/`iSSj`) share ONE
// radare2 producer on the libr leg (`r_bin_get_sections_vec`, opposite
// `is_segment` filters); see `direct.hpp`'s `SectionRow` comment.
using SegmentRow = direct::SectionRow;
}  // namespace

void register_segments_table(Session& s) {
  auto def = xsql::cached_table<SegmentRow>("segments")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "iSS~?", 64);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<SegmentRow>& rows) {
      if (auto* api = be->direct()) {
        api->sections_scan(/*want_segment=*/true, rows);
        return;
      }
      auto arr = be->cmd_json("iSSj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        SegmentRow r;
        r.addr  = json_utils::i64(j, "vaddr");
        r.vsize = json_utils::i64(j, "vsize");
        r.paddr = json_utils::i64(j, "paddr");
        r.size  = json_utils::i64(j, "size");
        r.name  = json_utils::str(j, "name");
        r.perm  = json_utils::str(j, "perm");
        rows.push_back(std::move(r));
      }
    })
    // Canonical address range (the cross-tool names). Clean break: the old r2
    // `addr` column is replaced by `start_addr` (no alias). `vsize`/`paddr`/
    // `size` stay as radare2-specific extras.
    .column_int64("start_addr", [](const SegmentRow& r) { return r.addr; })
    .column_int64("end_addr",   [](const SegmentRow& r) { return r.addr + r.vsize; })
    .column_int64("vsize", [](const SegmentRow& r) { return r.vsize; })
    .column_int64("paddr", [](const SegmentRow& r) { return r.paddr; })
    .column_int64("size",  [](const SegmentRow& r) { return r.size; })
    .column_text ("name",  [](const SegmentRow& r) { return r.name; })
    .column_text ("perm",  [](const SegmentRow& r) { return r.perm; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql

