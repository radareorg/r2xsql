// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// binary — binary info summary, canonical key/value/type shape (one row per
// fact). Columns: (key TEXT, value TEXT, type TEXT), type in {string, hex,
// bool, int}.
//
// Carries the raw bin-info fields from `iIj` (arch, bits, bintype, os, baddr,
// endian, compiler, lang, ...) plus these r2xsql identity / entry / count keys:
//   r2xsql_version  — tool version (raw key; tool_version is the canonical dup)
//   radare2_version — the RUNNING radare2 ENGINE's own version, from `?Vj`'s
//                     "version" field (verified live: `?Vj` on the current
//                     ref/radare2 build returns {"version":"6.1.7",...}) --
//                     distinct from r2xsql_version/tool_version above. This is
//                     a key that neither `binary` nor `bininfo` carried
//                     before: on the r2pipe flavor the
//                     engine actually running is whatever `radare2` binary is
//                     on PATH at runtime, which can differ from whatever
//                     version r2xsql itself was BUILT against, so a live `?Vj`
//                     query is the only source of truth (a compile-time
//                     R2_VERSION macro, e.g. the one already used for plugin
//                     ABI metadata in src/plugin/core_r2xsql.cpp, would be
//                     wrong on that flavor). Command-path-only key, identical
//                     on both backends -- `?Vj` needs no analysis and no bin
//                     loaded, matching every other identity key here.
//   file           — input file path (ij -> core.file)
//   entry          — program entry vaddr (iej[0].vaddr)
//   entry_name     — flag/name at the entry (fd @ entry)
//   func_count / string_count / import_count / section_count / segment_count /
//   symbol_count   — JSON-array lengths, so they match the corresponding tables
//   summary        — a one-line synthesized digest
//
// Canonical core keys (family-shared names, values aliased from the raw
// radare2 facts above): tool_name, tool_version, processor (=arch),
// filetype (=bintype), image_base (=baddr, hex), entry_point (=entry),
// endianness (from endian), filename (=file), is_64bit (from bits), and
// min_addr/max_addr derived from the section (iSj) / segment (iSSj) maps
// (omitted when neither map yields addresses). The raw `bits` key doubles as
// the canonical `bits`. md5/sha256 are best-effort core keys and are not
// emitted (radare2's `it` hashing is best-effort and often skipped).

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <r2xsql/version.hpp>
#include <xsql/vtable.hpp>

#include <cstdint>
#include <cstdio>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2xsql {

namespace {
struct BinaryRow {
  std::string key;
  std::string value;
  std::string type;
};

std::string hex_u64(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string chomp(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}

// radare2's generic "unknown/invalid" 64-bit sentinel. `cbin.c`'s own `iIj`
// handler already guards `baddr` against it (`!= UT64_MAX`) before emitting
// that key; every OTHER integer key in the same JSON object gets no such
// guard, so this table's generic per-key pass-through must apply the same
// one itself or repeat whatever nonsense value radare2 emits.
constexpr uint64_t kR2UnknownU64 = 0xFFFFFFFFFFFFFFFFULL;  // UT64_MAX

// A SECOND, distinct sentinel this table has observed live leaking into
// `iIj`'s "binsz" key on every PE opened on this Windows radare2 build
// (confirmed via `ref/radare2` source, not assumed): `libr/io/p/io_default.c`
// `mmap_seek()` returns `UT64_MAX - 1` for a SEEK_END on what it believes is
// a block device -- but `mmo->isblk` is a tri-state (-1 unknown / 0 no / 1
// yes) and the Windows build of `check_for_blockdevice()` is a no-op that
// never sets it away from -1, so `if (mmo->isblk)` treats "unknown" as "yes"
// and returns this sentinel for EVERY file once radare2 defaults `rawio` on
// (upstream commit `70a5b8f6ae`, "Enable rawio by default", 2025-12-20) --
// not file-specific, not r2xsql-side. Recorded as a known upstream bug in
// the project's private tracker; this constant is the r2xsql-side
// defensive guard (never patch the vendored ref/radare2 source for this).
constexpr uint64_t kR2SizeSentinel = 0xFFFFFFFFFFFFFFFEULL;  // UT64_MAX - 1

bool is_unknown_u64_sentinel(uint64_t v) {
  return v == kR2UnknownU64 || v == kR2SizeSentinel;
}
}  // namespace

void register_binary_table(Session& s) {
  auto def = xsql::cached_table<BinaryRow>("binary")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 40; })
    .cache_builder([be = s.backend_ptr()](std::vector<BinaryRow>& rows) {
      auto add = [&rows](const char* key, std::string value, const char* type) {
        rows.push_back({key, std::move(value), type});
      };

      // --- bin info (iIj): arch, bits, bintype, os, baddr, ... -----------
      // Raw keys pass through untouched; type is inferred from the JSON
      // value (bool -> bool, integral number -> int, else string).
      auto info = be->cmd_json("iIj");
      std::string arch, bits, bintype, os_name;
      bool have_baddr = false;
      uint64_t baddr = 0;
      bool have_endian_big = false, endian_known = false;
      if (info.is_object()) {
        for (auto& [k, v] : info.items()) {
          // A known-bad radare2 sentinel masquerading as a real integer (see
          // kR2UnknownU64/kR2SizeSentinel above) -- skip the row entirely
          // rather than emit a value no caller could use, the same "honest
          // omission over a bogus number" choice this file already makes for
          // min_addr/max_addr below.
          if (v.is_number_unsigned() && is_unknown_u64_sentinel(v.get<uint64_t>())) {
            continue;
          }
          BinaryRow r;
          r.key = k;
          if (v.is_string()) {
            r.value = v.get<std::string>();
            r.type = "string";
          } else if (v.is_boolean()) {
            r.value = v.get<bool>() ? "true" : "false";
            r.type = "bool";
          } else if (v.is_number_integer() || v.is_number_unsigned()) {
            r.value = v.dump();
            r.type = "int";
          } else if (v.is_number()) {
            r.value = v.dump();
            r.type = "string";
          } else {
            r.value = v.dump();
            r.type = "string";
          }
          rows.push_back(std::move(r));
        }
        arch = info.value("arch", std::string());
        bintype = info.value("bintype", std::string());
        os_name = info.value("os", std::string());
        if (info.contains("bits")) {
          bits = info["bits"].is_number() ? std::to_string(info["bits"].get<long long>())
                                          : info["bits"].dump();
        }
        if (info.contains("baddr") && info["baddr"].is_number()) {
          baddr = info["baddr"].get<uint64_t>();
          have_baddr = true;
        }
        if (info.contains("endian")) {
          const auto& e = info["endian"];
          if (e.is_string()) {
            const std::string es = e.get<std::string>();
            endian_known = !es.empty();
            have_endian_big = es == "big" || es == "BE" || es == "be";
          } else if (e.is_boolean()) {
            // Some radare2 versions emit endian as a bool (true = big).
            endian_known = true;
            have_endian_big = e.get<bool>();
          }
        }
      }

      // --- tool identity --------------------------------------------------
      add("r2xsql_version", r2xsql::version(), "string");  // raw key (kept)

      // --- radare2 engine identity (`?Vj`'s "version" field -- the LIVE
      //     running engine, not r2xsql's own build-time version above) ------
      {
        auto j = be->cmd_json("?Vj");
        if (j.is_object() && j.contains("version") && j["version"].is_string()) {
          add("radare2_version", j["version"].get<std::string>(), "string");
        }
      }

      // --- input file path (ij -> core.file) ------------------------------
      std::string file_path;
      {
        auto j = be->cmd_json("ij");
        if (j.is_object() && j.contains("core") && j["core"].is_object()) {
          auto& core = j["core"];
          if (core.contains("file") && core["file"].is_string()) {
            file_path = core["file"].get<std::string>();
            add("file", file_path, "string");
          }
        }
      }

      // --- entry point + name (iej[0]) -------------------------------------
      std::string entry_hex, entry_name;
      {
        auto j = be->cmd_json("iej");
        if (j.is_array() && !j.empty() && j[0].is_object() && j[0].contains("vaddr") &&
            j[0]["vaddr"].is_number()) {
          entry_hex = hex_u64(j[0]["vaddr"].get<uint64_t>());
          add("entry", entry_hex, "hex");
          entry_name = chomp(be->cmd("fd @ " + entry_hex));
          if (!entry_name.empty()) add("entry_name", entry_name, "string");
        }
      }

      // --- counts (JSON array lengths, so they agree exactly with the
      //     corresponding tables; the `<cmd>~?` text form over-counts header
      //     and formatting lines) -------------------------------------------
      auto add_count = [&](const char* key, const char* cmd) -> std::string {
        auto j = be->cmd_json(cmd);
        std::string v = std::to_string(j.is_array() ? j.size() : 0);
        add(key, v, "int");
        return v;
      };
      const std::string func_count    = add_count("func_count",    "aflj");
      const std::string string_count  = add_count("string_count",  "izj");
      add_count("import_count",  "iij");
      const std::string section_count = add_count("section_count", "iSj");
      add_count("segment_count", "iSSj");
      add_count("symbol_count",  "isj");

      // --- min/max mapped address, derived from the section map (iSj),
      //     falling back to the segment map (iSSj). Omitted honestly when
      //     neither map yields an address. -----------------------------------
      {
        bool have_range = false;
        uint64_t min_addr = 0, max_addr = 0;
        auto scan = [&](const char* cmd) {
          auto j = be->cmd_json(cmd);
          if (!j.is_array()) return;
          for (const auto& e : j) {
            if (!e.is_object() || !e.contains("vaddr") || !e["vaddr"].is_number())
              continue;
            const uint64_t vaddr = e["vaddr"].get<uint64_t>();
            uint64_t vsize = 0;
            if (e.contains("vsize") && e["vsize"].is_number())
              vsize = e["vsize"].get<uint64_t>();
            if (vsize == 0) continue;  // unmapped entry
            // radare2 reports file-only sections as vaddr==0 with a non-zero
            // vsize; those are not part of the memory map and would otherwise
            // pin min_addr to 0. Skip them (an image genuinely based at 0 is
            // reported honestly as "omitted" rather than a bogus 0).
            if (vaddr == 0) continue;
            if (!have_range || vaddr < min_addr) min_addr = vaddr;
            if (!have_range || vaddr + vsize > max_addr) max_addr = vaddr + vsize;
            have_range = true;
          }
        };
        scan("iSj");
        if (!have_range) scan("iSSj");
        if (have_range) {
          add("min_addr", hex_u64(min_addr), "hex");
          add("max_addr", hex_u64(max_addr), "hex");
        }
      }

      // --- canonical core keys (family-shared names; values alias the raw
      //     radare2 facts above so both spellings answer) --------------------
      add("tool_name", "r2xsql", "string");
      add("tool_version", r2xsql::version(), "string");
      if (!arch.empty())    add("processor", arch, "string");
      if (!bintype.empty()) add("filetype", bintype, "string");
      if (have_baddr)       add("image_base", hex_u64(baddr), "hex");
      if (!entry_hex.empty()) add("entry_point", entry_hex, "hex");
      if (!bits.empty())    add("is_64bit", bits == "64" ? "true" : "false", "bool");
      if (endian_known)     add("endianness", have_endian_big ? "big" : "little", "string");
      if (!file_path.empty()) add("filename", file_path, "string");

      // --- one-line summary digest (inserted FIRST: agents doing
      //     `SELECT * FROM binary` see the digest up top) --------------------
      std::string summary = arch;
      if (!bits.empty()) summary += " " + bits + "-bit";
      if (!entry_name.empty())      summary += " | entry: " + entry_name + " @ " + entry_hex;
      else if (!entry_hex.empty())  summary += " | entry: " + entry_hex;
      summary += " | funcs: " + func_count +
                 " | sections: " + section_count +
                 " | strings: " + string_count;
      rows.insert(rows.begin(), BinaryRow{"summary", summary, "string"});
    })
    .column_text("key",   [](const BinaryRow& r) { return r.key; })
    .column_text("value", [](const BinaryRow& r) { return r.value; })
    .column_text("type",  [](const BinaryRow& r) { return r.type; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
